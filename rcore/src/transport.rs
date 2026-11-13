//! Port of xray-core transport/internet/{websocket,httpupgrade} server sides, the WebSocket
//! client (gorilla dialer) and common/protocol/http ApplyTrustedXForwardedFor.
use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use sha1::{Digest, Sha1};
use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context as TaskCx, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::TcpStream,
    sync::Mutex,
};

/// Any byte stream a proxy protocol can run over.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;

#[derive(Clone)]
pub enum Transport {
    Raw,
    Ws {
        path: String,
        host: String,
        heartbeat: u32,
    },
    HttpUpgrade {
        path: String,
        host: String,
    },
    Xhttp(std::sync::Arc<crate::xhttp::Config>),
}

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Config path as Xray builds it: `ed` query removed, then GetNormalizedPath.
pub fn normalize_path(path: &str) -> String {
    let path = match path.split_once('?') {
        Some((base, query)) => {
            let rest: Vec<&str> = query
                .split('&')
                .filter(|kv| !kv.is_empty() && kv.split('=').next() != Some("ed"))
                .collect();
            if rest.is_empty() {
                base.to_owned()
            } else {
                format!("{base}?{}", rest.join("&"))
            }
        }
        None => path.to_owned(),
    };
    if path.is_empty() {
        "/".into()
    } else if !path.starts_with('/') {
        format!("/{path}")
    } else {
        path
    }
}

struct Request {
    method: String,
    path: String,
    host: String,
    headers: Vec<(String, String)>,
}

impl Request {
    /// http.Header.Get: first value, case-insensitive name.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn has(&self, name: &str) -> bool {
        self.header(name).is_some()
    }
    /// tokenListContainsValue (gorilla): comma-separated tokens, case-insensitive.
    fn has_token(&self, name: &str, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }
}

/// Reads one HTTP/1.x request head. Returns the request and bytes read past it.
async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    limit: usize,
    carry: Vec<u8>,
) -> Result<(Request, Vec<u8>)> {
    let mut buf = carry;
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        ensure!(buf.len() < limit, "request header too large");
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        ensure!(n > 0, "EOF");
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let rest = buf[end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or_default().split(' ');
    let (method, target, version) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    ensure!(version.starts_with("HTTP/1."), "malformed HTTP request");
    let mut headers = Vec::new();
    for line in lines {
        let (k, v) = line.split_once(':').context("malformed MIME header line")?;
        headers.push((k.trim().to_owned(), v.trim().to_owned()));
    }
    // Absolute-form targets carry the host and path in the URL.
    let (url_host, raw_path) = match target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        Some(rest) => rest
            .split_once('/')
            .map(|(h, p)| (h.to_owned(), format!("/{p}")))
            .unwrap_or((rest.to_owned(), "/".into())),
        None => (String::new(), target.to_owned()),
    };
    let raw_path = raw_path.split('?').next().unwrap_or_default().to_owned();
    let path = percent_encoding::percent_decode_str(&raw_path)
        .decode_utf8_lossy()
        .into_owned();
    let host = if url_host.is_empty() {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    } else {
        url_host
    };
    Ok((
        Request {
            method: method.to_owned(),
            path,
            host,
            headers,
        },
        rest,
    ))
}

/// internet.IsValidHTTPHost
pub(crate) fn valid_host(request: &str, config: &str) -> bool {
    let (r, c) = (request.to_lowercase(), config.to_lowercase());
    if r.contains(':') {
        let h = if let Some(rest) = r.strip_prefix('[') {
            rest.split(']').next().unwrap_or_default()
        } else {
            r.rsplit_once(':').map(|(h, _)| h).unwrap_or(&r)
        };
        return h == c;
    }
    r == c
}

/// ApplyTrustedXForwardedFor: the first X-Forwarded-For entry replaces the source (port 0)
/// only when one of the trusted headers is present.
fn forwarded(req: &Request, trusted: &[String], remote: SocketAddr) -> SocketAddr {
    forwarded_for(
        req.header("X-Forwarded-For"),
        |t| req.has(t),
        trusted,
        remote,
    )
}

/// ApplyTrustedXForwardedFor over any header map: `has` reports whether a header is present.
pub(crate) fn forwarded_for(
    xff: Option<&str>,
    has: impl Fn(&str) -> bool,
    trusted: &[String],
    remote: SocketAddr,
) -> SocketAddr {
    let Some(value) = xff.filter(|v| !v.is_empty()) else {
        return remote;
    };
    if trusted.iter().any(|t| has(t)) {
        let first = value.split(',').next().unwrap_or_default().trim();
        if let Ok(ip) = first
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            return SocketAddr::new(ip.to_canonical(), 0);
        }
        return remote;
    }
    if trusted.is_empty() {
        tracing::warn!(
            "received \"X-Forwarded-For\" from {remote} but \"sockopt.trustedXForwardedFor\" is not configured; ignoring it and using the real remote address"
        );
    } else {
        tracing::error!("ignored potentially forged \"X-Forwarded-For\" from {remote}: {value}");
    }
    remote
}

/// net/http response for a plain status (WriteHeader / http.Error).
fn http_status(code: u16, reason: &str, error_body: bool) -> Vec<u8> {
    let date = httpdate::fmt_http_date(std::time::SystemTime::now());
    if error_body {
        let body = format!("{reason}\n");
        format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nSec-Websocket-Version: 13\r\nX-Content-Type-Options: nosniff\r\nDate: {date}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    } else {
        format!("HTTP/1.1 {code} {reason}\r\nDate: {date}\r\nContent-Length: 0\r\n\r\n")
            .into_bytes()
    }
}

/// Accepts a WebSocket connection like Xray's net/http + gorilla handler. Rejected
/// requests get Go's responses and the connection stays open for the next request.
pub async fn accept_ws(
    mut tcp: TcpStream,
    path: &str,
    host: &str,
    heartbeat: u32,
    trusted: &[String],
) -> Result<(BoxIo, SocketAddr)> {
    let remote = tcp.peer_addr()?;
    let mut carry = Vec::new();
    loop {
        // ReadHeaderTimeout 4s, MaxHeaderBytes 8192 (+4096 net/http slack).
        let (req, rest) = tokio::time::timeout(
            Duration::from_secs(4),
            read_request(&mut tcp, 8192 + 4096, std::mem::take(&mut carry)),
        )
        .await
        .context("failed to read WebSocket request")??;
        carry = rest;
        if (!host.is_empty() && !valid_host(&req.host, host)) || req.path != path {
            tcp.write_all(&http_status(404, "Not Found", false)).await?;
            continue;
        }
        // gorilla Upgrader.Upgrade check order: Connection, Upgrade (400), method (405), version, key (400).
        let key = req
            .header("Sec-Websocket-Key")
            .unwrap_or_default()
            .to_owned();
        let rejected =
            if !req.has_token("Connection", "upgrade") || !req.has_token("Upgrade", "websocket") {
                Some((400, "Bad Request"))
            } else if req.method != "GET" {
                Some((405, "Method Not Allowed"))
            } else if !req.has_token("Sec-Websocket-Version", "13")
                || !STANDARD.decode(&key).is_ok_and(|k| k.len() == 16)
            {
                Some((400, "Bad Request"))
            } else {
                None
            };
        if let Some((code, reason)) = rejected {
            tcp.write_all(&http_status(code, reason, true)).await?;
            continue;
        }
        let mut early = Vec::new();
        let mut protocol = None;
        if let Some(value) = req
            .header("Sec-WebSocket-Protocol")
            .filter(|v| !v.is_empty())
        {
            let normalized: String = value
                .chars()
                .filter(|c| *c != '=')
                .map(|c| match c {
                    '+' => '-',
                    '/' => '_',
                    c => c,
                })
                .collect();
            if let Ok(data) = URL_SAFE_NO_PAD.decode(normalized)
                && !data.is_empty()
            {
                early = data;
                protocol = Some(value.to_owned());
            }
        }
        let accept = STANDARD.encode(
            Sha1::new()
                .chain_update(key.as_bytes())
                .chain_update(WS_GUID)
                .finalize(),
        );
        let mut response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n"
        );
        if let Some(p) = &protocol {
            response.push_str(&format!("Sec-WebSocket-Protocol: {p}\r\n"));
        }
        response.push_str("\r\n");
        tcp.write_all(response.as_bytes()).await?;
        let source = forwarded(&req, trusted, remote);
        return Ok((
            Box::new(websocket(tcp, early, carry, heartbeat, false)),
            source,
        ));
    }
}

/// HTTPUpgrade server (transport/internet/httpupgrade/hub.go upgrade()).
pub async fn accept_httpupgrade(
    mut tcp: TcpStream,
    path: &str,
    host: &str,
    trusted: &[String],
) -> Result<(BoxIo, SocketAddr)> {
    let remote = tcp.peer_addr()?;
    let (req, rest) = tokio::time::timeout(
        Duration::from_secs(4),
        read_request(&mut tcp, 12288, Vec::new()),
    )
    .await
    .context("failed to handle request")??;
    if !host.is_empty() && !valid_host(&req.host, host) {
        bail!("bad host: {}", req.host);
    }
    if req.path != path {
        bail!("bad path: {}", req.path);
    }
    let connection = req.header("Connection").unwrap_or_default().to_lowercase();
    let upgrade = req.header("Upgrade").unwrap_or_default().to_lowercase();
    ensure!(
        connection == "upgrade" && upgrade == "websocket",
        "unrecognized request"
    );
    // http.Response.Write: sorted, canonical header keys.
    let mut response = String::from("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n");
    if let Some(key) = req.header("Sec-WebSocket-Key").filter(|k| !k.is_empty()) {
        let accept = STANDARD.encode(
            Sha1::new()
                .chain_update(key.as_bytes())
                .chain_update(WS_GUID)
                .finalize(),
        );
        response.push_str(&format!("Sec-Websocket-Accept: {accept}\r\n"));
    }
    response.push_str("Upgrade: websocket\r\n\r\n");
    tcp.write_all(response.as_bytes()).await?;
    let source = forwarded(&req, trusted, remote);
    // Go drops bytes its bufio reader buffered past the request (early data); rcore keeps them.
    Ok((
        Box::new(Prefixed {
            prefix: rest,
            pos: 0,
            inner: tcp,
        }),
        source,
    ))
}

/// A stream that first yields already-read bytes.
pub struct Prefixed<S> {
    pub prefix: Vec<u8>,
    pub pos: usize,
    pub inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// One final frame; clients mask every frame with a fresh key (RFC 6455 5.3).
fn frame_as(opcode: u8, payload: &[u8], client: bool) -> Vec<u8> {
    let mask_bit = if client { 0x80 } else { 0 };
    let mut out = vec![0x80 | opcode];
    match payload.len() {
        n if n < 126 => out.push(mask_bit | n as u8),
        n if n <= 0xffff => {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    if client {
        let mut key = [0u8; 4];
        let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key);
        out.extend_from_slice(&key);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/// RFC 6455 framing behind a byte pipe, like Xray's websocket.connection: each write becomes
/// one binary message, pings are answered, close 1000/1005 is EOF. Servers receive masked
/// frames; clients (`client`) send masked frames and receive unmasked ones.
fn websocket<S: AsyncRead + AsyncWrite + Send + 'static>(
    tcp: S,
    early: Vec<u8>,
    carry: Vec<u8>,
    heartbeat: u32,
    client: bool,
) -> DuplexStream {
    let (app, pipe) = tokio::io::duplex(64 * 1024);
    let (mut pipe_read, mut pipe_write) = tokio::io::split(pipe);
    let (tcp_read, tcp_write) = tokio::io::split(tcp);
    let tcp_write = Arc::new(Mutex::new(tcp_write));
    let closed = Arc::new(AtomicBool::new(false));
    // Reader: client frames -> payload pipe.
    {
        let (tcp_write, closed) = (tcp_write.clone(), closed.clone());
        tokio::spawn(async move {
            let mut reader = Prefixed {
                prefix: carry,
                pos: 0,
                inner: tcp_read,
            };
            if !early.is_empty() && pipe_write.write_all(&early).await.is_err() {
                return;
            }
            let result: Result<()> = async {
                loop {
                    let mut head = [0u8; 2];
                    reader.read_exact(&mut head).await?;
                    let (fin, rsv, opcode) = (head[0] & 0x80 != 0, head[0] & 0x70, head[0] & 0x0f);
                    ensure!(rsv == 0, "unexpected reserved bits");
                    ensure!((head[1] & 0x80 != 0) != client, "bad MASK");
                    let len = match head[1] & 0x7f {
                        126 => reader.read_u16().await? as u64,
                        127 => reader.read_u64().await?,
                        n => n as u64,
                    };
                    let mut mask = [0u8; 4];
                    if !client {
                        reader.read_exact(&mut mask).await?;
                    }
                    if opcode >= 8 {
                        ensure!(fin && len <= 125, "bad control frame");
                    }
                    let mut payload = vec![0u8; usize::try_from(len)?];
                    reader.read_exact(&mut payload).await?;
                    for (i, b) in payload.iter_mut().enumerate() {
                        *b ^= mask[i % 4];
                    }
                    match opcode {
                        0..=2 => pipe_write.write_all(&payload).await?,
                        8 => {
                            // Default close handler: echo the code, then report EOF for 1000/1005.
                            let code = if payload.len() >= 2 {
                                u16::from_be_bytes([payload[0], payload[1]])
                            } else {
                                1005
                            };
                            if !closed.swap(true, Ordering::SeqCst) {
                                let reply = if code == 1005 {
                                    Vec::new()
                                } else {
                                    code.to_be_bytes().to_vec()
                                };
                                let _ = tcp_write
                                    .lock()
                                    .await
                                    .write_all(&frame_as(8, &reply, client))
                                    .await;
                            }
                            ensure!(code == 1000 || code == 1005, "websocket: close {code}");
                            return Ok(());
                        }
                        9 => {
                            tcp_write
                                .lock()
                                .await
                                .write_all(&frame_as(10, &payload, client))
                                .await?
                        }
                        10 => {}
                        other => bail!("unknown opcode {other}"),
                    }
                }
            }
            .await;
            if let Err(error) = result {
                tracing::debug!(%error, "websocket read ended");
            }
            let _ = pipe_write.shutdown().await;
        });
    }
    // Writer: payload pipe -> binary messages; close frame 1000 on shutdown.
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        let mut ping = tokio::time::interval(Duration::from_secs(u64::from(heartbeat.max(1))));
        ping.tick().await;
        loop {
            tokio::select! {
                n = pipe_read.read(&mut buf) => {
                    let n = n.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    let message = frame_as(2, &buf[..n], client);
                    if tcp_write.lock().await.write_all(&message).await.is_err() {
                        return;
                    }
                }
                _ = ping.tick(), if heartbeat > 0 => {
                    if tcp_write.lock().await.write_all(&frame_as(9, &[], client)).await.is_err() {
                        return;
                    }
                }
            }
        }
        let mut w = tcp_write.lock().await;
        if !closed.swap(true, Ordering::SeqCst) {
            let _ = w
                .write_all(&frame_as(8, &1000u16.to_be_bytes(), client))
                .await;
        }
        let _ = w.shutdown().await;
    });
    app
}

/// The WebSocket dialer (gorilla over Xray's dialWebSocket): Go's net/http request layout,
/// Chrome headers, optional early data in Sec-WebSocket-Protocol, then client framing.
pub async fn connect_ws(
    mut io: BoxIo,
    host: &str,
    path: &str,
    headers: &[(String, String)],
    early: &[u8],
    heartbeat: u32,
) -> Result<BoxIo> {
    let mut key = [0u8; 16];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key);
    let key = STANDARD.encode(key);
    let has = |name: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    let mut fields: Vec<(String, String)> = headers.to_vec();
    if !has("User-Agent") {
        fields.extend(crate::browser::chrome_headers("ws", has));
    }
    fields.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
    fields.extend([
        ("Upgrade".to_owned(), "websocket".to_owned()),
        ("Connection".to_owned(), "Upgrade".to_owned()),
        ("Sec-WebSocket-Key".to_owned(), key.clone()),
        ("Sec-WebSocket-Version".to_owned(), "13".to_owned()),
    ]);
    if !early.is_empty() {
        fields.push((
            "Sec-WebSocket-Protocol".to_owned(),
            URL_SAFE_NO_PAD.encode(early),
        ));
    }
    // http.Request.Write: Host, User-Agent, then the remaining headers sorted by key.
    let agent = fields
        .iter()
        .position(|(k, _)| k == "User-Agent")
        .map(|i| fields.remove(i));
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n");
    let agent = agent.map_or("Go-http-client/1.1".to_owned(), |(_, v)| v);
    request.push_str(&format!("User-Agent: {agent}\r\n"));
    for (k, v) in &fields {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("\r\n");
    io.write_all(request.as_bytes()).await?;
    io.flush().await?;
    let mut buf = Vec::new();
    let end = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok(i);
            }
            ensure!(buf.len() < 64 * 1024, "WebSocket response header too large");
            let mut chunk = [0u8; 4096];
            let n = io.read(&mut chunk).await?;
            ensure!(n > 0, "unexpected EOF");
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .context("WebSocket handshake timeout")??;
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let carry = buf[end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default().to_owned();
    let header = |name: &str| {
        head.split("\r\n")
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_owned())
            .unwrap_or_default()
    };
    let expected = STANDARD.encode(
        Sha1::new()
            .chain_update(key.as_bytes())
            .chain_update(WS_GUID)
            .finalize(),
    );
    if status.split(' ').nth(1) != Some("101")
        || !header("Upgrade").to_lowercase().contains("websocket")
        || !header("Connection").to_lowercase().contains("upgrade")
        || header("Sec-WebSocket-Accept") != expected
    {
        bail!("websocket: bad handshake: {status}");
    }
    Ok(Box::new(websocket(io, Vec::new(), carry, heartbeat, true)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_and_hosts_follow_xray() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("ws"), "/ws");
        assert_eq!(normalize_path("/api/websocket?ed=2048"), "/api/websocket");
        assert!(valid_host("Example.com:443", "example.com"));
        assert!(valid_host("[::1]:80", "::1"));
        assert!(!valid_host("evil.com", "example.com"));
    }
    #[test]
    fn trusted_forwarded_for_matches_go() {
        let req = |h: &[(&str, &str)]| Request {
            method: "GET".into(),
            path: "/".into(),
            host: String::new(),
            headers: h
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        };
        let remote: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let trusted = vec!["X-Forwarded-For".to_owned()];
        assert_eq!(
            forwarded(
                &req(&[("x-forwarded-for", "203.0.113.9, 10.0.0.1")]),
                &trusted,
                remote
            ),
            "203.0.113.9:0".parse().unwrap()
        );
        assert_eq!(
            forwarded(&req(&[("X-Forwarded-For", "203.0.113.9")]), &[], remote),
            remote
        );
        assert_eq!(
            forwarded(&req(&[("X-Forwarded-For", "not-an-ip")]), &trusted, remote),
            remote
        );
        assert_eq!(
            forwarded(
                &req(&[("X-Forwarded-For", "203.0.113.9")]),
                &["CF-Connecting-IP".to_owned()],
                remote
            ),
            remote
        );
    }
}

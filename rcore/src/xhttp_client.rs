//! Xray 26.11.9 transport/internet/splithttp/{dialer,client,mux,connection}.go.
use crate::{
    transport::BoxIo,
    vless::Address,
    vless_out::{Security, Server},
    xhttp::rand_between,
    xhttp_request::Config,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use std::{
    collections::{HashMap, VecDeque},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    task::{Context as Cx, Poll, ready},
    thread::ThreadId,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::{oneshot, watch},
    task::JoinHandle,
    time::Instant,
};

const BUFFER_SIZE: usize = 8192; // common/buf.Size
const IDLE: Duration = Duration::from_secs(300); // common/net.ConnIdleTimeout

pub struct Client {
    config: Arc<Config>,
    manager: Mutex<Manager>,
}

struct Manager {
    connections: i64,
    concurrency: i64,
    clients: Vec<Arc<HttpClient>>,
}

struct HttpClient {
    h2: h2_transport::Pool,
    raw: Mutex<HashMap<ThreadId, RawPool>>,
    closed: AtomicBool,
    running: AtomicI64,
    uses: AtomicI64,
    requests: AtomicI64,
    expires: Option<Instant>,
}

#[derive(Default)]
struct RawPool {
    private: Option<BoxIo>,
    shared: VecDeque<BoxIo>,
}

impl HttpClient {
    fn expired(&self) -> bool {
        self.expires.is_some_and(|at| Instant::now() > at)
    }
}

impl Client {
    pub fn new(config: Config) -> Self {
        Self {
            manager: Mutex::new(Manager {
                connections: rand_between(config.xmux.max_connections),
                concurrency: rand_between(config.xmux.max_concurrency),
                clients: Vec::new(),
            }),
            config: Arc::new(config),
        }
    }

    /// getHTTPClient: one manager per outbound stream-settings identity.
    fn select(&self) -> Arc<HttpClient> {
        let mut m = self.manager.lock().unwrap();
        m.clients.retain(|c| {
            !c.closed.load(Ordering::Acquire)
                && c.uses.load(Ordering::Acquire) != 0
                && c.requests.load(Ordering::Acquire) > 0
                && !c.expired()
        });
        let choices: Vec<_> = m
            .clients
            .iter()
            .filter(|c| m.concurrency <= 0 || c.running.load(Ordering::Acquire) < m.concurrency)
            .cloned()
            .collect();
        if m.clients.is_empty()
            || (m.connections > 0 && (m.clients.len() as i64) < m.connections)
            || choices.is_empty()
        {
            let reuse = rand_between(self.config.xmux.reuse);
            let requests = rand_between(self.config.xmux.requests);
            let seconds = rand_between(self.config.xmux.seconds);
            let client = Arc::new(HttpClient {
                h2: h2_transport::Pool::new(),
                raw: Mutex::new(HashMap::new()),
                closed: AtomicBool::new(false),
                running: AtomicI64::new(0),
                uses: AtomicI64::new(if reuse > 0 { reuse - 1 } else { -1 }),
                requests: AtomicI64::new(if requests > 0 {
                    requests
                } else {
                    i32::MAX as i64
                }),
                expires: (seconds > 0)
                    .then(|| Instant::now() + Duration::from_secs(seconds as u64)),
            });
            m.clients.push(client.clone());
            client
        } else {
            let c = choices[rand_between((0, choices.len() as i64)) as usize].clone();
            if c.uses.load(Ordering::Acquire) > 0 {
                c.uses.fetch_sub(1, Ordering::AcqRel);
            }
            c
        }
    }

    pub async fn connect(
        self: &Arc<Self>,
        server: &Server,
        socket: &crate::socket::Options,
    ) -> Result<BoxIo> {
        let h2 = match &server.security {
            Security::None => false,
            Security::Reality(_) => true,
            Security::Tls(tls) => {
                ensure!(tls.alpn != ["h3"], "XHTTP over HTTP/3 is not ported yet");
                tls.alpn != ["http/1.1"]
            }
        };
        let scheme = if matches!(server.security, Security::None) {
            "http"
        } else {
            "https"
        };
        let authority = if !self.config.server.host.is_empty() {
            self.config.server.host.clone()
        } else {
            match &server.security {
                Security::Tls(tls) | Security::Reality(tls) if !tls.server_name.is_empty() => {
                    tls.server_name.clone()
                }
                _ => server.address.to_string(),
            }
        };
        let dial = Dial {
            address: server.address.clone(),
            port: server.port,
            security: server.security.clone(),
            socket: socket.clone(),
            h2,
        };
        let mode = match self.config.server.mode.as_str() {
            "auto" | "" if matches!(server.security, Security::Reality(_)) => "stream-one",
            "auto" | "" => "packet-up",
            mode => mode,
        };
        let session = if mode == "stream-one" {
            String::new()
        } else {
            self.config.session_id()?
        };
        tracing::info!(
            "transport/internet/splithttp: XHTTP is dialing to {}:{}, mode {mode}, HTTP version {}, host {authority}",
            server.address,
            server.port,
            if h2 { "2" } else { "1.1" }
        );
        let selected = self.select();
        selected.running.fetch_add(1, Ordering::AcqRel);
        let running = Running(selected.clone());
        let (reader, down) = tokio::io::duplex(BUFFER_SIZE);
        let size = if mode == "packet-up" {
            rand_between(self.config.post_size) as usize
        } else {
            BUFFER_SIZE
        };
        let (writer, upload) = tokio::io::duplex(size);
        let mut upload = Some(upload);
        let error = Arc::new(Mutex::new(None));
        let clients = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        let (request, _) = self.config.request(
            scheme,
            &authority,
            &session,
            None,
            None,
            mode == "stream-one",
        )?;
        selected.requests.fetch_sub(1, Ordering::AcqRel);
        let (stop, stopped) = oneshot::channel();
        let body = if mode == "stream-one" {
            Upload::stream(upload.take().unwrap(), stopped)
        } else {
            Upload::packet(Bytes::new(), None)
        };
        // OpenStream returns after acquiring the socket, before response headers.
        let (response, active) = waiting(
            selected
                .start(&dial, request.map(|_| body), self.config.xmux.keep_alive)
                .await,
        );
        tasks.push(download(
            response,
            down,
            error.clone(),
            selected.clone(),
            active,
            stop,
        ));
        if mode == "stream-up" {
            let (request, _) = self
                .config
                .request(scheme, &authority, &session, None, None, true)?;
            selected.requests.fetch_sub(1, Ordering::AcqRel);
            let (stop, stopped) = oneshot::channel();
            let (response, active) = waiting(
                selected
                    .start(
                        &dial,
                        request.map(|_| Upload::stream(upload.take().unwrap(), stopped)),
                        self.config.xmux.keep_alive,
                    )
                    .await,
            );
            tasks.push(tokio::spawn(async move {
                let _active = active;
                if let Ok(response) = response.await {
                    drain(response.into_body()).await;
                }
                let _ = stop.send(());
            }));
        } else if mode == "packet-up" {
            let owner = self.clone();
            let clients = clients.clone();
            let (scheme, authority) = (scheme.to_owned(), authority.clone());
            tasks.push(tokio::spawn(async move {
                if let Err(error) = owner
                    .packets(
                        upload.take().unwrap(),
                        size,
                        selected,
                        dial,
                        (&scheme, &authority, &session),
                        clients,
                    )
                    .await
                {
                    tracing::info!(
                        "transport/internet/splithttp: failed to send upload > {error:#}"
                    );
                }
            }));
        }
        Ok(Box::new(Connection {
            reader,
            writer,
            error,
            tasks,
            _running: running,
            _clients: clients,
        }))
    }

    async fn packets(
        &self,
        mut upload: DuplexStream,
        max: usize,
        mut client: Arc<HttpClient>,
        dial: Dial,
        target: (&str, &str, &str),
        clients: Arc<Mutex<Vec<Arc<HttpClient>>>>,
    ) -> Result<()> {
        let (scheme, authority, session) = target;
        let mut seq = 0;
        let mut last: Option<Instant> = None;
        let (failure_tx, mut failure) = watch::channel(None::<String>);
        let mut buffer = vec![0u8; max.min(BUFFER_SIZE)];
        loop {
            let n = tokio::select! {
                biased;
                _ = failure.changed() => anyhow::bail!("{}", failure.borrow().as_deref().unwrap_or("XHTTP upload failed")),
                n = upload.read(&mut buffer) => n?,
            };
            if n == 0 {
                return Ok(());
            }
            let mut payload = buffer[..n].to_vec();
            while payload.len() < max {
                let take = buffer.len().min(max - payload.len());
                let n = std::future::poll_fn(|cx| {
                    let mut buf = ReadBuf::new(&mut buffer[..take]);
                    match Pin::new(&mut upload).poll_read(cx, &mut buf) {
                        Poll::Pending => Poll::Ready(Ok(0)),
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.filled().len())),
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    }
                })
                .await?;
                if n == 0 {
                    break;
                }
                payload.extend_from_slice(&buffer[..n]);
            }
            if self.config.post_interval.0 > 0
                && let Some(last) = last
            {
                tokio::select! {
                    _ = failure.changed() => anyhow::bail!("{}", failure.borrow().as_deref().unwrap_or("XHTTP upload failed")),
                    _ = tokio::time::sleep_until(last + Duration::from_millis(rand_between(self.config.post_interval) as u64)) => {}
                }
            }
            last = Some(Instant::now());
            if client.requests.fetch_sub(1, Ordering::AcqRel) <= 1 || client.expired() {
                let next = self.select();
                // Go's H1/H2 Close does not terminate requests already sent by this tunnel.
                clients.lock().unwrap().push(next.clone());
                client = next;
            }
            let (request, bytes) = self.config.request(
                scheme,
                authority,
                session,
                Some(seq),
                Some(&payload),
                false,
            )?;
            seq += 1;
            if dial.h2 {
                let (sent, received) = oneshot::channel();
                let (response, active) = client
                    .start(
                        &dial,
                        request.map(|_| Upload::packet(bytes, Some(sent))),
                        self.config.xmux.keep_alive,
                    )
                    .await?;
                let failed_client = client.clone();
                let failure_tx = failure_tx.clone();
                tokio::spawn(async move {
                    let _active = active;
                    match response.await {
                        Ok(response) => {
                            let status = response.status();
                            drain(response.into_body()).await;
                            if status != StatusCode::OK {
                                let _ = failure_tx.send(Some(format!("bad status code: {status}")));
                            }
                        }
                        Err(error) => {
                            failed_client.closed.store(true, Ordering::Release);
                            let _ = failure_tx.send(Some(format!("{error:#}")));
                        }
                    }
                });
                // Dispatch waits for body consumption, never the HTTP response.
                tokio::select! {
                    _ = failure.changed() => anyhow::bail!("{}", failure.borrow().as_deref().unwrap_or("XHTTP upload failed")),
                    _ = received => {}
                }
            } else {
                // Request.Write's WroteRequest trace fires during Go's in-memory serialization.
                let (sent, written) = oneshot::channel();
                let client = client.clone();
                let dial = dial.clone();
                let failure_tx = failure_tx.clone();
                tokio::spawn(async move {
                    let serialized = raw_request(request, bytes);
                    let _ = sent.send(());
                    let result = match serialized {
                        Ok(bytes) => client.post_raw(&dial, &bytes).await,
                        Err(error) => Err(error),
                    };
                    if let Err(error) = result {
                        let _ = failure_tx.send(Some(format!("{error:#}")));
                    }
                });
                tokio::select! {
                    _ = failure.changed() => anyhow::bail!("{}", failure.borrow().as_deref().unwrap_or("XHTTP upload failed")),
                    _ = written => {}
                }
            }
        }
    }
}

struct Running(Arc<HttpClient>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.running.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone)]
struct Dial {
    address: Address,
    port: u16,
    security: Security,
    socket: crate::socket::Options,
    h2: bool,
}
impl Dial {
    async fn connect(&self) -> Result<BoxIo> {
        let addrs: Vec<_> = match &self.address {
            Address::Ip(ip) => vec![std::net::SocketAddr::new(*ip, self.port)],
            Address::Domain(name) => tokio::net::lookup_host((name.as_str(), self.port))
                .await?
                .collect(),
        };
        let stream = crate::app::connect_once(&addrs, &self.socket).await?;
        stream.set_nodelay(true).ok();
        Ok(match &self.security {
            Security::None => Box::new(stream),
            Security::Tls(tls) | Security::Reality(tls) => {
                crate::tls_client::connect(stream, tls).await?.0
            }
        })
    }
}

#[path = "xhttp_h2.rs"]
mod h2_transport;
#[path = "xhttp_redirect.rs"]
mod redirects;

type Active = ();

enum ResponseBody {
    H1(Incoming),
    H2(h2_transport::Body),
}
impl Body for ResponseBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Cx<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        match &mut *self {
            Self::H1(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|frame| frame.map(|result| result.map_err(io::Error::other))),
            Self::H2(body) => Pin::new(body).poll_frame(cx),
        }
    }
    fn is_end_stream(&self) -> bool {
        match self {
            Self::H1(body) => body.is_end_stream(),
            Self::H2(body) => body.is_end_stream(),
        }
    }
    fn size_hint(&self) -> SizeHint {
        match self {
            Self::H1(body) => body.size_hint(),
            Self::H2(body) => body.size_hint(),
        }
    }
}

type ResponseFuture = Pin<Box<dyn Future<Output = Result<Response<ResponseBody>>> + Send>>;

#[derive(Clone)]
struct AutoGzip;

fn response_future(
    response: impl Future<Output = Result<Response<Incoming>, hyper::Error>> + Send + 'static,
    gzip: bool,
) -> ResponseFuture {
    Box::pin(async move {
        let mut response = response.await?.map(ResponseBody::H1);
        if gzip {
            response.extensions_mut().insert(AutoGzip);
        }
        Ok(response)
    })
}

fn waiting(result: Result<(ResponseFuture, Option<Active>)>) -> (ResponseFuture, Option<Active>) {
    result.unwrap_or_else(|error| (Box::pin(async { Err(error) }), None))
}

impl HttpClient {
    /// sync.Pool: a worker's private item cannot be stolen by another worker.
    fn take_raw(&self) -> Option<BoxIo> {
        let id = std::thread::current().id();
        let mut pools = self.raw.lock().unwrap();
        let local = pools.entry(id).or_default();
        local
            .private
            .take()
            .or_else(|| local.shared.pop_back())
            .or_else(|| {
                pools
                    .iter_mut()
                    .filter(|(key, _)| **key != id)
                    .find_map(|(_, pool)| pool.shared.pop_front())
            })
    }

    fn put_raw(&self, io: BoxIo) {
        let mut pools = self.raw.lock().unwrap();
        let local = pools.entry(std::thread::current().id()).or_default();
        if local.private.is_none() {
            local.private = Some(io);
        } else {
            local.shared.push_back(io);
        }
    }

    async fn start(
        self: &Arc<Self>,
        dial: &Dial,
        request: Request<Upload>,
        keep_alive: i64,
    ) -> Result<(ResponseFuture, Option<Active>)> {
        redirects::start(self, dial, request, keep_alive).await
    }

    async fn request_once(
        &self,
        dial: &Dial,
        mut request: Request<Upload>,
        keep_alive: i64,
    ) -> Result<(ResponseFuture, Option<Active>)> {
        if let Some((credentials, host)) = request
            .uri()
            .authority()
            .and_then(|a| a.as_str().rsplit_once('@'))
        {
            let host = host.to_owned();
            if request
                .headers()
                .get("authorization")
                .is_none_or(|h| h.is_empty())
            {
                let (user, pass) = credentials.split_once(':').unwrap_or((credentials, ""));
                let mut decoded: Vec<u8> = percent_encoding::percent_decode_str(user).collect();
                decoded.push(b':');
                decoded.extend(percent_encoding::percent_decode_str(pass));
                let auth =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, decoded);
                request
                    .headers_mut()
                    .insert("authorization", format!("Basic {auth}").parse()?);
            }
            let mut parts = request.uri().clone().into_parts();
            parts.authority = Some(host.parse()?);
            *request.uri_mut() = http::Uri::from_parts(parts)?;
        }
        for name in ["content-length", "transfer-encoding", "trailer"] {
            request.headers_mut().remove(name);
        }
        if request
            .headers()
            .get("user-agent")
            .is_some_and(|h| h.is_empty())
        {
            request.headers_mut().remove("user-agent");
        }
        let gzip = request
            .headers()
            .get("accept-encoding")
            .is_none_or(|h| h.is_empty())
            && request.headers().get("range").is_none_or(|h| h.is_empty())
            && request.method() != http::Method::HEAD;
        if gzip {
            request
                .headers_mut()
                .insert("accept-encoding", "gzip".parse().unwrap());
        }
        if dial.h2 {
            let (response, active) = self.h2.start(dial, request, keep_alive).await?;
            return Ok((
                Box::pin(async move {
                    let mut response = response.await?;
                    if gzip {
                        response.extensions_mut().insert(AutoGzip);
                    }
                    Ok(response)
                }),
                active,
            ));
        }
        let host = request
            .uri()
            .authority()
            .context("XHTTP authority")?
            .as_str()
            .parse()?;
        request.headers_mut().insert("host", host);
        *request.uri_mut() = request
            .uri()
            .path_and_query()
            .context("XHTTP path")?
            .as_str()
            .parse()?;
        request
            .headers_mut()
            .insert("connection", "close".parse().unwrap());
        let io = dial.connect().await?;
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .title_case_headers(true)
            .max_headers(32768) // http::HeaderMap's representable capacity.
            .max_header_size(10 << 20) // Go Transport.MaxResponseHeaderBytes default.
            .max_buf_size(10 << 20)
            .allow_obsolete_multiline_headers_in_responses(true)
            .handshake(hyper_util::rt::TokioIo::new(io))
            .await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok((response_future(sender.send_request(request), gzip), None))
    }

    /// The pinned H1 raw-packet pool returns after Write, without awaiting a response.
    async fn post_raw(&self, dial: &Dial, bytes: &[u8]) -> Result<()> {
        loop {
            let pooled = self.take_raw();
            let fresh = pooled.is_none();
            let mut io = match pooled {
                Some(io) => io,
                None => dial.connect().await?,
            };
            let result = async {
                io.write_all(bytes).await?;
                io.flush().await
            }
            .await;
            match result {
                Ok(()) => {
                    self.put_raw(io);
                    return Ok(());
                }
                Err(error) if fresh => return Err(error.into()),
                Err(_) => {}
            }
        }
    }
}

fn raw_request(request: Request<()>, body: Bytes) -> Result<Vec<u8>> {
    let target = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let mut bytes = format!(
        "{} {target} HTTP/1.1\r\nHost: {}\r\n",
        request.method(),
        request.uri().authority().context("XHTTP authority")?
    )
    .into_bytes();
    let agent = request
        .headers()
        .get("user-agent")
        .map(|h| h.as_bytes())
        .unwrap_or(b"Go-http-client/1.1");
    if !agent.is_empty() {
        bytes.extend_from_slice(b"User-Agent: ");
        bytes.extend_from_slice(agent);
        bytes.extend_from_slice(b"\r\n");
    }
    if !body.is_empty()
        || matches!(
            *request.method(),
            http::Method::POST | http::Method::PUT | http::Method::PATCH
        )
    {
        bytes.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    let mut headers: Vec<_> = request
        .headers()
        .iter()
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "host" | "user-agent" | "content-length" | "transfer-encoding" | "trailer"
            )
        })
        .map(|(key, value)| {
            let name = key
                .as_str()
                .split('-')
                .map(|word| {
                    let mut chars = word.chars();
                    chars
                        .next()
                        .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
                .join("-");
            (name, value)
        })
        .collect();
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in headers {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

enum Upload {
    Packet {
        data: Option<Bytes>,
        sent: Option<oneshot::Sender<()>>,
    },
    Stream {
        reader: Option<DuplexStream>,
        stop: Option<oneshot::Receiver<()>>,
    },
}
impl Upload {
    fn packet(data: Bytes, sent: Option<oneshot::Sender<()>>) -> Self {
        Self::Packet {
            data: Some(data),
            sent,
        }
    }
    fn stream(reader: DuplexStream, stop: oneshot::Receiver<()>) -> Self {
        Self::Stream {
            reader: Some(reader),
            stop: Some(stop),
        }
    }
}
impl Body for Upload {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Cx<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        match &mut *self {
            Self::Packet { data, sent } => {
                let frame = data
                    .take()
                    .filter(|data| !data.is_empty())
                    .map(|data| Ok(Frame::data(data)));
                if let Some(sent) = sent.take() {
                    let _ = sent.send(());
                }
                Poll::Ready(frame)
            }
            Self::Stream { reader, stop } => {
                if let Some(stopped) = stop {
                    match Pin::new(stopped).poll(cx) {
                        Poll::Ready(Ok(())) => {
                            reader.take();
                            return Poll::Ready(None);
                        }
                        Poll::Ready(Err(_)) => {
                            *stop = None;
                        }
                        Poll::Pending => {}
                    }
                }
                let Some(io) = reader else {
                    return Poll::Ready(None);
                };
                let mut bytes = [0; BUFFER_SIZE];
                let mut buf = ReadBuf::new(&mut bytes);
                match ready!(Pin::new(io).poll_read(cx, &mut buf)) {
                    Ok(()) if buf.filled().is_empty() => Poll::Ready(None),
                    Ok(()) => {
                        Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(buf.filled())))))
                    }
                    Err(error) => Poll::Ready(Some(Err(error))),
                }
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        matches!(self, Self::Packet { data: None, .. })
    }
    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Packet { data, .. } => {
                SizeHint::with_exact(data.as_ref().map_or(0, |d| d.len()) as u64)
            }
            _ => SizeHint::default(),
        }
    }
}

async fn drain(mut body: ResponseBody) {
    while let Some(frame) = body.frame().await {
        if frame.is_err() {
            break;
        }
    }
}

fn download(
    response: ResponseFuture,
    mut down: DuplexStream,
    error: Arc<Mutex<Option<String>>>,
    client: Arc<HttpClient>,
    active: Option<Active>,
    stop: oneshot::Sender<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _active = active;
        let result: Result<()> = async {
            let response = response.await.inspect_err(|_| {
                client.closed.store(true, Ordering::Release);
            })?;
            if response.status() != StatusCode::OK {
                let status = response.status();
                drain(response.into_body()).await;
                anyhow::bail!("unexpected status {status}");
            }
            let gzip = response.extensions().get::<AutoGzip>().is_some()
                && response
                    .headers()
                    .get("content-encoding")
                    .is_some_and(|h| h.as_bytes().eq_ignore_ascii_case(b"gzip"));
            let stream =
                tokio_stream::StreamExt::map(response.into_body().into_data_stream(), |result| {
                    result.map_err(io::Error::other)
                });
            let reader = tokio_util::io::StreamReader::new(stream);
            if gzip {
                let mut reader = async_compression::tokio::bufread::GzipDecoder::new(reader);
                reader.multiple_members(true);
                tokio::io::copy(&mut reader, &mut down).await?;
            } else {
                tokio::io::copy(&mut { reader }, &mut down).await?;
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            let _ = stop.send(());
            *error.lock().unwrap() = Some(format!("XHTTP download: {e:#}"));
        }
    })
}

struct Connection {
    reader: DuplexStream,
    writer: DuplexStream,
    error: Arc<Mutex<Option<String>>>,
    tasks: Vec<JoinHandle<()>>,
    _running: Running,
    _clients: Arc<Mutex<Vec<Arc<HttpClient>>>>,
}
impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Cx<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        ready!(Pin::new(&mut self.reader).poll_read(cx, out))?;
        if out.filled().len() == before
            && let Some(error) = self.error.lock().unwrap().as_ref()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                error.clone(),
            )));
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Cx<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Cx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Cx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
#[path = "xhttp_client_tests.rs"]
mod tests;

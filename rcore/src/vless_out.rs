//! Port of xray-core proxy/vless/outbound (Xray 26.11.9): the VLESS client over RAW or
//! WebSocket, plain, TLS or REALITY, with xtls-rprx-vision and UDP carried as XUDP
//! (mux.cool) or as length-prefixed packets.
use crate::{
    app::{Counted, Packet},
    stats::Counter,
    tls13::DirectControl,
    transport::BoxIo,
    vless::{Address, XRV},
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context as TaskCx, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf},
    sync::Mutex as AsyncMutex,
};

pub enum Network {
    Raw,
    Xhttp(Arc<crate::xhttp_client::Client>),
    Ws {
        path: String,
        host: String,
        headers: Vec<(String, String)>,
        early: usize,
        heartbeat: u32,
    },
}

#[derive(Clone)]
pub enum Security {
    None,
    Tls(crate::tls_client::Client),
    Reality(crate::tls_client::Client),
}

/// One vnext server with its single user, plus the outbound's stream settings.
pub struct Server {
    pub address: Address,
    pub port: u16,
    pub id: [u8; 16],
    /// "", xtls-rprx-vision or xtls-rprx-vision-udp443.
    pub flow: String,
    pub level: u32,
    pub network: Network,
    pub security: Security,
}

const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;
const CMD_MUX: u8 = 3;

impl Server {
    fn vision(&self) -> bool {
        self.flow.starts_with(XRV)
    }

    /// EncodeRequestHeader: version 0, UUID, addons (flow), command, port and address.
    fn header(&self, command: u8, dest: Option<(&Address, u16)>) -> Vec<u8> {
        let mut h = vec![0];
        h.extend_from_slice(&self.id);
        if self.vision() {
            // The -udp443 suffix only relaxes the client; the server sees plain Vision.
            let mut addons = vec![0x0a, XRV.len() as u8];
            addons.extend_from_slice(XRV.as_bytes());
            h.push(addons.len() as u8);
            h.extend_from_slice(&addons);
        } else {
            h.push(0);
        }
        h.push(command);
        if let Some((address, port)) = dest {
            crate::mux::write_address_port(&mut h, address, port);
        }
        h
    }

    /// dialer.Dial with retry.ExponentialBackoff(5, 200): TCP, then TLS/REALITY, then WS.
    async fn dial(
        &self,
        socket: &crate::socket::Options,
        early: &[u8],
    ) -> Result<(BoxIo, Option<DirectControl>)> {
        let mut last = None;
        for attempt in 0..5u32 {
            match self.dial_once(socket, early).await {
                Ok(conn) => return Ok(conn),
                Err(error) => {
                    tracing::debug!(
                        "VLESS dial to {}:{} failed: {error:#}",
                        self.address,
                        self.port
                    );
                    last = Some(error);
                }
            }
            tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
        }
        Err(last
            .unwrap_or_else(|| anyhow::anyhow!("failed to dial"))
            .context("failed to find an available destination"))
    }

    async fn dial_once(
        &self,
        socket: &crate::socket::Options,
        early: &[u8],
    ) -> Result<(BoxIo, Option<DirectControl>)> {
        if let Network::Xhttp(client) = &self.network {
            return Ok((client.connect(self, socket).await?, None));
        }
        let addrs: Vec<_> = match &self.address {
            Address::Ip(ip) => vec![std::net::SocketAddr::new(*ip, self.port)],
            Address::Domain(d) => tokio::net::lookup_host((d.as_str(), self.port))
                .await?
                .collect(),
        };
        let tcp = crate::app::connect_once(&addrs, socket).await?;
        tcp.set_nodelay(true).ok();
        let (io, direct): (BoxIo, _) = match &self.security {
            Security::None => (Box::new(tcp), None),
            Security::Tls(client) | Security::Reality(client) => {
                let (io, direct) = crate::tls_client::connect(tcp, client).await?;
                (io, Some(direct))
            }
        };
        match &self.network {
            Network::Raw => Ok((io, direct)),
            Network::Xhttp(_) => unreachable!(),
            Network::Ws {
                path,
                host,
                headers,
                heartbeat,
                ..
            } => {
                let io = crate::transport::connect_ws(io, host, path, headers, early, *heartbeat)
                    .await
                    .with_context(|| format!("failed to dial to (ws://{host}{path})"))?;
                Ok((io, direct))
            }
        }
    }

    /// Opens a TCP tunnel: the request header goes out with `first` (Vision pads an empty
    /// one to hide the header). `counters` are the outbound's (uplink, downlink).
    pub async fn open_tcp(
        &self,
        socket: &crate::socket::Options,
        dest: &Address,
        port: u16,
        first: &[u8],
        counters: (Option<Arc<Counter>>, Option<Arc<Counter>>),
    ) -> Result<BoxIo> {
        self.open(socket, CMD_TCP, Some((dest, port)), first, counters)
            .await
    }

    async fn open(
        &self,
        socket: &crate::socket::Options,
        command: u8,
        dest: Option<(&Address, u16)>,
        first: &[u8],
        (up, down): (Option<Arc<Counter>>, Option<Arc<Counter>>),
    ) -> Result<BoxIo> {
        let header = self.header(command, dest);
        let mut early = Vec::new();
        if let Network::Ws { early: limit, .. } = &self.network
            && *limit > 0
            && !self.vision()
            && header.len() + first.len() <= *limit
        {
            // delayDialConn: the first write rides in Sec-WebSocket-Protocol when it fits.
            early = [header.as_slice(), first].concat();
        }
        let (io, direct) = self.dial(socket, &early).await?;
        if let Some(counter) = &up {
            // Go's counter wraps delayDialConn before its first write triggers the upgrade.
            counter.add(early.len() as i64);
        }
        let conn: BoxIo = Box::new(Counted::new(io, down, up));
        if self.vision() {
            ensure!(
                matches!(self.network, Network::Raw),
                "XTLS only supports TLS and REALITY directly for now."
            );
            let direct = direct.context("XTLS only supports TLS and REALITY directly for now.")?;
            let mut io = crate::vision::client(conn, self.id, direct, header, first)?;
            io.flush().await?;
            return Ok(io);
        }
        let mut io = Box::new(Response {
            inner: conn,
            header: Some(Vec::new()),
        });
        if early.is_empty() {
            io.write_all(&[header.as_slice(), first].concat()).await?;
            io.flush().await?;
        }
        Ok(io)
    }

    /// Opens a UDP tunnel to `dest`: XUDP inside mux.cool for Vision (and, as Xray's cone
    /// default, for every port but 53 and 443), otherwise length-prefixed UDP packets.
    pub async fn open_udp(
        &self,
        socket: &crate::socket::Options,
        dest: &Address,
        port: u16,
        counters: (Option<Arc<Counter>>, Option<Arc<Counter>>),
    ) -> Result<UdpTunnel> {
        if self.flow == XRV && port == 443 {
            bail!("XTLS rejected UDP/443 traffic");
        }
        let xudp = self.vision() || (port != 53 && port != 443);
        let io = if xudp {
            // v1.mux.cool:666 marks XUDP; mux requests carry no address in the header.
            self.open(socket, CMD_MUX, None, &[], counters).await?
        } else {
            self.open(socket, CMD_UDP, Some((dest, port)), &[], counters)
                .await?
        };
        let (reader, writer) = tokio::io::split(io);
        Ok(UdpTunnel {
            reader: AsyncMutex::new(reader),
            writer: AsyncMutex::new(writer),
            xudp: xudp.then(|| Xudp {
                target: (dest.clone(), port),
                new_sent: AtomicBool::new(false),
            }),
        })
    }
}

/// Strips the VLESS response header (version 0, addons) from the downlink.
struct Response {
    inner: BoxIo,
    header: Option<Vec<u8>>,
}

impl AsyncRead for Response {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while let Some(header) = self.header.as_mut() {
            let need = match header.len() {
                0 | 1 => 2 - header.len(),
                n => 2 + header[1] as usize - n,
            };
            if need == 0 {
                self.header = None;
                break;
            }
            let mut byte = vec![0u8; need];
            let mut read = ReadBuf::new(&mut byte);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read))?;
            let filled = read.filled().to_vec();
            if filled.is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to read response version",
                )));
            }
            let header = self.header.as_mut().expect("header");
            header.extend_from_slice(&filled);
            if header[0] != 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected response version. Expecting 0 but actually {}",
                        header[0]
                    ),
                )));
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Response {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct Xudp {
    target: (Address, u16),
    new_sent: AtomicBool,
}

/// UDP through a VLESS server; packets keep their destinations under XUDP.
pub struct UdpTunnel {
    reader: AsyncMutex<ReadHalf<BoxIo>>,
    writer: AsyncMutex<WriteHalf<BoxIo>>,
    xudp: Option<Xudp>,
}

impl UdpTunnel {
    /// xudp.PacketWriter / LengthPacketWriter; returns the bytes written (0 when dropped).
    pub async fn send(&self, data: &[u8], addr: Option<&(Address, u16)>) -> Result<usize> {
        let overhead = if self.xudp.is_some() { 666 } else { 2 };
        if data.is_empty() || data.len() > 8192 - overhead {
            return Ok(0);
        }
        let mut writer = self.writer.lock().await;
        let mut frame = Vec::with_capacity(data.len() + 64);
        if let Some(x) = &self.xudp {
            frame.extend_from_slice(&[0, 0, 0, 0]);
            if !x.new_sent.swap(true, Ordering::AcqRel) {
                frame.extend_from_slice(&[1, 1, 2]);
                crate::mux::write_address_port(&mut frame, &x.target.0, x.target.1);
                if addr.is_some() {
                    // The GlobalID: zero, since only socks/dokodemo/shadowsocks/tun inbounds
                    // derive one, and an empty ID is not a full-cone XUDP session.
                    frame.extend_from_slice(&[0; 8]);
                }
            } else {
                frame.extend_from_slice(&[2, 1]);
                if let Some((address, port)) = addr {
                    frame.push(2);
                    crate::mux::write_address_port(&mut frame, address, *port);
                }
            }
            let meta = (frame.len() - 2) as u16;
            frame[..2].copy_from_slice(&meta.to_be_bytes());
        }
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        writer.write_all(&frame).await?;
        writer.flush().await?;
        Ok(frame.len())
    }

    /// xudp.PacketReader / LengthPacketReader: the next packet and its wire size.
    pub async fn recv(&self) -> Result<(Packet, usize)> {
        let mut reader = self.reader.lock().await;
        if self.xudp.is_none() {
            let len = reader.read_u16().await? as usize;
            let mut data = vec![0u8; len];
            reader.read_exact(&mut data).await?;
            return Ok((Packet { data, addr: None }, len + 2));
        }
        loop {
            let len = reader.read_u16().await? as usize;
            ensure!(
                (4..=8192).contains(&len),
                "invalid XUDP metadata length: {len}"
            );
            let mut meta = vec![0u8; len];
            reader.read_exact(&mut meta).await?;
            let mut addr = None;
            let discard = match meta[2] {
                2 => {
                    if len > 4 && meta[4] == 2 {
                        let (address, port, _) = crate::mux::read_address_port(&meta[5..])?;
                        addr = Some((address, port));
                    }
                    false
                }
                4 => true,
                _ => bail!("EOF"),
            };
            if meta[3] & 1 == 1 {
                let size = reader.read_u16().await? as usize;
                ensure!(size <= 8192, "invalid XUDP payload length: {size}");
                let mut data = vec![0u8; size];
                reader.read_exact(&mut data).await?;
                if size > 0 && !discard {
                    return Ok((Packet { data, addr }, len + 4 + size));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(flow: &str) -> Server {
        Server {
            address: Address::Domain("example.com".into()),
            port: 443,
            id: [7; 16],
            flow: flow.into(),
            level: 0,
            network: Network::Raw,
            security: Security::None,
        }
    }

    #[test]
    fn request_header_matches_go_encoding() {
        let h = server("").header(CMD_TCP, Some((&Address::Domain("a.b".into()), 80)));
        let mut expected = vec![0];
        expected.extend_from_slice(&[7; 16]);
        expected.extend_from_slice(&[0, 1, 0, 80, 2, 3, b'a', b'.', b'b']);
        assert_eq!(h, expected);
        let h = server("xtls-rprx-vision-udp443").header(CMD_MUX, None);
        assert_eq!(&h[17..19], &[18, 0x0a]);
        assert_eq!(&h[19..20], &[16]);
        assert_eq!(&h[20..36], XRV.as_bytes());
        assert_eq!(h[36], CMD_MUX);
        assert_eq!(h.len(), 37);
    }

    fn tunnel(xudp: bool) -> (UdpTunnel, tokio::io::DuplexStream) {
        let (a, b) = tokio::io::duplex(1 << 17);
        let (reader, writer) = tokio::io::split(Box::new(a) as BoxIo);
        (
            UdpTunnel {
                reader: AsyncMutex::new(reader),
                writer: AsyncMutex::new(writer),
                xudp: xudp.then(|| Xudp {
                    target: (Address::Ip([8, 8, 8, 8].into()), 53),
                    new_sent: AtomicBool::new(false),
                }),
            },
            b,
        )
    }

    #[tokio::test]
    async fn cancelling_a_queued_send_preserves_the_new_frame() {
        let (tunnel, mut peer) = tunnel(true);
        let guard = tunnel.writer.lock().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), tunnel.send(b"cancelled", None))
                .await
                .is_err()
        );
        drop(guard);
        tunnel.send(b"sent", None).await.unwrap();
        let len = peer.read_u16().await.unwrap() as usize;
        let mut meta = vec![0; len];
        peer.read_exact(&mut meta).await.unwrap();
        assert_eq!(meta[2], 1, "first transmitted packet must open the session");
    }

    #[tokio::test]
    async fn plain_udp_drops_empty_and_oversized_packets_like_go() {
        let (tunnel, _peer) = tunnel(false);
        for size in [0, 8191, 65536] {
            assert_eq!(
                tunnel.send(&vec![0; size], None).await.unwrap(),
                0,
                "size {size}"
            );
        }
    }

    #[tokio::test]
    async fn xudp_rejects_oversized_frames_before_reading_the_body() {
        for prefix in [vec![0x20, 1], vec![0, 4, 0, 0, 2, 1, 0x20, 1]] {
            let (tunnel, mut peer) = tunnel(true);
            peer.write_all(&prefix).await.unwrap();
            let result = tokio::time::timeout(Duration::from_millis(50), tunnel.recv()).await;
            assert!(
                matches!(result, Ok(Err(_))),
                "oversized frame must fail without waiting for its body"
            );
        }
    }

    #[tokio::test]
    async fn empty_response_read_does_not_consume_the_header() {
        let (a, _peer) = tokio::io::duplex(16);
        let mut response = Response {
            inner: Box::new(a),
            header: Some(Vec::new()),
        };
        let result = tokio::time::timeout(Duration::from_millis(10), response.read(&mut [])).await;
        assert!(matches!(result, Ok(Ok(0))));
        assert_eq!(response.header.as_deref(), Some(&[][..]));
    }

    #[tokio::test]
    async fn websocket_early_data_counts_and_preserves_remote_dns() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut server = server("");
        server.address = Address::Ip([127, 0, 0, 1].into());
        server.port = listener.local_addr().unwrap().port();
        server.network = Network::Ws {
            path: "/".into(),
            host: "target.test".into(),
            headers: vec![],
            early: 2048,
            heartbeat: 0,
        };
        let dest = Address::Domain("remote-only.invalid".into());
        let header = server.header(CMD_TCP, Some((&dest, 80)));
        let expected = [header.as_slice(), b"first"].concat();
        let count = expected.len();
        let peer = tokio::spawn(async move {
            let (tcp, from) = listener.accept().await.unwrap();
            let (mut io, _) = crate::transport::accept_ws(tcp, from, "/", "target.test", 0, &[])
                .await
                .unwrap();
            let mut got = vec![0; expected.len()];
            io.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected);
            io.write_all(&[0, 2, 0, 0, b'o', b'k']).await.unwrap();
            io.flush().await.unwrap();
        });
        let up = Arc::new(Counter::default());
        let down = Arc::new(Counter::default());
        let mut io = server
            .open_tcp(
                &crate::socket::Options::default(),
                &dest,
                80,
                b"first",
                (Some(up.clone()), Some(down.clone())),
            )
            .await
            .unwrap();
        assert_eq!(
            up.value(),
            count as i64,
            "early payload must count as VLESS uplink"
        );
        let mut reply = [0; 2];
        io.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok");
        assert_eq!(down.value(), 6);
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn xudp_frames_round_trip_through_the_reader() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (ar, aw) = tokio::io::split(Box::new(a) as BoxIo);
        let (br, bw) = tokio::io::split(Box::new(b) as BoxIo);
        let tunnel = |r, w| UdpTunnel {
            reader: AsyncMutex::new(r),
            writer: AsyncMutex::new(w),
            xudp: Some(Xudp {
                target: (Address::Ip([8, 8, 8, 8].into()), 53),
                new_sent: AtomicBool::new(false),
            }),
        };
        let (client, server) = (tunnel(ar, aw), tunnel(br, bw));
        let dest = (Address::Ip([1, 1, 1, 1].into()), 53);
        assert_eq!(client.send(b"", Some(&dest)).await.unwrap(), 0);
        assert_eq!(client.send(&[0; 7600], Some(&dest)).await.unwrap(), 0);
        let first = client.send(b"q1", Some(&dest)).await.unwrap();
        // New frame: id 0, New, Data, UDP, 8.8.8.8:53, zero GlobalID, then the packet.
        assert_eq!(first, 2 + 4 + 1 + 7 + 8 + 2 + 2);
        client.send(b"q2", Some(&dest)).await.unwrap();
        // The peer's reader skips the New frame (status 1 is EOF for a client reader), so
        // feed Keep frames from the "server" side instead.
        server
            .xudp
            .as_ref()
            .unwrap()
            .new_sent
            .store(true, Ordering::Release);
        server.send(b"r1", Some(&dest)).await.unwrap();
        let (packet, _) = client.recv().await.unwrap();
        assert_eq!(
            (packet.data.as_slice(), packet.addr),
            (&b"r1"[..], Some(dest))
        );
    }
}

//! Instance wiring: inbound listeners, dispatcher (sniff + route), outbounds and the relay.
use crate::{
    config::{Config, FinalRule, InboundKind, LevelPolicy, Outbound, OutboundKind},
    dns::Strategy,
    dns_outbound::DnsOutbound,
    geodata::{IpMatcher, private_ips},
    router::Ctx,
    sniff::{Sniff, sniff_tcp},
    stats::{Counter, OnlineGuard, Stats},
    transport::{BoxIo, Transport, accept_httpupgrade, accept_ws},
    vless::{self, Address, Command, Users},
};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context as TaskCx, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
};

static PRIVATE: LazyLock<IpMatcher> = LazyLock::new(private_ips);

/// buf.Size: Go reads at most this much of one datagram.
const BUF_SIZE: usize = 8192;

const HTTP_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nCache-Control: max-age=3600, public\r\nContent-Length: 0\r\n\r\n";

/// What every dispatch of one inbound connection shares (session.Inbound plus user stats).
pub(crate) struct Base {
    pub origin: Origin,
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub email: String,
    pub level: u32,
    pub vless_route: u16,
    pub policy: LevelPolicy,
    pub user_up: Option<Arc<Counter>>,
    pub user_down: Option<Arc<Counter>>,
    pub mux: bool,
    /// session.ID: shown as "[id]" on every log line of this connection.
    pub id: Sid,
}

/// Where a dispatch comes from: an inbound listener, or the core itself (DNS, observatory).
pub(crate) enum Origin {
    Inbound(usize),
    Internal(Internal),
}

/// The session context the core sets on its own dispatches (app/dns toDnsContext, tagged dialer).
pub(crate) struct Internal {
    /// session.Inbound.Tag
    pub tag: String,
    /// session.Content.Protocol
    pub protocol: &'static str,
    /// session.Content.SkipDNSResolve
    pub skip_dns: bool,
    /// session.SetForcedOutboundTagToContext
    pub forced: Option<String>,
    /// log.AccessMessage{From: "DNS", To: ...}
    pub access: Option<String>,
    /// session.TrackedConnectionError: where the outbound's failure is reported.
    pub report: Option<Arc<std::sync::Mutex<Option<String>>>>,
}

/// session.ID as Go prints it: "[id] " before the message, nothing for the core's own traffic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Sid(pub u32);

impl std::fmt::Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.0 == 0 {
            Ok(())
        } else {
            write!(f, "[{}] ", self.0)
        }
    }
}

/// session.NewID: a random non-zero ID per inbound connection.
pub(crate) fn session_id() -> Sid {
    loop {
        let mut b = [0u8; 4];
        let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
        let id = u32::from_le_bytes(b);
        if id != 0 {
            return Sid(id);
        }
    }
}

impl Base {
    fn ctx(&self, tag: &str, udp: bool, port: u16) -> Ctx {
        let internal = match &self.origin {
            Origin::Internal(internal) => Some(internal),
            Origin::Inbound(_) => None,
        };
        Ctx {
            inbound_tag: tag.to_owned(),
            inbound_name: if internal.is_some() { "" } else { "vless" },
            udp,
            source: internal.is_none().then_some(self.peer),
            local: internal.is_none().then_some(self.local),
            domain: None,
            ip: None,
            port,
            protocol: internal.map(|i| i.protocol.to_owned()).unwrap_or_default(),
            user: self.email.clone(),
            level: self.level,
            vless_route: self.vless_route,
            skip_dns: internal.is_some_and(|i| i.skip_dns),
        }
    }

    /// A dispatch the core starts on its own: no source, user or sniffing.
    fn internal(internal: Internal, policy: LevelPolicy) -> Self {
        let none = SocketAddr::from(([0, 0, 0, 0], 0));
        Base {
            origin: Origin::Internal(internal),
            peer: none,
            local: none,
            email: String::new(),
            level: 0,
            vless_route: 0,
            policy,
            user_up: None,
            user_down: None,
            mux: false,
            id: Sid(0),
        }
    }
}

/// internet.DialSystem with no socket options: resolves a domain with the system resolver.
pub(crate) async fn dial_system(dest: &Address, port: u16) -> Result<TcpStream> {
    connect_once(
        &resolve(dest, port).await?,
        &crate::socket::Options::default(),
    )
    .await
}

/// Appends one access-log line as log.AccessMessage records it.
pub(crate) fn write_access(path: &str, line: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = file.write_all(format!("{} {line}\n", crate::log_time()).as_bytes());
    }
}

/// The client side of a byte-stream dispatch: a VLESS connection or a mux TCP sub-session.
pub(crate) struct Stream {
    pub conn: Counted<BoxIo>,
    pub payload: Vec<u8>,
    pub skip: Arc<AtomicUsize>,
    pub header_pending: bool,
    /// Vision's switch over raw TLS/REALITY, for splicing the direct downlink.
    pub vision: Option<crate::tls13::DirectControl>,
}

/// One datagram; `addr` is its destination (uplink) or source (downlink) when it carries one.
pub(crate) struct Packet {
    pub data: Vec<u8>,
    pub addr: Option<(Address, u16)>,
}

/// transport.Link for packets: `up` comes from the client, `down` goes back to it.
pub(crate) struct PacketLink {
    pub up: mpsc::Receiver<Packet>,
    pub down: mpsc::Sender<Packet>,
}

pub struct Instance {
    pub stats: Stats,
    pub config: Config,
    pub users: HashMap<String, Arc<Users>>,
    pub started: Instant,
}

/// Counts bytes read (uplink) and written (downlink) on a connection, like stat.Connection.
pub struct Counted<S> {
    pub inner: S,
    up: Option<Arc<Counter>>,
    down: Option<Arc<Counter>>,
    /// Bytes of upcoming writes that bypass the counter (see `uncounted`).
    skip: Arc<AtomicUsize>,
}

impl<S> Counted<S> {
    pub fn new(inner: S, up: Option<Arc<Counter>>, down: Option<Arc<Counter>>) -> Self {
        Self {
            inner,
            up,
            down,
            skip: Arc::default(),
        }
    }
    /// Go quirk (common/buf BufferedWriter.flushInternal): the VLESS response header and the
    /// first downlink batch are written to the unwrapped conn, so the inbound counter skips them.
    fn uncounted(&self) -> Arc<AtomicUsize> {
        self.skip.clone()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let (Poll::Ready(Ok(())), Some(c)) = (&result, &self.up) {
            c.add((buf.filled().len() - before) as i64);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &result {
            let skipped = self.skip.load(Ordering::Relaxed).min(*n);
            self.skip.fetch_sub(skipped, Ordering::Relaxed);
            if let Some(c) = &self.down {
                c.add((*n - skipped) as i64);
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl tonic::transport::server::Connected for Counted<TcpStream> {
    type ConnectInfo = tonic::transport::server::TcpConnectInfo;
    fn connect_info(&self) -> Self::ConnectInfo {
        self.inner.connect_info()
    }
}

/// signal.ActivityTimer: cancels a session after `timeout` without traffic.
pub(crate) struct Activity {
    start: Instant,
    last: AtomicU64,
    timeout: AtomicU64,
}

impl Activity {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
            timeout: AtomicU64::new(timeout.as_millis() as u64),
        }
    }
    pub(crate) fn touch(&self) {
        self.last
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    fn set_timeout(&self, timeout: Duration) {
        self.timeout
            .store(timeout.as_millis() as u64, Ordering::Relaxed);
        self.touch();
    }
    pub(crate) async fn expired(&self) {
        loop {
            let idle = self.start.elapsed().as_millis() as u64 - self.last.load(Ordering::Relaxed);
            let timeout = self.timeout.load(Ordering::Relaxed);
            if idle >= timeout {
                return;
            }
            tokio::time::sleep(Duration::from_millis((timeout - idle).clamp(10, 1000))).await;
        }
    }
}

/// Go net.Address.String(): IPv6 in brackets, IPv4-mapped shown as IPv4.
fn address_string(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V6(v6) => format!("[{v6}]"),
        v4 => v4.to_string(),
    }
}

impl Instance {
    pub fn new(config: Config) -> Result<Arc<Self>> {
        let stats = Stats::default();
        let mut users = HashMap::new();
        for inbound in &config.inbounds {
            if !inbound.tag.is_empty() && config.stats {
                // app/proxyman/inbound getStatCounter registers counters at startup.
                if config.policy.inbound_uplink {
                    stats.counter(&format!("inbound>>>{}>>>traffic>>>uplink", inbound.tag));
                }
                if config.policy.inbound_downlink {
                    stats.counter(&format!("inbound>>>{}>>>traffic>>>downlink", inbound.tag));
                }
            }
            if let InboundKind::Vless(clients) = &inbound.kind {
                let set = Users::default();
                for user in clients {
                    set.add(user.clone())?;
                }
                users.insert(inbound.tag.clone(), Arc::new(set));
            }
        }
        for outbound in &config.outbounds {
            if !outbound.tag.is_empty() && config.stats {
                if config.policy.outbound_uplink {
                    stats.counter(&format!("outbound>>>{}>>>traffic>>>uplink", outbound.tag));
                }
                if config.policy.outbound_downlink {
                    stats.counter(&format!("outbound>>>{}>>>traffic>>>downlink", outbound.tag));
                }
            }
        }
        for warning in &config.warnings {
            tracing::warn!("{warning}");
        }
        config.dns.log_created();
        Ok(Arc::new(Self {
            stats,
            config,
            users,
            started: Instant::now(),
        }))
    }

    /// Counters exist only with a `stats` object, like Xray's stats feature.
    fn counter(&self, enabled: bool, name: String) -> Option<Arc<Counter>> {
        (enabled && self.config.stats).then(|| self.stats.counter(&name))
    }

    /// Binds every inbound, then serves them until the process exits.
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        self.config.observatory.start(self);
        for (index, inbound) in self.config.inbounds.iter().enumerate() {
            let listener = TcpListener::bind((inbound.listen, inbound.port))
                .await
                .with_context(|| {
                    format!(
                        "failed to listen TCP on {}:{}",
                        inbound.listen, inbound.port
                    )
                })?;
            if let Some(reality) = &inbound.reality {
                reality.profiles.warm(&reality.dest, &reality.server_names);
            }
            if let Some(tls) = &inbound.tls {
                tls.start();
            }
            let me = self.clone();
            match inbound.kind {
                InboundKind::Api => {
                    let incoming = async_incoming(listener, me.clone(), inbound.tag.clone());
                    tokio::spawn(async move {
                        if let Err(error) = crate::api::serve(me, incoming).await {
                            tracing::error!(%error, "API server failed");
                        }
                    });
                }
                InboundKind::Vless(_) if matches!(inbound.transport, Transport::Xhttp(_)) => {
                    tokio::spawn(crate::xhttp::serve(me, index, listener));
                }
                InboundKind::Vless(_) => {
                    tokio::spawn(async move {
                        loop {
                            let Ok((stream, peer)) = listener.accept().await else {
                                continue;
                            };
                            let me = me.clone();
                            tokio::spawn(async move {
                                let id = session_id();
                                if let Err(error) = me.vless_session(index, stream, peer, id).await
                                {
                                    tracing::info!(
                                        "{id}app/proxyman/inbound: connection ends > {error:#}"
                                    );
                                }
                            });
                        }
                    });
                }
            }
        }
        Ok(())
    }

    async fn vless_session(
        self: Arc<Self>,
        index: usize,
        stream: TcpStream,
        peer: SocketAddr,
        id: Sid,
    ) -> Result<()> {
        let inbound = &self.config.inbounds[index];
        let local = stream.local_addr()?;
        stream.set_nodelay(true).ok();
        let handshake = self.config.policy.level(0).handshake;
        // (stream, client address, Vision's switch, outer TLS version when VLESS runs on it).
        type Accepted = (
            BoxIo,
            SocketAddr,
            Option<crate::tls13::DirectControl>,
            Option<u16>,
        );
        let accepted: Result<Accepted> = async {
            if let Some(tls) = &inbound.tls {
                let http_hub = !matches!(inbound.transport, Transport::Raw);
                let tls = tokio::time::timeout(handshake, tls.accept(stream, http_hub))
                    .await
                    .context("tls: handshake timeout")??;
                return Ok(match &inbound.transport {
                    Transport::Raw => (tls.io, peer, tls.direct, Some(tls.version)),
                    Transport::Ws {
                        path,
                        host,
                        heartbeat,
                    } => {
                        let (io, peer) =
                            accept_ws(tls.io, peer, path, host, *heartbeat, &inbound.trusted_xff)
                                .await?;
                        (io, peer, None, None)
                    }
                    Transport::HttpUpgrade { path, host } => {
                        let (io, peer) =
                            accept_httpupgrade(tls.io, peer, path, host, &inbound.trusted_xff)
                                .await?;
                        (io, peer, None, None)
                    }
                    Transport::Xhttp(_) => bail!("XHTTP connections are served by xhttp::serve"),
                });
            }
            Ok(match &inbound.transport {
                Transport::Raw => match &inbound.reality {
                    Some(reality) => {
                        let (io, direct) =
                            crate::reality::accept(reality, stream, handshake).await?;
                        (io, peer, Some(direct), Some(0x0304))
                    }
                    None => (Box::new(stream) as BoxIo, peer, None, None),
                },
                Transport::Ws {
                    path,
                    host,
                    heartbeat,
                } => {
                    let (io, peer) =
                        accept_ws(stream, peer, path, host, *heartbeat, &inbound.trusted_xff)
                            .await?;
                    (io, peer, None, None)
                }
                Transport::HttpUpgrade { path, host } => {
                    let (io, peer) =
                        accept_httpupgrade(stream, peer, path, host, &inbound.trusted_xff).await?;
                    (io, peer, None, None)
                }
                Transport::Xhttp(_) => bail!("XHTTP connections are served by xhttp::serve"),
            })
        }
        .await;
        let (io, peer, direct, outer_tls) = match accepted {
            Ok(accepted) => accepted,
            // Go's lazy handshake fails VLESS's first read, so the session ends with its ID; a
            // connection closed before any byte stays quiet, like an empty VLESS request.
            Err(error) if inbound.tls.is_some() && matches!(inbound.transport, Transport::Raw) => {
                if error.is::<vless::EmptyRequest>() {
                    return Ok(());
                }
                return Err(error);
            }
            Err(error) => {
                // Transport hubs reject before a session exists, so Go logs them without an ID.
                let hub = match &inbound.transport {
                    Transport::Ws { .. } => "transport/internet/websocket",
                    Transport::HttpUpgrade { .. } => "transport/internet/httpupgrade",
                    _ => "transport/internet/tcp",
                };
                tracing::info!("{hub}: {error:#}");
                return Ok(());
            }
        };
        self.vless_conn(index, io, peer, local, direct, outer_tls, id)
            .await
    }

    /// A VLESS connection over an established transport (raw/REALITY, WS, HTTPUpgrade, XHTTP).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn vless_conn(
        self: Arc<Self>,
        index: usize,
        io: BoxIo,
        peer: SocketAddr,
        local: SocketAddr,
        direct: Option<crate::tls13::DirectControl>,
        outer_tls: Option<u16>,
        id: Sid,
    ) -> Result<()> {
        let inbound = &self.config.inbounds[index];
        let tag = &inbound.tag;
        // The inbound counters wrap whatever the transport hands over (WS payload, not frames).
        let mut conn = Counted::new(
            io,
            self.counter(
                self.config.policy.inbound_uplink && !tag.is_empty(),
                format!("inbound>>>{tag}>>>traffic>>>uplink"),
            ),
            self.counter(
                self.config.policy.inbound_downlink && !tag.is_empty(),
                format!("inbound>>>{tag}>>>traffic>>>downlink"),
            ),
        );
        let users = self
            .users
            .get(tag)
            .context("inbound without users")?
            .clone();
        let handshake = self.config.policy.level(0).handshake;
        let read = async {
            // Go reads once into `first` and logs its length before decoding the header.
            let mut first = vec![0u8; 8192];
            let n = conn.read(&mut first).await?;
            if n == 0 {
                return Err(vless::EmptyRequest.into());
            }
            tracing::info!("{id}proxy/vless/inbound: firstLen = {n}");
            first.truncate(n);
            let mut reader = crate::transport::Prefixed {
                prefix: first,
                pos: 0,
                inner: &mut conn,
            };
            vless::read_request(&mut reader, &users).await
        };
        let (request, mut payload) = match tokio::time::timeout(handshake, read)
            .await
            .context("handshake timeout")?
        {
            Ok(request) => request,
            Err(error) if error.is::<vless::EmptyRequest>() => return Ok(()),
            Err(error) => return Err(error.context(format!("invalid request from {peer}"))),
        };
        vless::check_flow(&request, outer_tls, &payload)?;
        let mut vision = None;
        if request.flow == vless::XRV {
            let control = direct.context("XTLS only supports TLS and REALITY directly for now.")?;
            let (io, decoded) =
                crate::vision::wrap(conn.inner, &payload, request.sent_id, control.clone())?;
            vision = Some(control);
            conn.inner = io;
            payload = decoded;
        }
        let user = request.user.clone();
        tracing::info!(
            "{id}proxy/vless/inbound: received request for {}:{}:{}",
            if request.command == Command::Udp {
                "udp"
            } else {
                "tcp"
            },
            request.address,
            request.port
        );
        if request.command == Command::Rvs {
            // Reverse proxies need a user `reverse` setting, which rcore does not accept.
            bail!(
                "reverse: user {} is not allowed to create reverse proxy",
                vless::uuid_string(user.id)
            );
        }
        let policy = self.config.policy.level(user.level);
        let email = user.email.clone();
        let _online = (policy.user_online && !email.is_empty())
            .then(|| OnlineGuard::new(&self.stats, &email, address_string(peer.ip())));
        let base = Base {
            id,
            origin: Origin::Inbound(index),
            peer,
            local,
            user_up: self.counter(
                policy.user_uplink && !email.is_empty(),
                format!("user>>>{email}>>>traffic>>>uplink"),
            ),
            user_down: self.counter(
                policy.user_downlink && !email.is_empty(),
                format!("user>>>{email}>>>traffic>>>downlink"),
            ),
            email,
            level: user.level,
            vless_route: u16::from_be_bytes([request.sent_id[6], request.sent_id[7]]),
            policy,
            mux: request.command == Command::Mux,
        };
        // Measured against Go: only raw TCP leaves the first downlink write uncounted.
        let skip = if matches!(inbound.transport, Transport::Raw) {
            conn.uncounted()
        } else {
            Arc::default()
        };
        if base.mux {
            // A Vision account may only carry UDP (XUDP) inside mux (session.ContextWithAllowedNetwork).
            let udp_only = user.flow == vless::XRV;
            return crate::mux::serve(self.clone(), base, conn, payload, skip, udp_only).await;
        }
        let stream = Stream {
            conn,
            payload,
            skip,
            header_pending: true,
            vision,
        };
        let udp = request.command == Command::Udp;
        self.dispatch_stream(&base, stream, udp, request.address, request.port)
            .await
    }

    /// The dispatcher for one byte stream: sniffing, routing, then the outbound.
    pub(crate) async fn dispatch_stream(
        self: &Arc<Self>,
        base: &Base,
        stream: Stream,
        udp: bool,
        address: Address,
        port: u16,
    ) -> Result<()> {
        let Stream {
            mut conn,
            mut payload,
            skip,
            header_pending,
            vision,
        } = stream;
        let (tag, sniffing) = self.origin(base);
        let mut dest = address.clone();
        let mut route_domain = match &dest {
            Address::Domain(d) => Some(d.clone()),
            Address::Ip(_) => None,
        };
        let mut protocol = base.ctx(tag, udp, port).protocol;
        let route_only = sniffing.is_some_and(|s| s.route_only);
        // Go counts user uplink when the dispatcher reads the client; sniffing reads the first payload.
        let sniffed = sniffing.is_some_and(|s| s.enabled && !s.metadata_only) && !udp;
        if sniffed
            && let Some(sniffing) = sniffing
            && let Some((p, domain)) = sniff_first(&mut conn, &mut payload).await
        {
            protocol = p.to_owned();
            let overrides = !domain.is_empty()
                && !sniffing.domains_excluded.matches(&domain)
                && sniffing
                    .dest_override
                    .iter()
                    .any(|o| p.starts_with(o.as_str()) || o.starts_with(p));
            if overrides {
                tracing::info!("{}app/dispatcher: sniffed domain: {domain}", base.id);
                route_domain = Some(domain.clone());
                if !sniffing.route_only {
                    dest = Address::Domain(domain);
                }
            }
        }
        let ctx = Ctx {
            domain: route_domain,
            ip: match &dest {
                Address::Ip(ip) => Some(*ip),
                Address::Domain(_) => match &address {
                    Address::Ip(ip) if route_only => Some(*ip),
                    _ => None,
                },
            },
            protocol,
            ..base.ctx(tag, udp, port)
        };
        let destination = format!("{}:{dest}:{port}", if ctx.udp { "udp" } else { "tcp" });
        let Some((outbound, routed)) = self.route(&ctx, base, &destination).await? else {
            return Ok(());
        };
        self.access(base, &ctx, &dest, &outbound.tag, routed);
        let (out_up, out_down) = self.outbound_counters(&outbound.tag);
        if sniffed && let Some(c) = &base.user_up {
            c.add(payload.len() as i64);
        }
        let policy = &base.policy;
        let client = Client {
            skip,
            conn,
            payload,
            payload_counted: sniffed,
            user_up: base.user_up.clone(),
            user_down: base.user_down.clone(),
            header_pending,
            vision,
            id: base.id,
        };
        match &outbound.kind {
            OutboundKind::Blackhole { http } => client.blackhole(*http, udp).await,
            OutboundKind::Socks(server) => {
                let counters = (out_up.clone(), out_down.clone());
                let (remote, relay) = socks_connect(
                    outbound,
                    server,
                    &dest,
                    port,
                    udp,
                    policy.handshake,
                    counters,
                )
                .await?;
                match relay {
                    Some(socket) => {
                        let socket = Datagram::Socket {
                            socket,
                            socks: Some((dest, port)),
                        };
                        let mut remote = remote;
                        let mut closed = [0u8; 1];
                        tokio::select! {
                            result = client.relay_udp(socket, policy, out_up, out_down) => result,
                            _ = remote.read(&mut closed) => Ok(()),
                        }
                    }
                    None => client.relay_tcp(remote, policy, None).await,
                }
            }
            OutboundKind::Freedom {
                final_rules,
                strategy,
            } => {
                let target = self
                    .freedom_target(&dest, port, udp, final_rules, *strategy, base.id)
                    .await?;
                match target {
                    Target::Blocked(rule_delay, shown) => {
                        let delay = block_delay(rule_delay, &shown, udp, base.id);
                        client.drain_for(delay).await
                    }
                    Target::Dial(addrs, resolved) if udp => {
                        let addrs = self
                            .dial_addrs(&dest, port, addrs, resolved, "udp", base.id)
                            .await?;
                        let addr = *addrs.first().context("failed to resolve destination")?;
                        let socket = udp_connect(addr, &outbound.socket).await?;
                        tracing::info!(
                            "{}proxy/freedom: connection opened to udp:{dest}:{port}, local endpoint {}, remote endpoint {addr}",
                            base.id,
                            socket.local_addr()?
                        );
                        client
                            .relay_udp(
                                Datagram::Socket {
                                    socket,
                                    socks: None,
                                },
                                policy,
                                out_up,
                                out_down,
                            )
                            .await
                    }
                    Target::Dial(addrs, resolved) => {
                        tracing::info!(
                            "{}transport/internet/tcp: dialing TCP to tcp:{dest}:{port}",
                            base.id
                        );
                        let addrs = self
                            .dial_addrs(&dest, port, addrs, resolved, "tcp", base.id)
                            .await?;
                        let remote = connect(&addrs, &outbound.socket).await?;
                        if let Address::Domain(_) = dest
                            && let Some((delay, shown)) =
                                blocked(remote.peer_addr()?, udp, final_rules)
                        {
                            drop(remote);
                            let delay = block_delay(delay, &shown, udp, base.id);
                            return client.drain_for(delay).await;
                        }
                        tracing::info!(
                            "{}proxy/freedom: connection opened to tcp:{dest}:{port}, local endpoint {}, remote endpoint {}",
                            base.id,
                            remote.local_addr()?,
                            remote.peer_addr()?
                        );
                        remote.set_nodelay(true).ok();
                        let remote = Arc::new(remote);
                        let shared = crate::transport::SharedTcp(remote.clone());
                        client
                            .relay_tcp(
                                Counted::new(shared, out_down.clone(), out_up),
                                policy,
                                Some((remote, out_down)),
                            )
                            .await
                    }
                }
            }
            OutboundKind::Dns(dns) => {
                let own = self.config.dns.is_own_link(&ctx.inbound_tag);
                client
                    .dns(self, outbound, dns, base.id, own, udp, &dest, port)
                    .await
            }
            OutboundKind::Vless(server) => {
                // The VLESS outbound runs on its own user's policy.
                let policy = self.config.policy.level(server.level);
                let counters = (out_up, out_down);
                if udp {
                    tracing::info!(
                        "{}proxy/vless/outbound: tunneling request to udp:{dest}:{port} via {}:{}",
                        base.id,
                        server.address,
                        server.port
                    );
                    let tunnel = tokio::time::timeout(
                        policy.handshake,
                        server.open_udp(&outbound.socket, &dest, port, counters),
                    )
                    .await
                    .context("VLESS outbound handshake timeout")??;
                    return client
                        .relay_udp(Datagram::Vless(tunnel), &policy, None, None)
                        .await;
                }
                let mut client = client;
                let mut first = std::mem::take(&mut client.payload);
                if !client.payload_counted
                    && let Some(c) = &client.user_up
                {
                    c.add(first.len() as i64);
                }
                if first.is_empty() {
                    // postRequest: wait up to 500 ms to send the first payload with the header.
                    let mut buf = vec![0u8; 8192];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_millis(500), client.conn.read(&mut buf))
                            .await
                    {
                        first.extend_from_slice(&buf[..n]);
                        if let Some(c) = &client.user_up {
                            c.add(n as i64);
                        }
                    }
                }
                tracing::info!(
                    "{}proxy/vless/outbound: tunneling request to tcp:{dest}:{port} via {}:{}",
                    base.id,
                    server.address,
                    server.port
                );
                let remote = tokio::time::timeout(
                    policy.handshake,
                    server.open_tcp(&outbound.socket, &dest, port, &first, counters),
                )
                .await
                .context("VLESS outbound handshake timeout")??;
                client.relay_tcp(remote, &policy, None).await
            }
        }
    }

    /// The dispatcher for a mux UDP sub-session, whose packets may each name a destination.
    pub(crate) async fn dispatch_packets(
        self: &Arc<Self>,
        base: &Base,
        dest: Address,
        port: u16,
        link: PacketLink,
    ) -> Result<()> {
        let (tag, _) = self.origin(base);
        let ctx = Ctx {
            domain: match &dest {
                Address::Domain(d) => Some(d.clone()),
                Address::Ip(_) => None,
            },
            ip: match &dest {
                Address::Ip(ip) => Some(*ip),
                Address::Domain(_) => None,
            },
            ..base.ctx(tag, true, port)
        };
        let destination = format!("{}:{dest}:{port}", if ctx.udp { "udp" } else { "tcp" });
        let Some((outbound, routed)) = self.route(&ctx, base, &destination).await? else {
            return Ok(());
        };
        self.access(base, &ctx, &dest, &outbound.tag, routed);
        let (out_up, out_down) = self.outbound_counters(&outbound.tag);
        match &outbound.kind {
            OutboundKind::Blackhole { http } => link.blackhole(*http, base).await,
            OutboundKind::Socks(server) => {
                let counters = (out_up.clone(), out_down.clone());
                let handshake = base.policy.handshake;
                let (mut remote, relay) =
                    socks_connect(outbound, server, &dest, port, true, handshake, counters).await?;
                let socket = relay.context("SOCKS server returned no UDP relay")?;
                let out = PacketOut::Socks { socket, dest, port };
                let mut closed = [0u8; 1];
                tokio::select! {
                    result = relay_packets(self, link, out, base, out_up, out_down) => result,
                    _ = remote.read(&mut closed) => Ok(()),
                }
            }
            OutboundKind::Freedom {
                final_rules,
                strategy,
            } => match self
                .freedom_target(&dest, port, true, final_rules, *strategy, base.id)
                .await?
            {
                Target::Blocked(rule_delay, shown) => {
                    link.drain_for(block_delay(rule_delay, &shown, true, base.id), base)
                        .await
                }
                Target::Dial(addrs, resolved) => {
                    let addrs = self
                        .dial_addrs(&dest, port, addrs, resolved, "udp", base.id)
                        .await?;
                    let default = *addrs.first().context("failed to resolve destination")?;
                    let socket = udp_bind(&outbound.socket).await?;
                    tracing::info!(
                        "{}proxy/freedom: connection opened to udp:{dest}:{port}, local endpoint {}, remote endpoint {default}",
                        base.id,
                        socket.local_addr()?
                    );
                    let out = PacketOut::Freedom {
                        v6: socket.local_addr()?.is_ipv6(),
                        socket,
                        default,
                        original: dest,
                        rules: final_rules,
                        strategy: *strategy,
                    };
                    relay_packets(self, link, out, base, out_up, out_down).await
                }
            },
            OutboundKind::Dns(dns) => {
                let own = self.config.dns.is_own_link(&ctx.inbound_tag);
                link.dns(self, outbound, dns, base, own, &dest, port).await
            }
            OutboundKind::Vless(server) => {
                let handshake = self.config.policy.level(server.level).handshake;
                tracing::info!(
                    "{}proxy/vless/outbound: tunneling request to udp:{dest}:{port} via {}:{}",
                    base.id,
                    server.address,
                    server.port
                );
                let tunnel = tokio::time::timeout(
                    handshake,
                    server.open_udp(&outbound.socket, &dest, port, (out_up, out_down)),
                )
                .await
                .context("VLESS outbound handshake timeout")??;
                relay_packets(self, link, PacketOut::Vless(tunnel), base, None, None).await
            }
        }
    }

    /// The inbound tag and sniffing settings of a dispatch (none for the core's own traffic).
    fn origin<'a>(&'a self, base: &'a Base) -> (&'a str, Option<&'a crate::config::Sniffing>) {
        match &base.origin {
            Origin::Inbound(i) => (
                &self.config.inbounds[*i].tag,
                Some(&self.config.inbounds[*i].sniffing),
            ),
            Origin::Internal(internal) => (&internal.tag, None),
        }
    }

    /// The core's own byte stream through routing and an outbound (cnc over a dispatched link).
    pub(crate) fn dial_internal(
        self: &Arc<Self>,
        internal: Internal,
        dest: Address,
        port: u16,
    ) -> BoxIo {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let me = self.clone();
        let report = internal.report.clone();
        tokio::spawn(async move {
            let base = Base::internal(internal, me.config.policy.level(0));
            let stream = Stream {
                conn: Counted::new(Box::new(theirs) as BoxIo, None, None),
                payload: Vec::new(),
                skip: Arc::default(),
                header_pending: false,
                vision: None,
            };
            if let Err(error) = me.dispatch_stream(&base, stream, false, dest, port).await {
                let error = format!(
                    "app/proxyman/outbound: failed to process outbound traffic > {error:#}"
                );
                if let Some(report) = report {
                    *report.lock().unwrap() = Some(error.clone());
                }
                tracing::info!("{error}");
            }
        });
        Box::new(ours)
    }

    /// The core's own packet link through routing and an outbound (udp.Dispatcher's link).
    pub(crate) fn packets_internal(
        self: &Arc<Self>,
        internal: Internal,
        dest: Address,
        port: u16,
    ) -> (mpsc::Sender<Packet>, mpsc::Receiver<Packet>) {
        let (up_tx, up) = mpsc::channel(64);
        let (down, down_rx) = mpsc::channel(64);
        let me = self.clone();
        tokio::spawn(async move {
            let base = Base::internal(internal, me.config.policy.level(0));
            let link = PacketLink { up, down };
            if let Err(error) = me.dispatch_packets(&base, dest, port, link).await {
                tracing::info!(
                    "app/proxyman/outbound: failed to process outbound traffic > {error:#}"
                );
            }
        });
        (up_tx, down_rx)
    }

    /// routedDispatch: the outbound and how it was chosen; `None` when the chosen tag is missing.
    async fn route(
        self: &Arc<Self>,
        ctx: &Ctx,
        base: &Base,
        destination: &str,
    ) -> Result<Option<(&Outbound, Detour)>> {
        let id = base.id;
        let find = |tag: &str| self.config.outbounds.iter().find(|o| o.tag == tag);
        if let Origin::Internal(Internal {
            forced: Some(tag), ..
        }) = &base.origin
        {
            return Ok(match find(tag) {
                Some(o) => {
                    tracing::info!(
                        "{id}app/dispatcher: taking platform initialized detour [{tag}] for [{destination}]"
                    );
                    Some((o, Detour::Forced))
                }
                None => {
                    tracing::error!(
                        "{id}app/dispatcher: non existing tag for platform initialized detour: {tag}"
                    );
                    None
                }
            });
        }
        match self.config.router.pick(ctx, self).await {
            Ok(Some((rule, tag))) => match find(&tag) {
                Some(o) => {
                    if rule.tag.is_empty() {
                        tracing::info!(
                            "{id}app/dispatcher: taking detour [{tag}] for [{destination}]"
                        );
                    } else {
                        tracing::info!(
                            "{id}app/dispatcher: Hit route rule: [{}] so taking detour [{tag}] for [{destination}]",
                            rule.tag
                        );
                    }
                    return Ok(Some((o, Detour::Rule)));
                }
                None => {
                    // DO NOT CHANGE (Go): a missing tag must not fall back to the default outbound.
                    tracing::warn!("{id}app/dispatcher: non existing outTag: {tag}");
                    return Ok(None);
                }
            },
            Ok(None) => {}
            Err(error) => {
                tracing::error!(
                    "{id}app/dispatcher: failed to pick route for {destination} > {error:#}"
                );
            }
        }
        tracing::info!("{id}app/dispatcher: default route for {destination}");
        let default = self.config.outbounds.first();
        Ok(Some((
            default.context("default outbound handler not exist")?,
            Detour::Default,
        )))
    }

    fn outbound_counters(&self, tag: &str) -> (Option<Arc<Counter>>, Option<Arc<Counter>>) {
        (
            self.counter(
                self.config.policy.outbound_uplink && !tag.is_empty(),
                format!("outbound>>>{tag}>>>traffic>>>uplink"),
            ),
            self.counter(
                self.config.policy.outbound_downlink && !tag.is_empty(),
                format!("outbound>>>{tag}>>>traffic>>>downlink"),
            ),
        )
    }

    /// log.AccessMessage as the dispatcher records it.
    fn access(&self, base: &Base, ctx: &Ctx, dest: &Address, outbound: &str, detour: Detour) {
        let Some(path) = &self.config.access_log else {
            return;
        };
        let mut line = match (&base.origin, ctx.source) {
            (
                Origin::Internal(Internal {
                    access: Some(to), ..
                }),
                _,
            ) => {
                format!("from DNS accepted {to}")
            }
            // Only the DNS module puts an access message in its context.
            (Origin::Internal(_), _) | (_, None) => return,
            (Origin::Inbound(_), Some(source)) => format!(
                "from {}{source} accepted {}:{dest}:{}",
                // Mux sub-sessions log the inbound source as a net.Destination.
                if base.mux { "tcp:" } else { "" },
                if ctx.udp { "udp" } else { "tcp" },
                ctx.port,
            ),
        };
        let inbound = &ctx.inbound_tag;
        match (inbound.is_empty(), outbound.is_empty(), detour) {
            (_, true, _) => {}
            (true, false, _) => line += &format!(" [{outbound}]"),
            (false, false, Detour::Forced) => line += &format!(" [{inbound} ==> {outbound}]"),
            (false, false, Detour::Rule) => line += &format!(" [{inbound} -> {outbound}]"),
            (false, false, Detour::Default) => line += &format!(" [{inbound} >> {outbound}]"),
        }
        if !ctx.user.is_empty() {
            line += &format!(" email: {}", ctx.user);
        }
        write_access(path, &line);
    }
}

/// How routedDispatch chose the outbound (isPickRoute).
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Detour {
    Default,
    Forced,
    Rule,
}

fn async_incoming(
    listener: TcpListener,
    me: Arc<Instance>,
    tag: String,
) -> impl tokio_stream::Stream<Item = io::Result<Counted<TcpStream>>> + Send + 'static {
    use tokio_stream::StreamExt;
    tokio_stream::wrappers::TcpListenerStream::new(listener).map(move |accepted| {
        accepted.map(|stream| {
            Counted::new(
                stream,
                me.counter(
                    me.config.policy.inbound_uplink && !tag.is_empty(),
                    format!("inbound>>>{tag}>>>traffic>>>uplink"),
                ),
                me.counter(
                    me.config.policy.inbound_downlink && !tag.is_empty(),
                    format!("inbound>>>{tag}>>>traffic>>>downlink"),
                ),
            )
        })
    })
}

/// Dispatcher sniffing loop: up to 200ms and two no-clue attempts on the first payload.
async fn sniff_first<S: AsyncRead + Unpin>(
    conn: &mut S,
    payload: &mut Vec<u8>,
) -> Option<(&'static str, String)> {
    let deadline = Instant::now() + Duration::from_millis(200);
    let mut attempts = 0;
    loop {
        if !payload.is_empty() {
            match sniff_tcp(payload) {
                Sniff::Found(p, d) => return Some((p, d)),
                Sniff::NotMatched => return None,
                Sniff::NeedMore => attempts += 1,
            }
        } else {
            attempts += 1;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if attempts >= 2 || remaining.is_zero() {
            return None;
        }
        let mut chunk = [0u8; 8192];
        match tokio::time::timeout(remaining, conn.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => payload.extend_from_slice(&chunk[..n]),
            Ok(_) => return None,
            Err(_) => attempts += 1,
        }
    }
}

enum Target {
    /// Addresses to dial, and what DialSystem logs about the domain strategy first.
    Dial(Vec<SocketAddr>, Resolved),
    Blocked((u64, u64), String),
}

/// How DialSystem treats a domain target: dial what was resolved, or resolve again through the
/// DNS module with sockopt.domainStrategy (freedom.domainStrategy) and dial one random IP.
#[derive(Clone, Copy)]
enum Resolved {
    Plain,
    Strategy(Strategy),
}

fn rule_matches(rule: &FinalRule, ip: IpAddr, port: u16, udp: bool) -> bool {
    (if udp { rule.udp } else { rule.tcp })
        && (rule.ports.is_empty() || rule.ports.iter().any(|(a, b)| (*a..=*b).contains(&port)))
        && rule.ips.as_ref().is_none_or(|m| m.matches(ip))
}

/// matchFinalRule with the VLESS default rule (block private/reserved IPs).
fn blocked(addr: SocketAddr, udp: bool, rules: &[FinalRule]) -> Option<((u64, u64), String)> {
    if let Some(rule) = rules
        .iter()
        .find(|r| rule_matches(r, addr.ip(), addr.port(), udp))
    {
        return rule.block.then(|| (rule.delay, addr.to_string()));
    }
    PRIVATE
        .matches(addr.ip())
        .then(|| ((30, 90), addr.to_string()))
}

fn block_delay((min, max): (u64, u64), shown: &str, udp: bool, id: Sid) -> Duration {
    let delay = min + rand_below(max.saturating_sub(min) + 1);
    // FinalRule.log defaults to Info.
    tracing::info!(
        "{id}proxy/freedom: target blocked by a finalrule: {}:{shown}, blackholing connection for {delay}s",
        if udp { "udp" } else { "tcp" }
    );
    Duration::from_secs(delay)
}

impl Instance {
    /// freedom Process before dialing: final rules over the resolved IPs, with
    /// sockopt.domainStrategy (freedom.domainStrategy) resolving through the DNS module.
    async fn freedom_target(
        self: &Arc<Self>,
        dest: &Address,
        port: u16,
        udp: bool,
        rules: &[FinalRule],
        strategy: Strategy,
        id: Sid,
    ) -> Result<Target> {
        let domain = match dest {
            Address::Ip(ip) => {
                let addr = SocketAddr::new(*ip, port);
                return Ok(match blocked(addr, udp, rules) {
                    Some((delay, shown)) => Target::Blocked(delay, shown),
                    None => Target::Dial(vec![addr], Resolved::Plain),
                });
            }
            Address::Domain(domain) => domain,
        };
        let system = async || -> Vec<SocketAddr> {
            match tokio::net::lookup_host((domain.as_str(), port)).await {
                Ok(addrs) => addrs.collect(),
                Err(error) => {
                    tracing::info!(
                        "{id}proxy/freedom: failed to get IP address for domain {domain} > {error}"
                    );
                    Vec::new()
                }
            }
        };
        if !strategy.has_strategy() {
            let addrs = system().await;
            for addr in &addrs {
                if let Some((delay, shown)) = blocked(*addr, udp, rules) {
                    return Ok(Target::Blocked(delay, shown));
                }
            }
            return Ok(Target::Dial(addrs, Resolved::Plain));
        }
        // retry.ExponentialBackoff(5, 100) around the lookup, as Go retries a ForceIP failure.
        let mut last = None;
        for attempt in 0..5u64 {
            match self.config.dns.lookup_for_ip(self, domain, strategy).await {
                Ok(ips) => {
                    for ip in &ips {
                        if let Some((delay, shown)) =
                            blocked(SocketAddr::new(*ip, port), udp, rules)
                        {
                            return Ok(Target::Blocked(delay, shown));
                        }
                    }
                    return Ok(Target::Dial(Vec::new(), Resolved::Strategy(strategy)));
                }
                Err(error) => {
                    tracing::info!(
                        "{id}proxy/freedom: failed to get IP address for domain {domain} > {error}"
                    );
                    if !strategy.force() {
                        return Ok(Target::Dial(Vec::new(), Resolved::Strategy(strategy)));
                    }
                    last = Some(error);
                }
            }
            tokio::time::sleep(Duration::from_millis(100 * attempt)).await;
        }
        bail!(
            "proxy/freedom: failed to open connection to {}:{dest}:{port} > {}",
            if udp { "udp" } else { "tcp" },
            last.map(|e| e.to_string()).unwrap_or_default()
        )
    }

    /// DialSystem: with a domain strategy, a random IP from the DNS module ("replace
    /// destination"), falling back to the system resolver unless the strategy forces IPs.
    async fn dial_addrs(
        self: &Arc<Self>,
        dest: &Address,
        port: u16,
        addrs: Vec<SocketAddr>,
        resolved: Resolved,
        net: &str,
        id: Sid,
    ) -> Result<Vec<SocketAddr>> {
        let (Resolved::Strategy(strategy), Address::Domain(domain)) = (resolved, dest) else {
            tracing::debug!("{id}transport/internet: dialing to {net}:{dest}:{port}");
            return Ok(addrs);
        };
        match self.config.dns.lookup_for_ip(self, domain, strategy).await {
            Ok(ips) => {
                let addr = SocketAddr::new(ips[crate::dns::roll(ips.len())], port);
                tracing::info!("{id}transport/internet: replace destination with {net}:{addr}");
                tracing::debug!("{id}transport/internet: dialing to {net}:{addr}");
                Ok(vec![addr])
            }
            Err(error) => {
                tracing::error!("{id}transport/internet: failed to resolve ip > {error}");
                if strategy.force() {
                    bail!("transport/internet: failed to resolve ip > {error}");
                }
                tracing::debug!("{id}transport/internet: dialing to {net}:{dest}:{port}");
                Ok(resolve(dest, port).await.unwrap_or_default())
            }
        }
    }

    /// freedom PacketWriter resolution of a per-packet domain: a random IP from the domain
    /// strategy (ForceIP* drops the packet without one), else the system resolver's IPv4 first.
    async fn resolve_packet(
        self: &Arc<Self>,
        domain: &str,
        port: u16,
        strategy: Strategy,
    ) -> Option<IpAddr> {
        if strategy.has_strategy() {
            match self.config.dns.lookup_for_ip(self, domain, strategy).await {
                Ok(ips) => return Some(ips[crate::dns::roll(ips.len())]),
                Err(_) if strategy.force() => return None,
                Err(_) => {}
            }
        }
        let all: Vec<SocketAddr> = tokio::net::lookup_host((domain, port))
            .await
            .map(|a| a.collect())
            .unwrap_or_default();
        all.iter()
            .find(|a| a.is_ipv4())
            .or(all.first())
            .map(SocketAddr::ip)
    }
}

/// Go dials UDP by listening on "udp" with a wildcard address: dual-stack where IPv6 exists
/// (relies on the default net.ipv6.bindv6only=0).
async fn udp_bind(options: &crate::socket::Options) -> Result<UdpSocket> {
    let socket = match UdpSocket::bind("[::]:0").await {
        Ok(socket) => socket,
        Err(_) => UdpSocket::bind("0.0.0.0:0").await?,
    };
    options.apply(&socket, false)?;
    Ok(socket)
}

/// Connects to a SOCKS5 server and runs CONNECT or UDP ASSOCIATE; returns the control
/// connection and, for UDP, a socket connected to the relay.
async fn socks_connect(
    outbound: &Outbound,
    server: &crate::socks::Server,
    dest: &Address,
    port: u16,
    udp: bool,
    handshake: Duration,
    (out_up, out_down): (Option<Arc<Counter>>, Option<Arc<Counter>>),
) -> Result<(Counted<TcpStream>, Option<UdpSocket>)> {
    let addrs: Vec<_> = tokio::net::lookup_host((server.address.as_str(), server.port))
        .await?
        .collect();
    let remote = connect(&addrs, &outbound.socket).await?;
    remote.set_nodelay(true).ok();
    let mut remote = Counted::new(remote, out_down, out_up);
    let (mut relay, relay_port) = tokio::time::timeout(
        handshake,
        crate::socks::handshake(&mut remote, server, dest, port, udp),
    )
    .await
    .context("SOCKS handshake timeout")??;
    if !udp {
        return Ok((remote, None));
    }
    if matches!(relay, Address::Ip(ip) if ip.is_unspecified()) {
        relay = Address::Ip(remote.inner.peer_addr()?.ip());
    }
    let relay = resolve(&relay, relay_port)
        .await?
        .into_iter()
        .next()
        .context("failed to resolve SOCKS UDP relay")?;
    let socket = udp_connect(relay, &outbound.socket).await?;
    Ok((remote, Some(socket)))
}

enum PacketOut<'a> {
    Freedom {
        socket: UdpSocket,
        v6: bool,
        default: SocketAddr,
        original: Address,
        rules: &'a [FinalRule],
        strategy: Strategy,
    },
    Socks {
        socket: UdpSocket,
        dest: Address,
        port: u16,
    },
    Vless(crate::vless_out::UdpTunnel),
}

impl PacketOut<'_> {
    /// Sends one packet to its own destination or the session's; returns the bytes counted by
    /// the outbound (0 for packets the final rules or resolution drop).
    async fn send(
        &self,
        inst: &Arc<Instance>,
        packet: Packet,
        resolved: &mut HashMap<String, IpAddr>,
    ) -> Result<usize> {
        match self {
            PacketOut::Freedom {
                socket,
                v6,
                default,
                rules,
                strategy,
                ..
            } => {
                let target = match packet.addr {
                    None => *default,
                    Some((address, port)) => {
                        let ip = match address {
                            Address::Ip(ip) => ip,
                            // Cached so a multi-IP domain keeps one peer.
                            Address::Domain(domain) => match resolved.get(&domain) {
                                Some(ip) => *ip,
                                None => {
                                    let Some(ip) =
                                        inst.resolve_packet(&domain, port, *strategy).await
                                    else {
                                        return Ok(0);
                                    };
                                    *resolved.entry(domain).or_insert(ip)
                                }
                            },
                        };
                        let target = SocketAddr::new(ip, port);
                        if blocked(target, true, rules).is_some() {
                            return Ok(0);
                        }
                        target
                    }
                };
                let target = match target {
                    SocketAddr::V4(v4) if *v6 => {
                        SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
                    }
                    target => target,
                };
                Ok(socket.send_to(&packet.data, target).await?)
            }
            PacketOut::Socks { socket, dest, port } => {
                let (address, port) = packet.addr.unwrap_or_else(|| (dest.clone(), *port));
                let wire = crate::socks::udp_encode(&address, port, &packet.data)?;
                socket.send(&wire).await?;
                Ok(wire.len())
            }
            PacketOut::Vless(tunnel) => tunnel.send(&packet.data, packet.addr.as_ref()).await,
        }
    }

    /// Receives one packet tagged with its source, plus its wire size; `None` when a final rule
    /// drops the source.
    async fn recv(&self, buf: &mut [u8]) -> Result<Option<(Packet, usize)>> {
        match self {
            PacketOut::Freedom {
                socket,
                default,
                original,
                rules,
                ..
            } => {
                let (n, source) = socket.recv_from(buf).await?;
                let ip = source.ip().to_canonical();
                if blocked(SocketAddr::new(ip, source.port()), true, rules).is_some() {
                    return Ok(None);
                }
                // Replies from the dialed IP keep the address the client asked for (e.g. a domain).
                let address = if ip == default.ip().to_canonical() {
                    original.clone()
                } else {
                    Address::Ip(ip)
                };
                let packet = Packet {
                    data: buf[..n].to_vec(),
                    addr: Some((address, source.port())),
                };
                Ok(Some((packet, n)))
            }
            PacketOut::Socks { socket, .. } => {
                let wire = socket.recv(buf).await?;
                let (address, port, data) = crate::socks::udp_decode(&buf[..wire])?;
                let packet = Packet {
                    data: data.to_vec(),
                    addr: Some((address, port)),
                };
                Ok(Some((packet, wire)))
            }
            PacketOut::Vless(tunnel) => tunnel.recv().await.map(Some),
        }
    }
}

/// Packet relay between a mux UDP sub-session and the outbound (freedom/socks Process for UDP).
async fn relay_packets(
    inst: &Arc<Instance>,
    link: PacketLink,
    out: PacketOut<'_>,
    base: &Base,
    out_up: Option<Arc<Counter>>,
    out_down: Option<Arc<Counter>>,
) -> Result<()> {
    let PacketLink { mut up, down } = link;
    let policy = &base.policy;
    let activity = Activity::new(policy.conn_idle);
    let uplink = async {
        let mut resolved = HashMap::new();
        if let PacketOut::Freedom {
            original: Address::Domain(domain),
            default,
            ..
        } = &out
        {
            resolved.insert(domain.clone(), default.ip());
        }
        while let Some(packet) = up.recv().await {
            activity.touch();
            if let Some(c) = &base.user_up {
                c.add(packet.data.len() as i64);
            }
            let wire = out.send(inst, packet, &mut resolved).await?;
            if let Some(c) = &out_up {
                c.add(wire as i64);
            }
        }
        activity.set_timeout(policy.downlink_only);
        Result::<()>::Ok(())
    };
    let downlink = async {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let Some((packet, wire)) = out.recv(&mut buf).await? else {
                continue;
            };
            activity.touch();
            if let Some(c) = &out_down {
                c.add(wire as i64);
            }
            if let Some(c) = &base.user_down {
                c.add(packet.data.len() as i64);
            }
            if down.send(packet).await.is_err() {
                bail!("failed to process response: io: read/write on closed pipe");
            }
        }
        #[allow(unreachable_code)]
        Result::<()>::Ok(())
    };
    tokio::select! {
        result = async { tokio::try_join!(uplink, downlink) } => { result?; }
        _ = activity.expired() => {}
    }
    Ok(())
}

impl PacketLink {
    /// The dns outbound over mux UDP: each packet is one message; answers carry no address.
    #[allow(clippy::too_many_arguments)]
    async fn dns(
        self,
        inst: &Arc<Instance>,
        outbound: &Outbound,
        cfg: &DnsOutbound,
        base: &Base,
        own: bool,
        dest: &Address,
        port: u16,
    ) -> Result<()> {
        let PacketLink { mut up, down } = self;
        let (up_tx, up_rx) = mpsc::channel::<Vec<u8>>(16);
        let (down_tx, mut down_rx) = mpsc::channel::<Vec<u8>>(16);
        let reader = async {
            while let Some(packet) = up.recv().await {
                if let Some(c) = &base.user_up {
                    c.add(packet.data.len() as i64);
                }
                if up_tx.send(packet.data).await.is_err() {
                    break;
                }
            }
            drop(up_tx);
            std::future::pending::<Result<()>>().await
        };
        let writer = async {
            while let Some(data) = down_rx.recv().await {
                if let Some(c) = &base.user_down {
                    c.add(data.len() as i64);
                }
                if down.send(Packet { data, addr: None }).await.is_err() {
                    bail!("io: read/write on closed pipe");
                }
            }
            std::future::pending::<Result<()>>().await
        };
        let handler = crate::dns_outbound::process(
            inst, outbound, cfg, base.id, own, true, dest, port, up_rx, down_tx,
        );
        tokio::select! {
            result = handler => result,
            result = reader => result,
            result = writer => result,
        }
    }

    /// blackhole for UDP: optional HTTP response, then drain until 30-90 s pass without packets.
    async fn blackhole(mut self, http: bool, base: &Base) -> Result<()> {
        if http {
            let response = Packet {
                data: HTTP_403.to_vec(),
                addr: None,
            };
            let _ = self.down.send(response).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let idle = Duration::from_secs(30 + rand_below(61));
        while let Ok(Some(packet)) = tokio::time::timeout(idle, self.up.recv()).await {
            if let Some(c) = &base.user_up {
                c.add(packet.data.len() as i64);
            }
        }
        Ok(())
    }

    /// freedom blackhole(): discards the client's packets for `delay`.
    async fn drain_for(mut self, delay: Duration, base: &Base) -> Result<()> {
        let _ = tokio::time::timeout(delay, async {
            while let Some(packet) = self.up.recv().await {
                if let Some(c) = &base.user_up {
                    c.add(packet.data.len() as i64);
                }
            }
        })
        .await;
        Ok(())
    }
}

pub(crate) async fn resolve(dest: &Address, port: u16) -> Result<Vec<SocketAddr>> {
    match dest {
        Address::Ip(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
        Address::Domain(d) => Ok(tokio::net::lookup_host((d.as_str(), port)).await?.collect()),
    }
}

pub(crate) async fn udp_connect(
    addr: SocketAddr,
    options: &crate::socket::Options,
) -> Result<UdpSocket> {
    let socket = UdpSocket::bind(if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    options.apply(&socket, false)?;
    socket.connect(addr).await?;
    Ok(socket)
}

enum Datagram {
    Socket {
        socket: UdpSocket,
        socks: Option<(Address, u16)>,
    },
    Vless(crate::vless_out::UdpTunnel),
}

impl Datagram {
    async fn send(&self, data: &[u8]) -> Result<usize> {
        match self {
            Datagram::Socket {
                socket,
                socks: Some((dest, port)),
            } => {
                let packet = crate::socks::udp_encode(dest, *port, data)?;
                socket.send(&packet).await?;
                Ok(packet.len())
            }
            Datagram::Socket { socket, .. } => Ok(socket.send(data).await?),
            Datagram::Vless(tunnel) => tunnel.send(data, None).await,
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, usize)> {
        match self {
            Datagram::Socket { socket, socks } => {
                let wire = socket.recv(buf).await?;
                if socks.is_some() {
                    let (_, _, payload) = crate::socks::udp_decode(&buf[..wire])?;
                    let n = payload.len();
                    buf.copy_within(wire - n..wire, 0);
                    Ok((n, wire))
                } else {
                    Ok((wire, wire))
                }
            }
            Datagram::Vless(tunnel) => {
                let (packet, wire) = tunnel.recv().await?;
                let n = packet.data.len().min(buf.len());
                buf[..n].copy_from_slice(&packet.data[..n]);
                Ok((n, wire))
            }
        }
    }
}

async fn connect(addrs: &[SocketAddr], options: &crate::socket::Options) -> Result<TcpStream> {
    // retry.ExponentialBackoff(5, 100): despite the name it sleeps 0, 100, 200, 300, 400 ms.
    let mut last = None;
    for attempt in 0..5u32 {
        if addrs.is_empty() {
            bail!("failed to resolve destination");
        }
        match connect_once(addrs, options).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
        tokio::time::sleep(Duration::from_millis(100 * u64::from(attempt))).await;
    }
    Err(last
        .unwrap_or_else(|| anyhow::anyhow!("failed to dial"))
        .context("failed to open connection"))
}

/// One dial attempt over every resolved address (system dialer, 16 s timeout each).
pub(crate) async fn connect_once(
    addrs: &[SocketAddr],
    options: &crate::socket::Options,
) -> Result<TcpStream> {
    let mut last = None;
    for addr in addrs {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        };
        let socket = match socket {
            Ok(socket) => socket,
            Err(error) => {
                last = Some(error.into());
                continue;
            }
        };
        options.apply(&socket, true)?;
        match tokio::time::timeout(Duration::from_secs(16), socket.connect(*addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last = Some(anyhow::Error::from(e)),
            Err(_) => last = Some(anyhow::anyhow!("dial timeout")),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("failed to resolve destination")))
}

fn rand_below(n: u64) -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(Instant::now().elapsed().as_nanos());
    h.finish() % n.max(1)
}

/// The inbound side of a VLESS session after the request header.
struct Client {
    conn: Counted<BoxIo>,
    skip: Arc<AtomicUsize>,
    payload: Vec<u8>,
    payload_counted: bool,
    user_up: Option<Arc<Counter>>,
    user_down: Option<Arc<Counter>>,
    header_pending: bool,
    vision: Option<crate::tls13::DirectControl>,
    id: Sid,
}

pub(crate) const RESPONSE_HEADER: [u8; 2] = [0, 0];

impl Client {
    async fn write_down(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(c) = &self.user_down {
            c.add(data.len() as i64);
        }
        if self.header_pending {
            self.header_pending = false;
            let mut first = RESPONSE_HEADER.to_vec();
            first.extend_from_slice(data);
            self.skip.store(first.len(), Ordering::Relaxed);
            self.conn.write_all(&first).await?;
        } else {
            self.conn.write_all(data).await?;
        }
        self.conn.flush().await
    }

    async fn blackhole(mut self, http: bool, udp: bool) -> Result<()> {
        if http {
            self.write_down(HTTP_403).await?;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        if udp {
            return self
                .drain_for(Duration::from_secs(30 + rand_below(61)))
                .await;
        }
        if self.header_pending {
            self.skip.store(RESPONSE_HEADER.len(), Ordering::Relaxed);
            self.conn.write_all(&RESPONSE_HEADER).await.ok();
            self.conn.flush().await.ok();
        }
        Ok(())
    }

    /// freedom blackhole(): reads and discards the client for `delay`, counting it as user uplink.
    async fn drain_for(mut self, delay: Duration) -> Result<()> {
        if !self.payload_counted
            && let Some(c) = &self.user_up
        {
            c.add(self.payload.len() as i64);
        }
        let mut sink = [0u8; 8192];
        let user_up = self.user_up.clone();
        let _ = tokio::time::timeout(delay, async {
            while let Ok(n) = self.conn.read(&mut sink).await
                && n > 0
            {
                if let Some(c) = &user_up {
                    c.add(n as i64);
                }
            }
        })
        .await;
        Ok(())
    }

    /// The dns outbound over this client: one message per 2-byte length frame both ways
    /// (DNS over TCP, or VLESS UDP packets).
    #[allow(clippy::too_many_arguments)]
    async fn dns(
        mut self,
        inst: &Arc<Instance>,
        outbound: &Outbound,
        cfg: &DnsOutbound,
        id: Sid,
        own: bool,
        udp: bool,
        dest: &Address,
        port: u16,
    ) -> Result<()> {
        let mut pending = Vec::new();
        let first = std::mem::take(&mut self.payload);
        if !self.payload_counted
            && !udp
            && let Some(c) = &self.user_up
        {
            c.add(first.len() as i64);
        }
        let user_up = self.user_up.clone();
        let (mut client_read, client_write) = tokio::io::split(self.conn);
        let mut down = Downlink {
            inner: client_write,
            skip: self.skip.clone(),
            user_down: self.user_down.clone(),
            header_pending: self.header_pending,
        };
        let (up_tx, up_rx) = mpsc::channel::<Vec<u8>>(16);
        let (down_tx, mut down_rx) = mpsc::channel::<Vec<u8>>(16);
        let reader = async {
            let mut buf = [0u8; 8192];
            pending.extend_from_slice(&first);
            'read: loop {
                while pending.len() >= 2 {
                    let len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                    if pending.len() < 2 + len {
                        break;
                    }
                    let message: Vec<u8> = pending.drain(..2 + len).skip(2).collect();
                    // VLESS UDP counts datagrams; DNS over TCP counts the stream, frames included.
                    if udp && let Some(c) = &user_up {
                        c.add(message.len() as i64);
                    }
                    if up_tx.send(message).await.is_err() {
                        break 'read;
                    }
                }
                let n = client_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                if !udp && let Some(c) = &user_up {
                    c.add(n as i64);
                }
                pending.extend_from_slice(&buf[..n]);
            }
            drop(up_tx);
            std::future::pending::<Result<()>>().await
        };
        let writer = async {
            while let Some(message) = down_rx.recv().await {
                let mut framed = (message.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&message);
                let counted = if udp { message.len() } else { framed.len() };
                down.write_raw(&framed, counted).await?;
            }
            std::future::pending::<Result<()>>().await
        };
        let handler = crate::dns_outbound::process(
            inst, outbound, cfg, id, own, udp, dest, port, up_rx, down_tx,
        );
        tokio::select! {
            result = handler => result,
            result = reader => result,
            result = writer => result,
        }
    }

    /// `splice_from`: freedom's socket and outbound downlink counter, for CopyRawConnIfExist.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    async fn relay_tcp<R: AsyncRead + AsyncWrite + Unpin>(
        mut self,
        remote: R,
        policy: &LevelPolicy,
        splice_from: Option<(Arc<TcpStream>, Option<Arc<Counter>>)>,
    ) -> Result<()> {
        let activity = Activity::new(policy.conn_idle);
        let inbound_down = self.conn.down.clone();
        let (vision, id) = (self.vision.take(), self.id);
        let (mut remote_read, mut remote_write) = tokio::io::split(remote);
        let payload = std::mem::take(&mut self.payload);
        let payload_counted = self.payload_counted;
        let user_up = self.user_up.clone();
        let (mut client_read, client_write) = tokio::io::split(self.conn);
        let mut down = Downlink {
            inner: client_write,
            skip: self.skip.clone(),
            user_down: self.user_down.clone(),
            header_pending: self.header_pending,
        };
        let uplink = async {
            if !payload.is_empty() {
                if !payload_counted && let Some(c) = &user_up {
                    c.add(payload.len() as i64);
                }
                remote_write.write_all(&payload).await?;
                activity.touch();
            }
            let mut buf = vec![0u8; 16384];
            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                activity.touch();
                if let Some(c) = &user_up {
                    c.add(n as i64);
                }
                remote_write.write_all(&buf[..n]).await?;
            }
            remote_write.shutdown().await.ok();
            activity.set_timeout(policy.downlink_only);
            io::Result::Ok(())
        };
        let downlink = async {
            let mut buf = vec![0u8; 16384];
            loop {
                // CopyRawConnIfExist: once Vision writes directly (its last padded frame is
                // flushed), the kernel moves the rest; Go splices only this direction.
                #[cfg(target_os = "linux")]
                if let (Some((source, out_down)), Some(target)) = (
                    &splice_from,
                    vision.as_ref().and_then(|v| v.splice_target()),
                ) {
                    tracing::debug!("{id}proxy: CopyRawConn splice");
                    activity.set_timeout(Duration::from_secs(24 * 3600));
                    let (moved, result) = crate::splice::copy(source, &target).await;
                    for counter in [out_down, &inbound_down, &down.user_down]
                        .into_iter()
                        .flatten()
                    {
                        counter.add(moved as i64);
                    }
                    result?;
                    break;
                }
                let n = remote_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                activity.touch();
                down.write(&buf[..n]).await?;
            }
            down.finish().await;
            activity.set_timeout(policy.uplink_only);
            io::Result::Ok(())
        };
        tokio::select! {
            result = async { tokio::try_join!(uplink, downlink) } => { result?; }
            _ = activity.expired() => {}
        }
        Ok(())
    }

    async fn relay_udp(
        mut self,
        socket: Datagram,
        policy: &LevelPolicy,
        out_up: Option<Arc<Counter>>,
        out_down: Option<Arc<Counter>>,
    ) -> Result<()> {
        let activity = Activity::new(policy.conn_idle);
        let mut pending = std::mem::take(&mut self.payload);
        let user_up = self.user_up.clone();
        let (mut client_read, client_write) = tokio::io::split(self.conn);
        let mut down = Downlink {
            inner: client_write,
            skip: self.skip.clone(),
            user_down: self.user_down.clone(),
            header_pending: self.header_pending,
        };
        let uplink = async {
            let mut buf = [0u8; 8192];
            loop {
                // encoding.LengthPacketReader: 2-byte big-endian length, then the datagram.
                while pending.len() >= 2 {
                    let len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                    if pending.len() < 2 + len {
                        break;
                    }
                    let packet: Vec<u8> = pending.drain(..2 + len).skip(2).collect();
                    if let Some(c) = &user_up {
                        c.add(packet.len() as i64);
                    }
                    let wire = socket.send(&packet).await?;
                    if let Some(c) = &out_up {
                        c.add(wire as i64);
                    }
                    activity.touch();
                }
                let n = client_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                pending.extend_from_slice(&buf[..n]);
            }
            activity.set_timeout(policy.downlink_only);
            Result::<()>::Ok(())
        };
        let downlink = async {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, wire) = socket.recv(&mut buf).await?;
                activity.touch();
                if let Some(c) = &out_down {
                    c.add(wire as i64);
                }
                let mut framed = (n as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&buf[..n]);
                down.write_raw(&framed, n).await?;
            }
            #[allow(unreachable_code)]
            Result::<()>::Ok(())
        };
        tokio::select! {
            result = async { tokio::try_join!(uplink, downlink) } => { result?; }
            _ = activity.expired() => {}
        }
        Ok(())
    }
}

struct Downlink<W> {
    inner: W,
    skip: Arc<AtomicUsize>,
    user_down: Option<Arc<Counter>>,
    header_pending: bool,
}

impl<W: AsyncWrite + Unpin> Downlink<W> {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.write_raw(data, data.len()).await
    }
    async fn write_raw(&mut self, data: &[u8], payload: usize) -> io::Result<()> {
        if let Some(c) = &self.user_down {
            c.add(payload as i64);
        }
        if self.header_pending {
            self.header_pending = false;
            let mut first = RESPONSE_HEADER.to_vec();
            first.extend_from_slice(data);
            self.skip.store(first.len(), Ordering::Relaxed);
            self.inner.write_all(&first).await?;
        } else {
            self.inner.write_all(data).await?;
        }
        self.inner.flush().await
    }
    async fn finish(&mut self) {
        if self.header_pending {
            self.header_pending = false;
            self.skip.store(RESPONSE_HEADER.len(), Ordering::Relaxed);
            let _ = self.inner.write_all(&RESPONSE_HEADER).await;
        }
        let _ = self.inner.shutdown().await;
    }
}

#[cfg(test)]
mod continuation_tests {
    use super::*;

    #[tokio::test]
    async fn empty_vless_connection_closes_cleanly_but_partial_request_still_fails() {
        let config = Config::parse(&serde_json::json!({"inbounds":[{"tag":"in","listen":"127.0.0.1","port":12345,"protocol":"vless","settings":{"decryption":"none","clients":[]}}]}).to_string()).unwrap();
        let me = Instance::new(config).unwrap();
        let peer: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        let (io, remote) = tokio::io::duplex(64);
        drop(remote);
        assert!(
            me.clone()
                .vless_conn(0, Box::new(io), peer, peer, None, None, Sid(1))
                .await
                .is_ok()
        );
        let (io, mut remote) = tokio::io::duplex(64);
        remote.write_all(&[0]).await.unwrap();
        drop(remote);
        assert!(
            me.vless_conn(0, Box::new(io), peer, peer, None, None, Sid(1))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn stalled_vless_outbound_uses_its_own_handshake_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stall = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let config = Config::parse(&serde_json::json!({
            "policy":{"levels":{"7":{"handshake":1}}},
            "inbounds":[{"tag":"in","port":12345,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"01010101010101010101010101010101"}]}}],
            "outbounds":[{"protocol":"vless","settings":{"address":"127.0.0.1","port":port,"id":"fuzz","encryption":"none","level":7},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost"}}}]
        }).to_string()).unwrap();
        let me = Instance::new(config).unwrap();
        let (io, mut remote) = tokio::io::duplex(128);
        let mut request = vec![0];
        request.extend_from_slice(&[1; 16]);
        request.extend_from_slice(&[0, 1, 0, 80, 1, 127, 0, 0, 1]);
        request.extend_from_slice(b"payload");
        remote.write_all(&request).await.unwrap();
        let peer = "127.0.0.1:12346".parse().unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(3),
            me.vless_conn(0, Box::new(io), peer, peer, None, None, Sid(1)),
        )
        .await
        .expect("outbound handshake ignored its policy")
        .expect_err("stalled handshake succeeded");
        stall.abort();
        assert!(
            format!("{error:#}").contains("VLESS outbound handshake timeout"),
            "{error:#}"
        );
    }
}

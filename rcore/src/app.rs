//! Instance wiring: inbound listeners, dispatcher (sniff + route), outbounds and the relay.
use crate::{
    config::{Config, FinalRule, InboundKind, LevelPolicy, OutboundKind},
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
};

static PRIVATE: LazyLock<IpMatcher> = LazyLock::new(private_ips);

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
struct Activity {
    start: Instant,
    last: AtomicU64,
    timeout: AtomicU64,
}

impl Activity {
    fn new(timeout: Duration) -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
            timeout: AtomicU64::new(timeout.as_millis() as u64),
        }
    }
    fn touch(&self) {
        self.last
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    fn set_timeout(&self, timeout: Duration) {
        self.timeout
            .store(timeout.as_millis() as u64, Ordering::Relaxed);
        self.touch();
    }
    async fn expired(&self) {
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
        for (index, inbound) in self.config.inbounds.iter().enumerate() {
            let listener = TcpListener::bind((inbound.listen, inbound.port))
                .await
                .with_context(|| {
                    format!(
                        "failed to listen TCP on {}:{}",
                        inbound.listen, inbound.port
                    )
                })?;
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
                InboundKind::Vless(_) => {
                    tokio::spawn(async move {
                        loop {
                            let Ok((stream, peer)) = listener.accept().await else {
                                continue;
                            };
                            let me = me.clone();
                            tokio::spawn(async move {
                                if let Err(error) =
                                    me.clone().vless_session(index, stream, peer).await
                                {
                                    tracing::info!(
                                        "[{}] {peer} {error:#}",
                                        me.config.inbounds[index].tag
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
    ) -> Result<()> {
        let inbound = &self.config.inbounds[index];
        let local = stream.local_addr()?;
        stream.set_nodelay(true).ok();
        let tag = &inbound.tag;
        // The inbound counters wrap whatever the transport hands over (WS payload, not frames).
        let (io, peer, direct): (BoxIo, SocketAddr, Option<crate::tls13::DirectControl>) =
            match &inbound.transport {
                Transport::Raw => match &inbound.reality {
                    Some(reality) => {
                        let (io, direct) = crate::reality::accept(
                            reality,
                            stream,
                            self.config.policy.level(0).handshake,
                        )
                        .await?;
                        (io, peer, Some(direct))
                    }
                    None => (Box::new(stream), peer, None),
                },
                Transport::Ws {
                    path,
                    host,
                    heartbeat,
                } => {
                    let (io, peer) =
                        accept_ws(stream, path, host, *heartbeat, &inbound.trusted_xff).await?;
                    (io, peer, None)
                }
                Transport::HttpUpgrade { path, host } => {
                    let (io, peer) =
                        accept_httpupgrade(stream, path, host, &inbound.trusted_xff).await?;
                    (io, peer, None)
                }
            };
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
        let (request, mut payload) =
            tokio::time::timeout(handshake, vless::read_request(&mut conn, &users))
                .await
                .context("handshake timeout")?
                .map_err(|e| e.context(format!("invalid request from {peer}")))?;
        vless::check_flow(&request, inbound.reality.is_some())?;
        if request.flow == vless::XRV {
            let (io, decoded) = crate::vision::wrap(
                conn.inner,
                &payload,
                request.sent_id,
                direct.context("Vision requires REALITY")?,
            )?;
            conn.inner = io;
            payload = decoded;
        }
        if matches!(request.command, Command::Mux | Command::Rvs) {
            return Err(crate::config::unsupported(
                "VLESS mux/xudp (v1.mux.cool) and reverse",
            ));
        }
        let user = request.user.clone();
        let policy = self.config.policy.level(user.level);
        let email = user.email.clone();
        let _online = (policy.user_online && !email.is_empty())
            .then(|| OnlineGuard::new(&self.stats, &email, address_string(peer.ip())));
        let user_up = self.counter(
            policy.user_uplink && !email.is_empty(),
            format!("user>>>{email}>>>traffic>>>uplink"),
        );
        let user_down = self.counter(
            policy.user_downlink && !email.is_empty(),
            format!("user>>>{email}>>>traffic>>>downlink"),
        );
        let udp = request.command == Command::Udp;
        let mut dest = request.address.clone();
        let mut route_domain = match &dest {
            Address::Domain(d) => Some(d.clone()),
            Address::Ip(_) => None,
        };
        let mut protocol = String::new();
        let sniffing = &inbound.sniffing;
        // Go counts user uplink when the dispatcher reads the client; sniffing reads the first payload.
        let sniffed = sniffing.enabled && !sniffing.metadata_only && !udp;
        if sniffed && let Some((p, domain)) = sniff_first(&mut conn, &mut payload).await {
            protocol = p.to_owned();
            let overrides = !domain.is_empty()
                && !sniffing.domains_excluded.matches(&domain)
                && sniffing
                    .dest_override
                    .iter()
                    .any(|o| p.starts_with(o.as_str()) || o.starts_with(p));
            if overrides {
                route_domain = Some(domain.clone());
                if !sniffing.route_only {
                    dest = Address::Domain(domain);
                }
            }
        }
        let ctx = Ctx {
            inbound_tag: tag.clone(),
            inbound_name: "vless",
            udp,
            source: peer,
            local,
            domain: route_domain,
            ip: match &dest {
                Address::Ip(ip) => Some(*ip),
                Address::Domain(_) => match &request.address {
                    Address::Ip(ip) if sniffing.route_only => Some(*ip),
                    _ => None,
                },
            },
            port: request.port,
            protocol,
            user: email.clone(),
            level: user.level,
            vless_route: u16::from_be_bytes([request.sent_id[6], request.sent_id[7]]),
        };
        let outbound = match self.config.router.pick(&ctx).await {
            Some(rule) => match self
                .config
                .outbounds
                .iter()
                .find(|o| o.tag == rule.outbound)
            {
                Some(o) if !rule.tag.is_empty() => {
                    tracing::info!(
                        "Hit route rule: [{}] so taking detour [{}]",
                        rule.tag,
                        o.tag
                    );
                    o
                }
                Some(o) => o,
                None => {
                    // DO NOT CHANGE (Go): a missing tag must not fall back to the default outbound.
                    tracing::warn!("non existing outTag: {}", rule.outbound);
                    return Ok(());
                }
            },
            None => self
                .config
                .outbounds
                .first()
                .context("default outbound handler not exist")?,
        };
        self.access(&ctx, &dest, &outbound.tag);
        let otag = &outbound.tag;
        let out_up = self.counter(
            self.config.policy.outbound_uplink && !otag.is_empty(),
            format!("outbound>>>{otag}>>>traffic>>>uplink"),
        );
        let out_down = self.counter(
            self.config.policy.outbound_downlink && !otag.is_empty(),
            format!("outbound>>>{otag}>>>traffic>>>downlink"),
        );
        if sniffed && let Some(c) = &user_up {
            c.add(payload.len() as i64);
        }
        let client = Client {
            // Measured against Go: only raw TCP leaves the first downlink write uncounted.
            skip: if matches!(inbound.transport, Transport::Raw) {
                conn.uncounted()
            } else {
                Arc::default()
            },
            conn,
            payload,
            payload_counted: sniffed,
            user_up,
            user_down,
            header_pending: true,
        };
        match &outbound.kind {
            OutboundKind::Blackhole { http } => client.blackhole(*http, udp).await,
            OutboundKind::Socks(server) => {
                let addrs: Vec<_> = tokio::net::lookup_host((server.address.as_str(), server.port))
                    .await?
                    .collect();
                let remote = connect(&addrs, &outbound.socket).await?;
                remote.set_nodelay(true).ok();
                let mut remote = Counted::new(remote, out_down.clone(), out_up.clone());
                let (mut relay, relay_port) = tokio::time::timeout(
                    policy.handshake,
                    crate::socks::handshake(&mut remote, server, &dest, request.port, udp),
                )
                .await
                .context("SOCKS handshake timeout")??;
                if udp {
                    if matches!(relay, Address::Ip(ip) if ip.is_unspecified()) {
                        relay = Address::Ip(remote.inner.peer_addr()?.ip());
                    }
                    let relay = resolve(&relay, relay_port)
                        .await?
                        .into_iter()
                        .next()
                        .context("failed to resolve SOCKS UDP relay")?;
                    let socket = udp_connect(relay, &outbound.socket).await?;
                    let socket = Datagram {
                        socket,
                        socks: Some((dest, request.port)),
                    };
                    let mut closed = [0u8; 1];
                    tokio::select! {
                        result = client.relay_udp(socket, &policy, out_up, out_down) => result,
                        _ = remote.read(&mut closed) => Ok(()),
                    }
                } else {
                    client.relay_tcp(remote, &policy).await
                }
            }
            OutboundKind::Freedom {
                final_rules,
                strategy,
            } => {
                let target = freedom_target(&dest, request.port, udp, final_rules, strategy).await;
                match target {
                    Target::Blocked(rule_delay, shown) => {
                        let delay = rule_delay.0
                            + rand_below(rule_delay.1.saturating_sub(rule_delay.0) + 1);
                        tracing::warn!(
                            "target blocked by a finalrule: {}:{shown}, blackholing connection for {delay}s",
                            if udp { "udp" } else { "tcp" }
                        );
                        client.drain_for(Duration::from_secs(delay)).await
                    }
                    Target::Dial(addrs) if udp => {
                        let addr = *addrs.first().context("failed to resolve destination")?;
                        let socket = udp_connect(addr, &outbound.socket).await?;
                        client
                            .relay_udp(
                                Datagram {
                                    socket,
                                    socks: None,
                                },
                                &policy,
                                out_up,
                                out_down,
                            )
                            .await
                    }
                    Target::Dial(addrs) => {
                        let remote = connect(&addrs, &outbound.socket).await?;
                        if let Address::Domain(_) = dest
                            && let Some((delay, shown)) =
                                blocked(remote.peer_addr()?, udp, final_rules)
                        {
                            drop(remote);
                            tracing::warn!(
                                "target blocked by a finalrule: tcp:{shown}, blackholing connection"
                            );
                            return client.drain_for(Duration::from_secs(delay.0)).await;
                        }
                        remote.set_nodelay(true).ok();
                        client
                            .relay_tcp(Counted::new(remote, out_down, out_up), &policy)
                            .await
                    }
                }
            }
        }
    }

    fn access(&self, ctx: &Ctx, dest: &Address, outbound: &str) {
        let Some(path) = &self.config.access_log else {
            return;
        };
        let line = format!(
            "from {} accepted {}:{dest}:{} [{} -> {outbound}] email: {}\n",
            ctx.source,
            if ctx.udp { "udp" } else { "tcp" },
            ctx.port,
            ctx.inbound_tag,
            ctx.user
        );
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            use std::io::Write;
            let _ = file.write_all(format!("{} {line}", crate::log_time()).as_bytes());
        }
    }
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
    Dial(Vec<SocketAddr>),
    Blocked((u64, u64), String),
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

async fn freedom_target(
    dest: &Address,
    port: u16,
    udp: bool,
    rules: &[FinalRule],
    strategy: &str,
) -> Target {
    let addrs: Vec<SocketAddr> = match dest {
        Address::Ip(ip) => vec![SocketAddr::new(*ip, port)],
        Address::Domain(d) => tokio::net::lookup_host((d.as_str(), port))
            .await
            .map(|a| a.collect())
            .unwrap_or_default(),
    };
    let addrs: Vec<SocketAddr> = match strategy {
        s if s.ends_with("IPv4") => addrs.into_iter().filter(SocketAddr::is_ipv4).collect(),
        s if s.ends_with("IPv6") => addrs.into_iter().filter(SocketAddr::is_ipv6).collect(),
        s if s.ends_with("IPv6v4") => {
            let (mut v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv6);
            v6.extend(v4);
            v6
        }
        s if s.ends_with("IPv4v6") => {
            let (mut v4, v6): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv4);
            v4.extend(v6);
            v4
        }
        _ => addrs,
    };
    for addr in &addrs {
        if let Some((delay, shown)) = blocked(*addr, udp, rules) {
            return Target::Blocked(delay, shown);
        }
    }
    Target::Dial(addrs)
}

async fn resolve(dest: &Address, port: u16) -> Result<Vec<SocketAddr>> {
    match dest {
        Address::Ip(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
        Address::Domain(d) => Ok(tokio::net::lookup_host((d.as_str(), port)).await?.collect()),
    }
}

async fn udp_connect(addr: SocketAddr, options: &crate::socket::Options) -> Result<UdpSocket> {
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

struct Datagram {
    socket: UdpSocket,
    socks: Option<(Address, u16)>,
}

impl Datagram {
    async fn send(&self, data: &[u8]) -> Result<usize> {
        if let Some((dest, port)) = &self.socks {
            let packet = crate::socks::udp_encode(dest, *port, data)?;
            self.socket.send(&packet).await?;
            Ok(packet.len())
        } else {
            Ok(self.socket.send(data).await?)
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, usize)> {
        let wire = self.socket.recv(buf).await?;
        if self.socks.is_some() {
            let payload = crate::socks::udp_decode(&buf[..wire])?;
            let n = payload.len();
            buf.copy_within(wire - n..wire, 0);
            Ok((n, wire))
        } else {
            Ok((wire, wire))
        }
    }
}

async fn connect(addrs: &[SocketAddr], options: &crate::socket::Options) -> Result<TcpStream> {
    // retry.ExponentialBackoff(5, 100)
    let mut last = None;
    for attempt in 0..5u32 {
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
        if addrs.is_empty() {
            bail!("failed to resolve destination");
        }
        tokio::time::sleep(Duration::from_millis(100 << attempt)).await;
    }
    Err(last
        .unwrap_or_else(|| anyhow::anyhow!("failed to dial"))
        .context("failed to open connection"))
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
}

const RESPONSE_HEADER: [u8; 2] = [0, 0];

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
            self.write_down(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nCache-Control: max-age=3600, public\r\nContent-Length: 0\r\n\r\n").await?;
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

    async fn relay_tcp(mut self, remote: Counted<TcpStream>, policy: &LevelPolicy) -> Result<()> {
        let activity = Activity::new(policy.conn_idle);
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

//! Port of xray-core app/dns (the DNS client: hosts, name servers, cache, query order),
//! features/dns/localdns, and the DNS message helpers they share with proxy/dns.
use crate::app::{Instance, Internal, Packet};
use crate::config::{keys, string_list, unsupported};
use crate::geodata::{DomainMatcher, IpMatcher, Kind, Loader};
use crate::vless::Address;
use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use serde_json::Value;
use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, watch},
};

/// features/dns DefaultTTL.
pub const DEFAULT_TTL: u32 = 300;
pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;

/// dns.IPOption.
#[derive(Clone, Copy, Debug)]
pub struct IpOption {
    pub v4: bool,
    pub v6: bool,
}

/// The errors the DNS code tells apart with errors.Is, printed as Go prints them.
#[derive(Clone, Debug)]
pub enum DnsError {
    /// dns.ErrEmptyResponse
    Empty,
    /// dns.RCodeError
    RCode(u16),
    /// errRecordNotFound
    NotFound,
    /// context.DeadlineExceeded
    Deadline,
    Msg(String),
    /// errors.New(msg).Base(inner)
    Wrap(String, Box<DnsError>),
    /// errors.Combine
    Multi(Vec<DnsError>),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DnsError::Empty => f.write_str("features/dns: empty response"),
            DnsError::RCode(c) => write!(f, "rcode: {c}"),
            DnsError::NotFound => f.write_str("app/dns: record not found"),
            DnsError::Deadline => f.write_str("context deadline exceeded"),
            DnsError::Msg(m) => f.write_str(m),
            DnsError::Wrap(m, inner) => write!(f, "{m} > {inner}"),
            DnsError::Multi(errs) => {
                f.write_str("multierr: ")?;
                errs.iter().try_for_each(|e| write!(f, "{e} | "))
            }
        }
    }
}

impl DnsError {
    /// errors.Is against the sentinel values (a multiError does not unwrap).
    pub fn is(&self, target: &DnsError) -> bool {
        match (self, target) {
            (DnsError::Wrap(_, inner), t) => inner.is(t),
            (DnsError::Empty, DnsError::Empty)
            | (DnsError::NotFound, DnsError::NotFound)
            | (DnsError::Deadline, DnsError::Deadline) => true,
            (DnsError::RCode(a), DnsError::RCode(b)) => a == b,
            _ => false,
        }
    }

    /// dns.RCodeFromError: the rcode carried by the innermost error.
    pub fn rcode(&self) -> u16 {
        match self {
            DnsError::Wrap(_, inner) => inner.rcode(),
            DnsError::RCode(c) => *c,
            _ => 0,
        }
    }

    fn wrap(msg: String, inner: DnsError) -> Self {
        DnsError::Wrap(msg, Box::new(inner))
    }
}

/// time.Duration.String.
pub fn go_duration(d: Duration) -> String {
    fn frac(v: u128, div: u128, prec: usize) -> String {
        let (int, f) = (v / div, v % div);
        if f == 0 {
            return int.to_string();
        }
        let digits = format!("{f:0prec$}");
        format!("{int}.{}", digits.trim_end_matches('0'))
    }
    let ns = d.as_nanos();
    match ns {
        0 => "0s".into(),
        n if n < 1_000 => format!("{n}ns"),
        n if n < 1_000_000 => format!("{}µs", frac(n, 1_000, 3)),
        n if n < 1_000_000_000 => format!("{}ms", frac(n, 1_000_000, 6)),
        n => {
            let (h, rem) = (n / 3_600_000_000_000, n % 3_600_000_000_000);
            let (m, s) = (rem / 60_000_000_000, rem % 60_000_000_000);
            let mut out = String::new();
            if h > 0 {
                out += &format!("{h}h");
            }
            if h > 0 || m > 0 {
                out += &format!("{m}m");
            }
            out + &format!("{}s", frac(s, 1_000_000_000, 9))
        }
    }
}

/// fmt's "%v" of []net.IP.
pub fn ip_list(ips: &[IpAddr]) -> String {
    let items: Vec<String> = ips.iter().map(IpAddr::to_string).collect();
    format!("[{}]", items.join(" "))
}

/// dnsmessage.Type.String.
pub fn type_name(t: u16) -> String {
    let name = match t {
        1 => "TypeA",
        2 => "TypeNS",
        5 => "TypeCNAME",
        6 => "TypeSOA",
        12 => "TypePTR",
        15 => "TypeMX",
        16 => "TypeTXT",
        28 => "TypeAAAA",
        33 => "TypeSRV",
        41 => "TypeOPT",
        64 => "TypeSVCB",
        65 => "TypeHTTPS",
        11 => "TypeWKS",
        13 => "TypeHINFO",
        14 => "TypeMINFO",
        252 => "TypeAXFR",
        255 => "TypeALL",
        other => return other.to_string(),
    };
    name.into()
}

fn fqdn(domain: &str) -> String {
    if domain.ends_with('.') {
        domain.to_owned()
    } else {
        format!("{domain}.")
    }
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    u64::from_le_bytes(b)
}

/// crypto.RandBetween: [from, to).
fn rand_between(from: u64, to: u64) -> u64 {
    from + random_u64() % (to - from).max(1)
}

/// dice.Roll.
pub fn roll(n: usize) -> usize {
    (random_u64() % n.max(1) as u64) as usize
}

/// net.ParseAddress: an IP (brackets allowed) or else a domain.
pub fn parse_address(s: &str) -> Address {
    let bare = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(s);
    match bare.parse::<IpAddr>() {
        Ok(ip) => Address::Ip(ip.to_canonical()),
        Err(_) => Address::Domain(s.to_owned()),
    }
}

// ---- wire format (golang.org/x/net/dns/dnsmessage subset) ----

/// Name.pack for a fully qualified name.
pub fn put_name(out: &mut Vec<u8>, name: &str) -> Result<()> {
    ensure!(
        name.len() <= 255,
        "insufficient data for calculated length type"
    );
    ensure!(name.ends_with('.'), "non-canonical name");
    if name != "." {
        for label in name[..name.len() - 1].split('.') {
            ensure!(!label.is_empty(), "zero length segment");
            ensure!(label.len() <= 63, "segment length too long");
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    Ok(())
}

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// ResourceHeader.SetEDNS0(1350, 0xfe00, true) with the given options.
fn opt_record(options: &[u8]) -> Vec<u8> {
    let mut rr = vec![0];
    put16(&mut rr, 41);
    put16(&mut rr, 1350);
    rr.extend_from_slice(&0xe000_8000u32.to_be_bytes());
    put16(&mut rr, options.len() as u16);
    rr.extend_from_slice(options);
    rr
}

/// genEDNS0Options: EDNS client subnet (/24, /96) and padding.
fn edns0(client_ip: Option<IpAddr>, padding: usize) -> Option<Vec<u8>> {
    if client_ip.is_none() && padding == 0 {
        return None;
    }
    let mut options = Vec::new();
    if let Some(ip) = client_ip {
        let (family, mask, addr) = match ip {
            IpAddr::V4(v4) => (1u16, 24u8, v4.octets()[..3].to_vec()),
            IpAddr::V6(v6) => (2, 96, v6.octets()[..12].to_vec()),
        };
        put16(&mut options, 8);
        put16(&mut options, 4 + addr.len() as u16);
        put16(&mut options, family);
        options.extend_from_slice(&[mask, 0]);
        options.extend_from_slice(&addr);
    }
    if padding != 0 {
        put16(&mut options, 12);
        put16(&mut options, padding as u16);
        options.resize(options.len() + padding, 0);
    }
    Some(opt_record(&options))
}

/// A query message: ID, RD, one question, and the OPT record when given.
fn build_query(id: u16, name: &str, qtype: u16, opt: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut m = Vec::with_capacity(64);
    put16(&mut m, id);
    put16(&mut m, 0x0100);
    put16(&mut m, 1);
    put16(&mut m, 0);
    put16(&mut m, 0);
    put16(&mut m, opt.is_some() as u16);
    put_name(&mut m, name)?;
    put16(&mut m, qtype);
    put16(&mut m, 1);
    if let Some(opt) = opt {
        m.extend_from_slice(opt);
    }
    Ok(m)
}

fn be16(b: &[u8], off: usize) -> Result<u16> {
    b.get(off..off + 2)
        .map(|x| u16::from_be_bytes([x[0], x[1]]))
        .context("insufficient data for base length type")
}

/// skipName / Name.unpack: returns the name text (with the trailing dot) and the next offset.
pub fn read_name(msg: &[u8], mut off: usize) -> Result<(String, usize)> {
    let mut name = String::new();
    let mut next = None;
    let mut hops = 0;
    loop {
        let len = *msg
            .get(off)
            .context("insufficient data for base length type")? as usize;
        match len & 0xc0 {
            0x00 if len == 0 => {
                off += 1;
                break;
            }
            0x00 => {
                let label = msg
                    .get(off + 1..off + 1 + len)
                    .context("segment length too long")?;
                name.push_str(&String::from_utf8_lossy(label));
                name.push('.');
                off += 1 + len;
            }
            0xc0 => {
                let ptr = (be16(msg, off)? & 0x3fff) as usize;
                next.get_or_insert(off + 2);
                hops += 1;
                ensure!(hops < 128, "too many pointers (>10)");
                off = ptr;
            }
            _ => bail!("invalid pointer"),
        }
    }
    if name.is_empty() {
        name.push('.');
    }
    Ok((name, next.unwrap_or(off)))
}

pub struct IpRecord {
    pub req_id: u16,
    pub ips: Vec<IpAddr>,
    pub expire: Instant,
    pub rcode: u16,
    pub truncated: bool,
}

impl IpRecord {
    /// getIPs: the IPs, the whole seconds until expiry (negative once expired), and the error.
    fn get(rec: Option<&IpRecord>) -> (Vec<IpAddr>, i32, Option<DnsError>) {
        let Some(r) = rec else {
            return (Vec::new(), 0, Some(DnsError::NotFound));
        };
        let now = Instant::now();
        let secs = if r.expire >= now {
            (r.expire - now).as_secs_f64()
        } else {
            -(now - r.expire).as_secs_f64()
        };
        let ttl = secs.ceil() as i32;
        if r.rcode != 0 {
            return (Vec::new(), ttl, Some(DnsError::RCode(r.rcode)));
        }
        if r.ips.is_empty() {
            return (Vec::new(), ttl, Some(DnsError::Empty));
        }
        (r.ips.clone(), ttl, None)
    }
}

/// parseResponse: header, skipped questions, then the A/AAAA answers and the lowest TTL.
pub fn parse_response(payload: &[u8]) -> Result<IpRecord, String> {
    ensure_msg(payload.len() >= 12)
        .map_err(|e| format!("app/dns: failed to parse DNS response > {e}"))?;
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let count = |i: usize| u16::from_be_bytes([payload[i], payload[i + 1]]);
    let now = Instant::now();
    let mut rec = IpRecord {
        req_id: u16::from_be_bytes([payload[0], payload[1]]),
        ips: Vec::new(),
        expire: now,
        rcode: flags & 0xf,
        truncated: flags & 0x0200 != 0,
    };
    let mut off = 12;
    for _ in 0..count(4) {
        off = read_name(payload, off)
            .map_err(|e| format!("app/dns: failed to skip questions in DNS response > {e}"))?
            .1
            + 4;
        if off > payload.len() {
            return Err("app/dns: failed to skip questions in DNS response > insufficient data for base length type".into());
        }
    }
    let mut expire: Option<Instant> = None;
    for _ in 0..count(6) {
        let header = (|| -> Result<(u16, u32, usize, usize)> {
            let (_, o) = read_name(payload, off)?;
            let t = be16(payload, o)?;
            let ttl = payload
                .get(o + 4..o + 8)
                .map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]))
                .context("insufficient data for base length type")?;
            let len = be16(payload, o + 8)? as usize;
            ensure!(o + 10 + len <= payload.len(), "resource length too long");
            Ok((t, ttl, o + 10, len))
        })();
        let Ok((t, ttl, data, len)) = header else {
            if let Err(e) = header {
                tracing::info!("app/dns: failed to parse answer section for domain:  > {e}");
            }
            break;
        };
        let at = now + Duration::from_secs(u64::from(ttl.max(1)));
        expire = Some(expire.map_or(at, |e: Instant| e.min(at)));
        match t {
            TYPE_A if len >= 4 => {
                let o: [u8; 4] = payload[data..data + 4].try_into().unwrap();
                rec.ips.push(IpAddr::from(o));
            }
            TYPE_AAAA if len >= 16 => {
                let o: [u8; 16] = payload[data..data + 16].try_into().unwrap();
                let ip = IpAddr::from(o);
                // net.IPAddress turns a v4-mapped address into IPv4, which the length check drops.
                if ip.to_canonical().is_ipv6() {
                    rec.ips.push(ip);
                }
            }
            TYPE_A | TYPE_AAAA => {
                tracing::info!(
                    "app/dns: failed to parse {} record for domain:  > insufficient data for base length type",
                    if t == TYPE_A { "A" } else { "AAAA" }
                );
                break;
            }
            _ => {}
        }
        off = data + len;
    }
    rec.expire = expire.unwrap_or(now + Duration::from_secs(u64::from(DEFAULT_TTL)));
    Ok(rec)
}

fn ensure_msg(ok: bool) -> Result<()> {
    ensure!(ok, "insufficient data for base length type");
    Ok(())
}

/// merge: one family's record, or both families' IPs with the lower TTL.
fn merge(
    option: IpOption,
    rec4: Option<&IpRecord>,
    rec6: Option<&IpRecord>,
    mut errs: Vec<DnsError>,
) -> (Vec<IpAddr>, i32, Option<DnsError>) {
    let mut all = Vec::new();
    let mut ttl_min = DEFAULT_TTL as i32;
    let both = option.v4 && option.v6;
    for (enabled, rec) in [(option.v4, rec4), (option.v6, rec6)] {
        if !enabled {
            continue;
        }
        let (ips, ttl, err) = IpRecord::get(rec);
        if !both || err.as_ref().is_some_and(|e| e.is(&DnsError::NotFound)) {
            return (ips, ttl, err);
        }
        ttl_min = ttl_min.min(ttl);
        if ips.is_empty() {
            errs.extend(err);
        } else {
            all.extend(ips);
        }
    }
    if !all.is_empty() {
        return (all, ttl_min, None);
    }
    if errs.len() == 2 && errs[0].is(&errs[1]) {
        return (Vec::new(), ttl_min, Some(errs.swap_remove(0)));
    }
    let err = (!errs.is_empty()).then_some(DnsError::Multi(errs));
    (Vec::new(), ttl_min, err)
}

// ---- cache controller ----

#[derive(Default)]
struct Record {
    a: Option<Arc<IpRecord>>,
    aaaa: Option<Arc<IpRecord>>,
}

type Fetched = (Vec<IpAddr>, u32, Option<DnsError>);
type Sink = mpsc::Sender<Arc<IpRecord>>;
type Answer = Result<(Vec<IpAddr>, u32), DnsError>;

/// CacheController: records per FQDN, the pubsub that wakes queries, and singleflight.
struct Cache {
    name: String,
    disable: bool,
    serve_stale: bool,
    /// Stored negated, as Go does.
    serve_expired_ttl: i32,
    ips: Mutex<HashMap<String, Record>>,
    subs: Mutex<HashMap<String, Vec<(u64, Sink)>>>,
    next_sub: AtomicU64,
    group: Mutex<HashMap<String, watch::Receiver<Option<Fetched>>>>,
    cleaning: AtomicBool,
}

struct Subscriber {
    cache: Arc<CachedServer>,
    key: String,
    id: u64,
    rx: mpsc::Receiver<Arc<IpRecord>>,
}

impl Drop for Subscriber {
    fn drop(&mut self) {
        let mut subs = self.cache.cache.subs.lock().unwrap();
        if let Some(list) = subs.get_mut(&self.key) {
            list.retain(|(id, _)| *id != self.id);
            if list.is_empty() {
                subs.remove(&self.key);
            }
        }
    }
}

impl Cache {
    fn new(name: String, disable: bool, serve_stale: bool, serve_expired_ttl: u32) -> Self {
        Self {
            name,
            disable,
            serve_stale,
            serve_expired_ttl: -(serve_expired_ttl as i32),
            ips: Mutex::default(),
            subs: Mutex::default(),
            next_sub: AtomicU64::new(0),
            group: Mutex::default(),
            cleaning: AtomicBool::new(false),
        }
    }

    fn publish(&self, key: &str, rec: &Arc<IpRecord>) {
        if let Some(list) = self.subs.lock().unwrap().get(key) {
            for (_, tx) in list {
                let _ = tx.try_send(rec.clone());
            }
        }
    }

    /// CacheCleanup: drops expired records (after serveExpiredTTL when serving stale).
    fn cleanup(&self) -> bool {
        let mut ips = self.ips.lock().unwrap();
        if ips.is_empty() {
            return false;
        }
        let mut now = Instant::now();
        if self.serve_stale && self.serve_expired_ttl != 0 {
            now = now
                .checked_sub(Duration::from_secs(
                    self.serve_expired_ttl.unsigned_abs() as u64
                ))
                .unwrap_or(now);
        }
        ips.retain(|_, rec| {
            if rec.a.as_ref().is_some_and(|r| r.expire < now) {
                rec.a = None;
            }
            if rec.aaaa.as_ref().is_some_and(|r| r.expire < now) {
                rec.aaaa = None;
            }
            rec.a.is_some() || rec.aaaa.is_some()
        });
        // shortcut: no high-watermark map rebuild; Rust's HashMap keeps its capacity until dropped.
        true
    }
}

/// A dnsRequest waiting for its answer.
#[derive(Clone)]
struct Request {
    qtype: u16,
    domain: String,
    start: Instant,
    has_opt: bool,
    msg: Vec<u8>,
}

impl Request {
    fn build(
        fqdn: &str,
        option: IpOption,
        mut id: impl FnMut() -> u16,
        opt: Option<Vec<u8>>,
    ) -> Result<Vec<(u16, Request)>> {
        let mut reqs = Vec::new();
        let start = Instant::now();
        for (enabled, qtype) in [(option.v4, TYPE_A), (option.v6, TYPE_AAAA)] {
            if enabled {
                let req_id = id();
                reqs.push((
                    req_id,
                    Request {
                        qtype,
                        domain: fqdn.to_owned(),
                        start,
                        has_opt: opt.is_some(),
                        msg: build_query(req_id, fqdn, qtype, opt.as_deref())?,
                    },
                ));
            }
        }
        Ok(reqs)
    }
}

enum Upstream {
    Udp(Udp),
    Tcp {
        local: bool,
        dest: Address,
        port: u16,
    },
    Doh(Doh),
}

/// ClassicNameServer state: pending requests by ID and the routed UDP link.
struct Udp {
    dest: Address,
    port: u16,
    requests: Mutex<HashMap<u16, (Request, Instant)>>,
    conn: Mutex<Option<(mpsc::Sender<Packet>, Arc<AtomicBool>)>>,
}

/// DoHNameServer state: one pooled HTTP/2 connection, as http2.Transport keeps.
struct Doh {
    url: String,
    hostname: String,
    port: u16,
    h2c: bool,
    local: bool,
    conn: tokio::sync::Mutex<
        Option<(
            hyper::client::conn::http2::SendRequest<http_body_util::Full<Bytes>>,
            Instant,
        )>,
    >,
}

/// A caching name server (UDP, TCP or DoH).
struct CachedServer {
    cache: Cache,
    upstream: Upstream,
    client_ip: Option<IpAddr>,
    req_id: AtomicU32,
}

impl CachedServer {
    fn next_id(&self) -> u16 {
        match self.upstream {
            Upstream::Doh(_) => 0,
            _ => (self.req_id.fetch_add(1, Ordering::Relaxed) + 1) as u16,
        }
    }

    /// queryIP: cache hit, optimistic stale answer, or a fresh fetch.
    async fn query(
        self: &Arc<Self>,
        inst: &Arc<Instance>,
        tag: &str,
        domain: &str,
        option: IpOption,
        deadline: tokio::time::Instant,
    ) -> Fetched {
        let fqdn = fqdn(domain);
        let cache = &self.cache;
        if !cache.disable {
            let rec = cache
                .ips
                .lock()
                .unwrap()
                .get(&fqdn)
                .map(|r| (r.a.clone(), r.aaaa.clone()));
            if let Some((a, aaaa)) = rec {
                let (ips, ttl, err) = merge(option, a.as_deref(), aaaa.as_deref(), Vec::new());
                if !err.as_ref().is_some_and(|e| e.is(&DnsError::NotFound)) {
                    if ttl > 0 {
                        tracing::debug!(
                            "app/dns: {} cache HIT {fqdn} -> {}{}",
                            cache.name,
                            ip_list(&ips),
                            err.as_ref().map(|e| format!(" > {e}")).unwrap_or_default()
                        );
                        return (ips, ttl as u32, err);
                    }
                    if cache.serve_stale
                        && (cache.serve_expired_ttl == 0 || cache.serve_expired_ttl < ttl)
                    {
                        tracing::debug!(
                            "app/dns: {} cache OPTIMISTE {fqdn} -> {}{}",
                            cache.name,
                            ip_list(&ips),
                            err.as_ref().map(|e| format!(" > {e}")).unwrap_or_default()
                        );
                        let (me, inst, tag, fqdn) =
                            (self.clone(), inst.clone(), tag.to_owned(), fqdn.clone());
                        tokio::spawn(async move {
                            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
                            me.fetch(&inst, &tag, &fqdn, option, deadline).await;
                        });
                        return (ips, 1, err);
                    }
                }
            }
        } else {
            tracing::debug!(
                "app/dns: DNS cache is disabled. Querying IP for {fqdn} at {}",
                cache.name
            );
        }
        self.fetch(inst, tag, &fqdn, option, deadline).await
    }

    /// fetch: singleflight per FQDN and family set.
    async fn fetch(
        self: &Arc<Self>,
        inst: &Arc<Instance>,
        tag: &str,
        fqdn: &str,
        option: IpOption,
        deadline: tokio::time::Instant,
    ) -> Fetched {
        let key = format!(
            "{fqdn}{}",
            match (option.v4, option.v6) {
                (true, true) => "46",
                (true, false) => "4",
                (false, true) => "6",
                _ => "",
            }
        );
        let waiting = {
            let mut group = self.cache.group.lock().unwrap();
            match group.get(&key) {
                Some(rx) => Err(rx.clone()),
                None => {
                    let (tx, rx) = watch::channel(None);
                    group.insert(key.clone(), rx);
                    Ok(tx)
                }
            }
        };
        match waiting {
            Ok(tx) => {
                let result = self.do_fetch(inst, tag, fqdn, option, deadline).await;
                self.cache.group.lock().unwrap().remove(&key);
                let _ = tx.send(Some(result.clone()));
                result
            }
            Err(mut rx) => loop {
                if let Some(result) = rx.borrow().clone() {
                    return result;
                }
                if rx.changed().await.is_err() {
                    return rx.borrow().clone().unwrap_or((
                        Vec::new(),
                        0,
                        Some(DnsError::Deadline),
                    ));
                }
            },
        }
    }

    fn subscribe(self: &Arc<Self>, key: String) -> Subscriber {
        let (tx, rx) = mpsc::channel(1);
        let id = self.cache.next_sub.fetch_add(1, Ordering::Relaxed);
        self.cache
            .subs
            .lock()
            .unwrap()
            .entry(key.clone())
            .or_default()
            .push((id, tx));
        Subscriber {
            cache: self.clone(),
            key,
            id,
            rx,
        }
    }

    async fn do_fetch(
        self: &Arc<Self>,
        inst: &Arc<Instance>,
        tag: &str,
        fqdn: &str,
        option: IpOption,
        deadline: tokio::time::Instant,
    ) -> Fetched {
        let mut sub4 = option.v4.then(|| self.subscribe(format!("{fqdn}4")));
        let mut sub6 = option.v6.then(|| self.subscribe(format!("{fqdn}6")));
        let (err_tx, mut err_rx) = mpsc::channel(2);
        self.send_query(inst, tag, err_tx, fqdn, option, deadline);
        let mut on_event =
            async |sub: &mut Option<Subscriber>| -> (Option<Arc<IpRecord>>, Option<DnsError>) {
                let Some(sub) = sub else {
                    return (None, None);
                };
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => (None, Some(DnsError::Deadline)),
                    Some(err) = err_rx.recv() => (None, Some(err)),
                    Some(rec) = sub.rx.recv() => (Some(rec), None),
                }
            };
        let (rec4, err4) = on_event(&mut sub4).await;
        let (rec6, err6) = on_event(&mut sub6).await;
        drop((sub4, sub6));
        let errs: Vec<DnsError> = err4.into_iter().chain(err6).collect();
        let (ips, ttl, err) = merge(option, rec4.as_deref(), rec6.as_deref(), errs);
        let ttl = if ttl > 0 {
            ttl as u32
        } else if ttl == 0 && err.as_ref().is_some_and(|e| e.is(&DnsError::NotFound)) {
            0
        } else {
            1
        };
        (ips, ttl, err)
    }

    /// updateRecord: wakes the waiting queries and caches the answer.
    fn update_record(self: &Arc<Self>, req: &Request, rep: IpRecord) {
        let rtt = req.start.elapsed();
        let rep = Arc::new(rep);
        let cache = &self.cache;
        let (key, other) = if req.qtype == TYPE_A {
            ("4", "6")
        } else {
            ("6", "4")
        };
        cache.publish(&format!("{}{key}", req.domain), &rep);
        if cache.disable {
            tracing::info!(
                "app/dns: {} got answer: {} {} -> {}, rtt: {}",
                cache.name,
                req.domain,
                type_name(req.qtype),
                ip_list(&rep.ips),
                go_duration(rtt)
            );
            return;
        }
        let pub_record = {
            let mut ips = cache.ips.lock().unwrap();
            let old = ips.remove(&req.domain).unwrap_or_default();
            let (record, pub_record) = if req.qtype == TYPE_A {
                (
                    Record {
                        a: Some(rep.clone()),
                        aaaa: old.aaaa.clone(),
                    },
                    old.aaaa,
                )
            } else {
                (
                    Record {
                        a: old.a.clone(),
                        aaaa: Some(rep.clone()),
                    },
                    old.a,
                )
            };
            ips.insert(req.domain.clone(), record);
            pub_record
        };
        let lock = req.start.elapsed().saturating_sub(rtt);
        if let Some(rec) = pub_record {
            let (_, ttl, err) = IpRecord::get(Some(&rec));
            if ttl > 0 && !err.is_some_and(|e| e.is(&DnsError::NotFound)) {
                cache.publish(&format!("{}{other}", req.domain), &rec);
            }
        }
        tracing::info!(
            "app/dns: {} got answer: {} {} -> {}, rtt: {}, lock: {}",
            cache.name,
            req.domain,
            type_name(req.qtype),
            ip_list(&rep.ips),
            go_duration(rtt),
            go_duration(lock)
        );
        if (!cache.serve_stale || cache.serve_expired_ttl != 0)
            && !cache.cleaning.swap(true, Ordering::AcqRel)
        {
            let me = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(300)).await;
                    if !me.cache.cleanup() {
                        me.cache.cleaning.store(false, Ordering::Release);
                        return;
                    }
                }
            });
        }
    }

    fn send_query(
        self: &Arc<Self>,
        inst: &Arc<Instance>,
        tag: &str,
        err_tx: mpsc::Sender<DnsError>,
        fqdn: &str,
        option: IpOption,
        deadline: tokio::time::Instant,
    ) {
        let name = &self.cache.name;
        let fail = |err: anyhow::Error| {
            tracing::error!("app/dns: failed to build dns query for {fqdn} > {err:#}");
            for enabled in [option.v4, option.v6] {
                if enabled {
                    let _ = err_tx.try_send(DnsError::Msg(format!("{err:#}")));
                }
            }
        };
        match &self.upstream {
            Upstream::Udp(udp) => {
                tracing::info!("app/dns: {name} querying DNS for: {fqdn}");
                let reqs =
                    match Request::build(fqdn, option, || self.next_id(), edns0(self.client_ip, 0))
                    {
                        Ok(reqs) => reqs,
                        Err(e) => return fail(e),
                    };
                for (id, req) in reqs {
                    let packet = req.msg.clone();
                    udp.add_pending(id, req);
                    self.udp_dispatch(inst, tag, packet);
                }
            }
            Upstream::Tcp { local, dest, port } => {
                tracing::info!("app/dns: {name} querying DNS for: {fqdn}");
                let reqs =
                    match Request::build(fqdn, option, || self.next_id(), edns0(self.client_ip, 0))
                    {
                        Ok(reqs) => reqs,
                        Err(e) => return fail(e),
                    };
                for (_, req) in reqs {
                    let (me, inst, tag, err_tx) =
                        (self.clone(), inst.clone(), tag.to_owned(), err_tx.clone());
                    let (local, dest, port) = (*local, dest.clone(), *port);
                    tokio::spawn(async move {
                        let exchange = async {
                            let mut conn: crate::transport::BoxIo = if local {
                                Box::new(
                                    crate::app::dial_system(&dest, port)
                                        .await
                                        .map_err(|e| ("failed to dial namesever", e.to_string()))?,
                                )
                            } else {
                                let internal = Internal {
                                    tag: tag.clone(),
                                    protocol: "dns",
                                    skip_dns: true,
                                    forced: None,
                                    access: Some(format!("tcp:{dest}:{port}")),
                                    report: None,
                                };
                                inst.dial_internal(internal, dest.clone(), port)
                            };
                            let mut framed = (req.msg.len() as u16).to_be_bytes().to_vec();
                            framed.extend_from_slice(&req.msg);
                            conn.write_all(&framed)
                                .await
                                .map_err(|e| ("failed to send query", e.to_string()))?;
                            let mut len = [0u8; 2];
                            conn.read_exact(&mut len)
                                .await
                                .map_err(|e| ("failed to read response length", e.to_string()))?;
                            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
                            conn.read_exact(&mut body)
                                .await
                                .map_err(|e| ("failed to read response length", e.to_string()))?;
                            parse_response(&body)
                                .map_err(|e| ("failed to parse DNS over TCP response", e))
                        };
                        match tokio::time::timeout_at(deadline, exchange).await {
                            Ok(Ok(rec)) => me.update_record(&req, rec),
                            Ok(Err((what, e))) => {
                                tracing::error!("app/dns: {what} > {e}");
                                let _ = err_tx.try_send(DnsError::Msg(e));
                            }
                            Err(_) => {}
                        }
                    });
                }
            }
            Upstream::Doh(_) => {
                tracing::info!("app/dns: {name} querying: {fqdn}");
                if format!("{name}.") == format!("DOH//{fqdn}") {
                    tracing::error!(
                        "app/dns: {name} tries to resolve itself! Use IP or set \"hosts\" instead"
                    );
                    for enabled in [option.v4, option.v6] {
                        if enabled {
                            let _ = err_tx.try_send(DnsError::Msg(format!(
                                "app/dns: tries to resolve itself!{name}"
                            )));
                        }
                    }
                    return;
                }
                let padding = rand_between(100, 300) as usize;
                let reqs = match Request::build(fqdn, option, || 0, edns0(self.client_ip, padding))
                {
                    Ok(reqs) => reqs,
                    Err(e) => return fail(e),
                };
                for (_, req) in reqs {
                    let (me, inst, tag, err_tx, fqdn) = (
                        self.clone(),
                        inst.clone(),
                        tag.to_owned(),
                        err_tx.clone(),
                        fqdn.to_owned(),
                    );
                    tokio::spawn(async move {
                        let exchange =
                            async {
                                let body =
                                    me.doh_post(&inst, &tag, req.msg.clone()).await.map_err(
                                        |e| ("failed to retrieve response for", format!("{e:#}")),
                                    )?;
                                parse_response(&body)
                                    .map_err(|e| ("failed to handle DOH response for", e))
                            };
                        match tokio::time::timeout_at(deadline, exchange).await {
                            Ok(Ok(rec)) => me.update_record(&req, rec),
                            Ok(Err((what, e))) => {
                                tracing::error!("app/dns: {what} {fqdn} > {e}");
                                let _ = err_tx.try_send(DnsError::Msg(e));
                            }
                            Err(_) => {}
                        }
                    });
                }
            }
        }
    }

    /// udp.Dispatcher.Dispatch: one routed link per server, torn down after a minute without
    /// answers.
    fn udp_dispatch(self: &Arc<Self>, inst: &Arc<Instance>, tag: &str, payload: Vec<u8>) {
        let Upstream::Udp(udp) = &self.upstream else {
            return;
        };
        tracing::debug!(
            "transport/internet/udp: dispatch request to: udp:{}:{}",
            udp.dest,
            udp.port
        );
        let mut conn = udp.conn.lock().unwrap();
        if conn
            .as_ref()
            .is_some_and(|(_, closed)| closed.load(Ordering::Acquire))
        {
            *conn = None;
        }
        if conn.is_none() {
            let destination = format!("udp:{}:{}", udp.dest, udp.port);
            tracing::info!("transport/internet/udp: establishing new connection for {destination}");
            let internal = Internal {
                tag: tag.to_owned(),
                protocol: "",
                skip_dns: false,
                forced: None,
                access: Some(destination),
                report: None,
            };
            let (tx, mut rx) = inst.packets_internal(internal, udp.dest.clone(), udp.port);
            let closed = Arc::new(AtomicBool::new(false));
            let (me, inst, tag, flag) =
                (self.clone(), inst.clone(), tag.to_owned(), closed.clone());
            tokio::spawn(async move {
                while let Ok(Some(packet)) =
                    tokio::time::timeout(Duration::from_secs(60), rx.recv()).await
                {
                    me.handle_udp_response(&inst, &tag, packet.data);
                }
                flag.store(true, Ordering::Release);
                if let Upstream::Udp(udp) = &me.upstream {
                    let mut conn = udp.conn.lock().unwrap();
                    if conn.as_ref().is_some_and(|(_, c)| Arc::ptr_eq(c, &flag)) {
                        *conn = None;
                    }
                }
            });
            *conn = Some((tx, closed));
        }
        let (tx, _) = conn.as_ref().unwrap();
        if tx
            .try_send(Packet {
                data: payload,
                addr: None,
            })
            .is_err()
        {
            tracing::info!(
                "transport/internet/udp: failed to write first UDP payload > io: read/write on closed pipe"
            );
            *conn = None;
        }
    }

    /// HandleResponse: matches the answer to its request, retrying a truncated answer with EDNS0.
    fn handle_udp_response(self: &Arc<Self>, inst: &Arc<Instance>, tag: &str, payload: Vec<u8>) {
        let Upstream::Udp(udp) = &self.upstream else {
            return;
        };
        let name = &self.cache.name;
        let rec = match parse_response(&payload) {
            Ok(rec) => rec,
            Err(e) => {
                tracing::error!("app/dns: {name} fail to parse responded DNS udp > {e}");
                return;
            }
        };
        let Some((req, _)) = udp.requests.lock().unwrap().remove(&rec.req_id) else {
            tracing::error!("app/dns: {name} cannot find the pending request");
            return;
        };
        if rec.truncated && !req.has_opt {
            let id = self.next_id();
            let mut msg = req.msg.clone();
            msg[0..2].copy_from_slice(&id.to_be_bytes());
            msg[10..12].copy_from_slice(&1u16.to_be_bytes());
            msg.extend_from_slice(&opt_record(&[]));
            let retry = Request {
                has_opt: true,
                msg: msg.clone(),
                ..req
            };
            udp.add_pending(id, retry);
            self.udp_dispatch(inst, tag, msg);
            return;
        }
        self.update_record(&req, rec);
    }

    /// dohHTTPSContext over the pooled HTTP/2 connection.
    async fn doh_post(&self, inst: &Arc<Instance>, tag: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let Upstream::Doh(doh) = &self.upstream else {
            bail!("not a DoH server");
        };
        let mut sender = {
            let mut pooled = doh.conn.lock().await;
            let fresh = pooled.as_ref().is_some_and(|(s, used)| {
                !s.is_closed() && used.elapsed() < Duration::from_secs(300)
            });
            if !fresh {
                *pooled = Some((doh.connect(inst, tag).await?, Instant::now()));
            }
            let (sender, used) = pooled.as_mut().unwrap();
            *used = Instant::now();
            sender.clone()
        };
        let mut request = http::Request::post(&doh.url)
            .header("Accept", "application/dns-message")
            .header("Content-Type", "application/dns-message");
        for (k, v) in
            crate::browser::chrome_headers("fetch", |k| matches!(k, "Accept" | "Content-Type"))
        {
            request = request.header(k, v);
        }
        let padding: String = (0..(rand_between(100, 1000) as f64 * 1.249_370_277_078_085_7)
            as usize)
            .map(|_| {
                b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[roll(62)] as char
            })
            .collect();
        let request = request
            .header("X-Padding", padding)
            .header("Accept-Encoding", "gzip")
            .body(http_body_util::Full::new(Bytes::from(body)))?;
        sender.ready().await?;
        let response = sender.send_request(request).await?;
        let status = response.status();
        let gzip = response
            .headers()
            .get("content-encoding")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await?
            .to_bytes();
        ensure!(
            status == 200,
            "DOH server returned code {}",
            status.as_u16()
        );
        if gzip {
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&bytes[..]), &mut out)?;
            return Ok(out);
        }
        Ok(bytes.to_vec())
    }
}

impl Udp {
    fn add_pending(&self, id: u16, req: Request) {
        let now = Instant::now();
        let mut requests = self.requests.lock().unwrap();
        // RequestsCleanup runs each minute in Go; dropping expired entries on insert is equivalent.
        requests.retain(|_, (_, expire)| *expire >= now);
        requests.insert(id, (req, now + Duration::from_secs(8)));
    }
}

impl Doh {
    /// DialTLSContext: routed through the dispatcher (or dialed locally), then uTLS Chrome
    /// unless h2c.
    async fn connect(
        &self,
        inst: &Arc<Instance>,
        tag: &str,
    ) -> Result<hyper::client::conn::http2::SendRequest<http_body_util::Full<Bytes>>> {
        let dest = parse_address(&self.hostname);
        let io: crate::transport::BoxIo = if self.local {
            if let Some(path) = &inst.config.access_log {
                crate::app::write_access(path, &format!("from DNS accepted {} [local]", self.url));
            }
            Box::new(crate::app::dial_system(&dest, self.port).await?)
        } else {
            let internal = Internal {
                tag: tag.to_owned(),
                protocol: "https",
                skip_dns: true,
                forced: None,
                access: Some(self.url.clone()),
                report: None,
            };
            inst.dial_internal(internal, dest, self.port)
        };
        let io = if self.h2c {
            io
        } else {
            let client = crate::tls_client::Client {
                server_name: self.hostname.clone(),
                fingerprint: crate::tls_client::Fingerprint::Chrome,
                alpn: vec!["h2".into(), "http/1.1".into()],
                reality: None,
            };
            crate::tls_client::connect(io, &client).await?.0
        };
        let (sender, conn) =
            hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .timer(hyper_util::rt::TokioTimer::new())
                .keep_alive_interval(Duration::from_secs(45))
                .keep_alive_while_idle(true)
                .handshake(hyper_util::rt::TokioIo::new(io))
                .await?;
        tokio::spawn(conn);
        Ok(sender)
    }
}

enum Server {
    Local,
    Cached(Arc<CachedServer>),
}

/// app/dns Client: one name server with its domain priority and IP filters.
struct Client {
    server: Server,
    name: String,
    skip_fallback: bool,
    final_query: bool,
    expected: Option<IpMatcher>,
    unexpected: Option<IpMatcher>,
    act_prior: bool,
    act_unprior: bool,
    tag: String,
    timeout: Duration,
    v4: bool,
    v6: bool,
    check_system: bool,
    policy_id: u32,
}

/// utils.CheckRoutes: whether IPv4/IPv6 default routes exist (probed once).
fn check_routes() -> (bool, bool) {
    static ROUTES: OnceLock<(bool, bool)> = OnceLock::new();
    *ROUTES.get_or_init(|| {
        let probe = |bind: &str, to: &str| {
            std::net::UdpSocket::bind(bind)
                .and_then(|s| s.connect(to))
                .is_ok()
        };
        (
            probe("0.0.0.0:0", "192.33.4.12:53"),
            probe("[::]:0", "[2001:500:2::c]:53"),
        )
    })
}

/// localdns.Client.LookupIP: the system resolver filtered by family.
async fn system_lookup(domain: &str, option: IpOption) -> Result<(Vec<IpAddr>, u32), DnsError> {
    let ips: Vec<IpAddr> = tokio::net::lookup_host((domain, 0))
        .await
        .map_err(|e| DnsError::Msg(format!("lookup {domain}: {e}")))?
        .map(|a| a.ip().to_canonical())
        .collect();
    let picked: Vec<IpAddr> = ips
        .into_iter()
        .filter(|ip| match (option.v4, option.v6) {
            (true, true) => true,
            (true, false) => ip.is_ipv4(),
            (false, true) => ip.is_ipv6(),
            _ => false,
        })
        .collect();
    if picked.is_empty() || !(option.v4 || option.v6) {
        return Err(DnsError::Empty);
    }
    Ok((picked, DEFAULT_TTL))
}

fn filter_ips(m: &IpMatcher, ips: Vec<IpAddr>) -> (Vec<IpAddr>, Vec<IpAddr>) {
    ips.into_iter().partition(|ip| m.matches(*ip))
}

impl Client {
    /// Client.QueryIP.
    async fn query_ip(
        &self,
        inst: &Arc<Instance>,
        domain: &str,
        mut option: IpOption,
    ) -> Result<(Vec<IpAddr>, u32), DnsError> {
        if self.check_system {
            let (v4, v6) = check_routes();
            option.v4 &= v4;
            option.v6 &= v6;
        } else {
            option.v4 &= self.v4;
            option.v6 &= self.v6;
        }
        if !option.v4 && !option.v6 {
            return Err(DnsError::Empty);
        }
        let deadline = tokio::time::Instant::now() + self.timeout;
        let (mut ips, ttl) = match &self.server {
            Server::Local => {
                let result = tokio::time::timeout_at(deadline, system_lookup(domain, option))
                    .await
                    .unwrap_or(Err(DnsError::Deadline));
                if let Ok((ips, _)) = &result {
                    tracing::info!(
                        "app/dns: Localhost got answer: {domain} -> {}",
                        ip_list(ips)
                    );
                }
                result?
            }
            Server::Cached(server) => {
                let (ips, ttl, err) = server
                    .query(inst, &self.tag, domain, option, deadline)
                    .await;
                if let Some(err) = err {
                    return Err(err);
                }
                (ips, ttl)
            }
        };
        if ips.is_empty() {
            return Err(DnsError::Empty);
        }
        if let Some(m) = &self.expected
            && !self.act_prior
        {
            ips = filter_ips(m, ips).0;
            tracing::debug!(
                "app/dns: domain {domain} expectedIPs {} matched at server {}",
                ip_list(&ips),
                self.name
            );
            if ips.is_empty() {
                return Err(DnsError::Empty);
            }
        }
        if let Some(m) = &self.unexpected
            && !self.act_unprior
        {
            ips = filter_ips(m, ips).1;
            tracing::debug!(
                "app/dns: domain {domain} unexpectedIPs {} matched at server {}",
                ip_list(&ips),
                self.name
            );
            if ips.is_empty() {
                return Err(DnsError::Empty);
            }
        }
        if let Some(m) = &self.expected
            && self.act_prior
        {
            let prior = filter_ips(m, ips.clone()).0;
            if !prior.is_empty() {
                ips = prior;
                tracing::debug!(
                    "app/dns: domain {domain} priorIPs {} matched at server {}",
                    ip_list(&ips),
                    self.name
                );
            }
        }
        if let Some(m) = &self.unexpected
            && self.act_unprior
        {
            let rest = filter_ips(m, ips.clone()).1;
            if !rest.is_empty() {
                ips = rest;
                tracing::debug!(
                    "app/dns: domain {domain} unpriorIPs {} matched at server {}",
                    ip_list(&ips),
                    self.name
                );
            }
        }
        Ok((ips, ttl))
    }
}

enum HostRep {
    Ip(IpAddr),
    Domain(String),
    RCode(u16),
}

/// StaticHosts.
#[derive(Default)]
struct Hosts(Vec<(DomainMatcher, Vec<HostRep>)>);

enum HostAnswer {
    Ips(Vec<IpAddr>),
    Domain(String),
}

impl Hosts {
    fn lookup_internal(&self, domain: &str) -> Result<Option<Vec<&HostRep>>, DnsError> {
        let mut found = None::<Vec<&HostRep>>;
        for (m, reps) in &self.0 {
            if !m.matches(domain) {
                continue;
            }
            for rep in reps {
                if let HostRep::RCode(code) = rep {
                    return Err(if *code == 0 {
                        DnsError::Empty
                    } else {
                        DnsError::RCode(*code)
                    });
                }
            }
            found.get_or_insert_default().extend(reps);
        }
        Ok(found)
    }

    fn lookup(
        &self,
        domain: &str,
        option: IpOption,
        depth: u32,
    ) -> Result<Option<HostAnswer>, DnsError> {
        let domain = domain.to_lowercase();
        let Some(reps) = self.lookup_internal(&domain)? else {
            return Ok(None);
        };
        if let [HostRep::Domain(next)] = reps.as_slice() {
            tracing::debug!("app/dns: found replaced domain: {domain} -> {next}. Try to unwrap it");
            if depth > 0
                && let Some(unwrapped) = self.lookup(next, option, depth - 1)?
            {
                return Ok(Some(unwrapped));
            }
            return Ok(Some(HostAnswer::Domain(next.clone())));
        }
        Ok(Some(HostAnswer::Ips(
            reps.iter()
                .filter_map(|r| match r {
                    HostRep::Ip(ip)
                        if (ip.is_ipv4() && option.v4) || (ip.is_ipv6() && option.v6) =>
                    {
                        Some(*ip)
                    }
                    _ => None,
                })
                .collect(),
        )))
    }
}

/// The DNS feature: app/dns when configured, otherwise features/dns/localdns.
#[derive(Default)]
pub struct Dns {
    configured: bool,
    hosts: Hosts,
    clients: Vec<Client>,
    /// matcherInfos with their rules, in match-index order.
    rules: Vec<(usize, String, DomainMatcher)>,
    v4: bool,
    v6: bool,
    check_system: bool,
    disable_fallback: bool,
    disable_fallback_if_match: bool,
    parallel: bool,
    /// Lines Go logs while building the clients, printed once logging is up.
    created: Vec<String>,
}

/// resolveQueryStrategy: (v4, v6, useSystem); unknown names mean UseIP.
fn query_strategy(s: &str) -> (bool, bool, bool) {
    match s.to_lowercase().as_str() {
        "useip4" | "useipv4" | "use_ip4" | "use_ipv4" | "use_ip_v4" | "use-ip4" | "use-ipv4"
        | "use-ip-v4" => (true, false, false),
        "useip6" | "useipv6" | "use_ip6" | "use_ipv6" | "use_ip_v6" | "use-ip6" | "use-ipv6"
        | "use-ip-v6" => (false, true, false),
        "usesys" | "usesystem" | "use_sys" | "use_system" | "use-sys" | "use-system" => {
            (true, true, true)
        }
        _ => (true, true, false),
    }
}

/// The conf Address JSON: a string parsed by net.ParseAddress.
fn address(v: &Value, path: &str) -> Result<Option<Address>> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(parse_address(s))),
        _ => bail!("{path}: invalid address"),
    }
}

fn client_ip(v: &Value, path: &str) -> Result<Option<IpAddr>> {
    match address(v, path)? {
        None => Ok(None),
        Some(Address::Ip(ip)) => Ok(Some(ip)),
        Some(Address::Domain(d)) => bail!("not an IP address:{d}"),
    }
}

fn opt_bool(v: &Value, path: &str) -> Result<Option<bool>> {
    match v {
        Value::Null => Ok(None),
        Value::Bool(b) => Ok(Some(*b)),
        _ => bail!("{path} must be a boolean"),
    }
}

fn opt_u64(v: &Value, path: &str) -> Result<Option<u64>> {
    match v {
        Value::Null => Ok(None),
        v => v
            .as_u64()
            .map(Some)
            .with_context(|| format!("{path} must be a non-negative integer")),
    }
}

/// A URL split the way net/url does for the parts the name servers use.
struct Url {
    scheme: String,
    host: String,
    hostname: String,
    port: Option<u16>,
    rest: String,
}

fn parse_url(s: &str) -> Option<Url> {
    let (scheme, rest) = s.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = &rest[..end];
    let (hostname, port) = if let Some(v6) = host.strip_prefix('[') {
        let (h, tail) = v6.split_once(']')?;
        (h.to_owned(), tail.strip_prefix(':'))
    } else {
        match host.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), Some(p)),
            None => (host.to_owned(), None),
        }
    };
    let port = match port {
        Some("") | None => None,
        Some(p) => Some(p.parse().ok()?),
    };
    Some(Url {
        scheme: scheme.to_lowercase(),
        host: host.to_owned(),
        hostname,
        port,
        rest: rest.to_owned(),
    })
}

fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// infra/conf readSystemHostsFrom.
fn system_hosts(text: &str) -> Vec<(String, Vec<IpAddr>)> {
    let mut hosts: Vec<(String, Vec<IpAddr>)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let line = line.split('#').next().unwrap_or_default();
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let Address::Ip(ip) = parse_address(fields[0]) else {
            continue;
        };
        for name in &fields[1..] {
            let domain = name.trim_end_matches('.').to_lowercase();
            match hosts.iter_mut().find(|(d, _)| *d == domain) {
                Some((_, ips)) => ips.push(ip),
                None => hosts.push((domain, vec![ip])),
            }
        }
    }
    hosts
}

impl Dns {
    pub fn parse(value: &Value, loader: &mut Loader) -> Result<Self> {
        if value.is_null() {
            return Ok(Self::default());
        }
        keys(
            value,
            &[
                "servers",
                "script",
                "hosts",
                "clientIp",
                "tag",
                "queryStrategy",
                "disableCache",
                "serveStale",
                "serveExpiredTTL",
                "disableFallback",
                "disableFallbackIfMatch",
                "enableParallelQuery",
                "useSystemHosts",
            ],
            "dns",
        )?;
        if value["script"].as_str().is_some_and(|s| !s.is_empty()) {
            return Err(unsupported("dns.script"));
        }
        let flag = |k: &str| -> Result<bool> {
            Ok(opt_bool(&value[k], &format!("dns.{k}"))?.unwrap_or(false))
        };
        let global_ip = client_ip(&value["clientIp"], "dns.clientIp")?;
        let (v4, v6, check_system) =
            query_strategy(value["queryStrategy"].as_str().unwrap_or_default());
        let disable_cache = flag("disableCache")?;
        let serve_stale = flag("serveStale")?;
        let serve_expired_ttl =
            opt_u64(&value["serveExpiredTTL"], "dns.serveExpiredTTL")?.unwrap_or(0) as u32;
        let default_tag = match value["tag"].as_str() {
            Some(t) if !t.is_empty() => t.to_owned(),
            _ => format!("xray.system.{}", uuid_v4()),
        };
        let mut dns = Dns {
            configured: true,
            v4,
            v6,
            check_system,
            disable_fallback: flag("disableFallback")?,
            disable_fallback_if_match: flag("disableFallbackIfMatch")?,
            parallel: flag("enableParallelQuery")?,
            ..Default::default()
        };
        let mut policies: HashMap<String, u32> = HashMap::new();
        for (i, raw) in value["servers"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let p = format!("dns.servers[{i}]");
            let ns = match raw {
                Value::String(_) => serde_json::json!({ "address": raw }),
                Value::Object(_) => raw.clone(),
                _ => bail!("failed to parse name server: {raw}"),
            };
            keys(
                &ns,
                &[
                    "id",
                    "address",
                    "clientIp",
                    "port",
                    "skipFallback",
                    "domains",
                    "expectedIPs",
                    "expectIPs",
                    "queryStrategy",
                    "tag",
                    "timeoutMs",
                    "disableCache",
                    "serveStale",
                    "serveExpiredTTL",
                    "finalQuery",
                    "unexpectedIPs",
                ],
                &p,
            )?;
            let addr = address(&ns["address"], &format!("{p}.address"))?
                .context("failed to build nameserver > nameserver address is not specified")?;
            let port = match opt_u64(&ns["port"], &format!("{p}.port"))? {
                Some(port) if port <= 65535 => port as u16,
                None => 0,
                Some(_) => bail!("{p}.port must be at most 65535"),
            };
            let list = |k: &str| string_list(&ns[k], &format!("{p}.{k}"));
            let domains = list("domains")?;
            let mut expected = list("expectedIPs")?;
            let expect = list("expectIPs")?;
            if expected.is_empty() {
                expected = expect.clone();
            }
            let unexpected = list("unexpectedIPs")?;
            let act_prior = expected.iter().any(|s| s == "*");
            let act_unprior = unexpected.iter().any(|s| s == "*");
            let expected: Vec<String> = expected.into_iter().filter(|s| s != "*").collect();
            let unexpected_ips: Vec<String> =
                unexpected.iter().filter(|s| *s != "*").cloned().collect();
            let ns_ip = client_ip(&ns["clientIp"], &format!("{p}.clientIp"))?;
            let ns_strategy = ns["queryStrategy"].as_str().unwrap_or_default();
            let ns_tag = ns["tag"].as_str().unwrap_or_default();
            let skip_fallback =
                opt_bool(&ns["skipFallback"], &format!("{p}.skipFallback"))?.unwrap_or(false);
            // buildPolicyID: servers with equal rule settings race as one group.
            let policy_key = {
                let write_list = |tag: &str, l: &[String]| {
                    let mut cp: Vec<String> = l.iter().map(|s| s.trim().to_lowercase()).collect();
                    cp.sort();
                    format!(
                        "{tag}={}|",
                        if cp.is_empty() {
                            "[]".into()
                        } else {
                            cp.join(",")
                        }
                    )
                };
                format!(
                    "client={}|skip={}|qs={}|tag={}|{}{}{}{}",
                    ns_ip.map(|ip| ip.to_string()).unwrap_or("none".into()),
                    skip_fallback as u8,
                    ns_strategy.trim().to_lowercase(),
                    ns_tag.trim().to_lowercase(),
                    write_list("domains", &domains),
                    write_list("expected", &list("expectedIPs")?),
                    write_list("expect", &expect),
                    write_list("unexpected", &unexpected),
                )
            };
            let next = policies.len() as u32 + 1;
            let policy_id = *policies.entry(policy_key).or_insert(next);
            let my_ip = ns_ip.or(global_ip);
            let disable = opt_bool(&ns["disableCache"], &format!("{p}.disableCache"))?
                .unwrap_or(disable_cache);
            let stale =
                opt_bool(&ns["serveStale"], &format!("{p}.serveStale"))?.unwrap_or(serve_stale);
            let expired_ttl = opt_u64(&ns["serveExpiredTTL"], &format!("{p}.serveExpiredTTL"))?
                .map(|v| v as u32)
                .unwrap_or(serve_expired_ttl);
            let tag = if ns_tag.is_empty() {
                default_tag.clone()
            } else {
                ns_tag.to_owned()
            };
            let (s4, s6, s_sys) = query_strategy(ns_strategy);
            // ResolveIpOptionOverride.
            let (c4, c6) = match (s4, s6, s_sys) {
                (true, false, _) => (v4, false),
                (false, true, _) => (false, v6),
                _ => (v4, v6),
            };
            ensure!(c4 || c6, "no QueryStrategy available for {addr}");
            let (server, name) = dns.server(&addr, port, my_ip, disable, stale, expired_ttl, &p)?;
            let client_idx = dns.clients.len();
            if matches!(server, Server::Local) {
                for rule in [
                    "regexp:^[^.]+$",
                    "domain:local",
                    "domain:localdomain",
                    "domain:localhost",
                    "domain:lan",
                    "domain:home.arpa",
                    "domain:example",
                    "domain:invalid",
                    "domain:test",
                ] {
                    let m = DomainMatcher::parse(&[rule.to_owned()], Kind::Substr, loader)?;
                    dns.rules.push((client_idx, rule.to_owned(), m));
                }
            }
            for rule in &domains {
                let m = DomainMatcher::parse(std::slice::from_ref(rule), Kind::Substr, loader)?;
                dns.rules.push((client_idx, rule.clone(), m));
            }
            if let Some(ip) = my_ip {
                dns.created
                    .push(format!("DNS: client {addr} uses clientIP {ip}"));
            }
            let mut matcher = |l: Vec<String>| -> Result<Option<IpMatcher>> {
                if l.is_empty() {
                    Ok(None)
                } else {
                    IpMatcher::parse(&l, loader).map(Some)
                }
            };
            let timeout = match opt_u64(&ns["timeoutMs"], &format!("{p}.timeoutMs"))? {
                Some(ms) if ms > 0 => Duration::from_millis(ms),
                _ => Duration::from_millis(4000),
            };
            dns.clients.push(Client {
                server,
                name,
                skip_fallback,
                final_query: opt_bool(&ns["finalQuery"], &format!("{p}.finalQuery"))?
                    .unwrap_or(false),
                expected: matcher(expected)?,
                unexpected: matcher(unexpected_ips)?,
                act_prior,
                act_unprior,
                tag,
                timeout,
                v4: c4,
                v6: c6,
                check_system: s_sys,
                policy_id,
            });
        }
        if dns.clients.is_empty() {
            dns.created.push("DNS: created localhost client".into());
            dns.clients.push(Client {
                server: Server::Local,
                name: "localhost".into(),
                skip_fallback: false,
                final_query: false,
                expected: None,
                unexpected: None,
                act_prior: false,
                act_unprior: false,
                tag: String::new(),
                timeout: Duration::ZERO,
                v4,
                v6,
                check_system: false,
                policy_id: 0,
            });
        }
        let mut hosts: Vec<(String, Vec<HostRep>)> = Vec::new();
        if let Some(map) = value["hosts"].as_object() {
            for (rule, v) in map {
                let one = |s: &str| match parse_address(s) {
                    Address::Ip(ip) => Ok(HostRep::Ip(ip)),
                    Address::Domain(d) => match d.strip_prefix('#') {
                        Some(code) => code
                            .parse::<i64>()
                            .map(|c| HostRep::RCode(c as u16))
                            .map_err(|e| anyhow::anyhow!("failed to build hosts > {e}")),
                        None => Ok(HostRep::Domain(d)),
                    },
                };
                let reps = match v {
                    Value::String(s) => vec![one(s)?],
                    Value::Array(items) => {
                        let mut ips = Vec::new();
                        let mut proxied = None;
                        for item in items {
                            let s = item
                                .as_str()
                                .context("invalid DNS hosts > invalid address")?;
                            match one(s)? {
                                HostRep::Ip(ip) => ips.push(HostRep::Ip(ip)),
                                other => {
                                    proxied = Some(other);
                                    break;
                                }
                            }
                        }
                        proxied.map(|p| vec![p]).unwrap_or(ips)
                    }
                    _ => bail!("invalid DNS hosts > invalid address"),
                };
                hosts.push((rule.clone(), reps));
            }
        }
        if flag("useSystemHosts")? {
            let text =
                std::fs::read_to_string("/etc/hosts").context("failed to read system hosts")?;
            for (domain, ips) in system_hosts(&text) {
                hosts.push((domain, ips.into_iter().map(HostRep::Ip).collect()));
            }
        }
        for (rule, reps) in hosts {
            let m = DomainMatcher::parse(&[rule], Kind::Full, loader)
                .context("failed to build hosts")?;
            dns.hosts.0.push((m, reps));
        }
        Ok(dns)
    }

    /// NewServer: the name server kind from the address and its log name.
    #[allow(clippy::too_many_arguments)]
    fn server(
        &mut self,
        addr: &Address,
        port: u16,
        client_ip: Option<IpAddr>,
        disable: bool,
        stale: bool,
        expired_ttl: u32,
        path: &str,
    ) -> Result<(Server, String)> {
        let cached = |name: String, upstream: Upstream| {
            let server = CachedServer {
                cache: Cache::new(name.clone(), disable, stale, expired_ttl),
                upstream,
                client_ip,
                req_id: AtomicU32::new(0),
            };
            (Server::Cached(Arc::new(server)), name)
        };
        if let Address::Domain(d) = addr {
            if d.eq_ignore_ascii_case("localhost") {
                self.created.push("DNS: created localhost client".into());
                return Ok((Server::Local, "localhost".into()));
            }
            if d.eq_ignore_ascii_case("fakedns") {
                return Err(unsupported(&format!("{path}.address fakedns")));
            }
            if let Some(url) = parse_url(d) {
                match url.scheme.as_str() {
                    "https" | "h2c" | "https+local" | "h2c+local" => {
                        let local = url.scheme.ends_with("+local");
                        let h2c = url.scheme.starts_with("h2c");
                        let mode = if local { "DOHL" } else { "DOH" };
                        let doh_url = format!("https://{}", url.rest);
                        self.created.push(format!(
                            "DNS: created {mode} client for {doh_url}, with h2c {h2c}"
                        ));
                        return Ok(cached(
                            format!("{mode}//{}", url.host),
                            Upstream::Doh(Doh {
                                url: doh_url,
                                hostname: url.hostname.clone(),
                                port: url.port.unwrap_or(443),
                                h2c,
                                local,
                                conn: tokio::sync::Mutex::new(None),
                            }),
                        ));
                    }
                    "quic+local" => {
                        return Err(unsupported(&format!("{path}.address quic+local")));
                    }
                    "tcp" | "tcp+local" => {
                        let local = url.scheme == "tcp+local";
                        let dest = parse_address(&url.hostname);
                        let tcp_port = url.port.unwrap_or(53);
                        self.created.push(format!(
                            "DNS: created {}TCP client initialized for {d}",
                            if local { "Local " } else { "" }
                        ));
                        let net_addr = format!("{dest}:{tcp_port}");
                        return Ok(cached(
                            format!("{}//{net_addr}", if local { "TCPL" } else { "TCP" }),
                            Upstream::Tcp {
                                local,
                                dest,
                                port: tcp_port,
                            },
                        ));
                    }
                    _ => {}
                }
            }
        }
        let port = if port == 0 { 53 } else { port };
        self.created.push(format!(
            "DNS: created UDP client initialized for {addr}:{port}"
        ));
        Ok(cached(
            format!("udp:{addr}:{port}").to_uppercase(),
            Upstream::Udp(Udp {
                dest: addr.clone(),
                port,
                requests: Mutex::default(),
                conn: Mutex::new(None),
            }),
        ))
    }

    /// Prints the client creation lines Go logs while loading the config.
    pub fn log_created(&self) {
        for line in &self.created {
            tracing::info!("app/dns: {line}");
        }
    }

    /// IsOwnLink: whether `tag` is the inbound tag of one of this module's queries.
    pub fn is_own_link(&self, tag: &str) -> bool {
        self.configured && self.clients.iter().any(|c| c.tag == tag)
    }

    /// DNS.LookupIP (or localdns.Client.LookupIP when no `dns` section exists).
    pub async fn lookup_ip(
        &self,
        inst: &Arc<Instance>,
        domain: &str,
        mut option: IpOption,
    ) -> Result<(Vec<IpAddr>, u32), DnsError> {
        if !self.configured {
            return system_lookup(domain, option).await;
        }
        let mut domain = domain.strip_suffix('.').unwrap_or(domain).to_owned();
        if domain.is_empty() {
            return Err(DnsError::Msg("app/dns: empty domain name".into()));
        }
        if self.check_system {
            let (v4, v6) = check_routes();
            option.v4 &= v4;
            option.v6 &= v6;
        } else {
            option.v4 &= self.v4;
            option.v6 &= self.v6;
        }
        if !option.v4 && !option.v6 {
            return Err(DnsError::Empty);
        }
        match self.hosts.lookup(&domain, option, 5) {
            Err(e) if e.is(&DnsError::Empty) => return Err(DnsError::Empty),
            Err(e) => {
                return Err(DnsError::wrap(
                    format!("app/dns: returning nil for domain {domain}"),
                    e,
                ));
            }
            Ok(None) => {}
            Ok(Some(HostAnswer::Ips(ips))) if ips.is_empty() => return Err(DnsError::Empty),
            Ok(Some(HostAnswer::Domain(next))) => {
                tracing::info!("app/dns: domain replaced: {domain} -> {next}");
                domain = next;
            }
            Ok(Some(HostAnswer::Ips(ips))) => {
                tracing::info!(
                    "app/dns: returning {} IP(s) for domain {domain} -> {}",
                    ips.len(),
                    ip_list(&ips)
                );
                return Ok((ips, 10));
            }
        }
        if self.parallel {
            self.parallel_query(inst, &domain, option).await
        } else {
            self.serial_query(inst, &domain, option).await
        }
    }

    /// sortClients: domain-matched servers first (in rule order), then the fallback ones.
    fn sort_clients(&self, domain: &str) -> Vec<usize> {
        let mut order = Vec::new();
        let mut used = vec![false; self.clients.len()];
        let mut names = Vec::new();
        let mut matched_rules = Vec::new();
        let mut has_match = false;
        let decided = |domain: &str, rules: &[String], names: &[String]| {
            if !rules.is_empty() {
                tracing::debug!(
                    "app/dns: domain {domain} matches following rules: [{}]",
                    rules.join(" ")
                );
            }
            if !names.is_empty() {
                tracing::debug!(
                    "app/dns: domain {domain} will use DNS in order: [{}]",
                    names.join(" ")
                );
            }
        };
        let lower = domain.to_lowercase();
        for (idx, rule, m) in &self.rules {
            if !m.matches(&lower) {
                continue;
            }
            matched_rules.push(format!("{rule}(DNS idx:{idx})"));
            if used[*idx] {
                continue;
            }
            used[*idx] = true;
            order.push(*idx);
            names.push(self.clients[*idx].name.clone());
            has_match = true;
            if self.clients[*idx].final_query {
                decided(domain, &matched_rules, &names);
                return order;
            }
        }
        if !(self.disable_fallback || self.disable_fallback_if_match && has_match) {
            for (idx, client) in self.clients.iter().enumerate() {
                if used[idx] || client.skip_fallback {
                    continue;
                }
                used[idx] = true;
                order.push(idx);
                names.push(client.name.clone());
                if client.final_query {
                    decided(domain, &matched_rules, &names);
                    return order;
                }
            }
        }
        decided(domain, &matched_rules, &names);
        if order.is_empty() {
            order.push(0);
            tracing::warn!(
                "app/dns: domain {domain} will use the first DNS: [{}]",
                self.clients[0].name
            );
        }
        order
    }

    async fn serial_query(
        &self,
        inst: &Arc<Instance>,
        domain: &str,
        option: IpOption,
    ) -> Result<(Vec<IpAddr>, u32), DnsError> {
        let mut errs = Vec::new();
        for idx in self.sort_clients(domain) {
            let client = &self.clients[idx];
            match client.query_ip(inst, domain, option).await {
                Ok((ips, ttl)) if !ips.is_empty() => return Ok((ips, ttl)),
                result => {
                    let err = result.err().unwrap_or(DnsError::Empty);
                    tracing::info!(
                        "app/dns: failed to lookup ip for domain {domain} at server {} in serial query mode > {err}",
                        client.name
                    );
                    errs.push(err);
                }
            }
        }
        Err(merge_query_errors(domain, errs))
    }

    async fn parallel_query(
        &self,
        inst: &Arc<Instance>,
        domain: &str,
        option: IpOption,
    ) -> Result<(Vec<IpAddr>, u32), DnsError> {
        let order = self.sort_clients(domain);
        let (tx, mut rx) = mpsc::channel(order.len().max(1));
        for (i, idx) in order.iter().copied().enumerate() {
            let (inst, tx, domain) = (inst.clone(), tx.clone(), domain.to_owned());
            // Queries keep running after a winner returns, so their answers still fill the cache.
            tokio::spawn(async move {
                let client = &inst.config.dns.clients[idx];
                let result = client.query_ip(&inst, &domain, option).await;
                let _ = tx.send((i, result)).await;
            });
        }
        drop(tx);
        // makeGroups: adjacent servers with the same policy race as one group.
        let mut groups: Vec<(usize, usize)> = Vec::new();
        for (i, idx) in order.iter().enumerate() {
            let pid = self.clients[*idx].policy_id;
            match groups.last_mut() {
                Some((_, end)) if self.clients[order[*end]].policy_id == pid => *end = i,
                _ => groups.push((i, i)),
            }
        }
        let group_of: Vec<usize> = (0..order.len())
            .map(|i| {
                groups
                    .iter()
                    .position(|(s, e)| (*s..=*e).contains(&i))
                    .unwrap()
            })
            .collect();
        let mut pending: Vec<usize> = groups.iter().map(|(s, e)| e - s + 1).collect();
        let mut results: Vec<Option<Answer>> = (0..order.len()).map(|_| None).collect();
        let mut errs = Vec::new();
        let mut next_group = 0;
        while let Some((i, result)) = rx.recv().await {
            results[i] = Some(result);
            pending[group_of[i]] -= 1;
            while next_group < groups.len() {
                let (start, end) = groups[next_group];
                for r in results[start..=end].iter().flatten() {
                    if let Ok((ips, ttl)) = r
                        && !ips.is_empty()
                    {
                        return Ok((ips.clone(), *ttl));
                    }
                }
                if pending[next_group] > 0 {
                    break;
                }
                for j in start..=end {
                    let err = match results[j].take() {
                        Some(Err(e)) => e,
                        _ => DnsError::Empty,
                    };
                    tracing::info!(
                        "app/dns: failed to lookup ip for domain {domain} at server {} in parallel query mode > {err}",
                        self.clients[order[j]].name
                    );
                    errs.push(err);
                }
                next_group += 1;
            }
        }
        Err(merge_query_errors(domain, errs))
    }

    /// internet.LookupForIP with no source address, for sockopt/freedom domainStrategy.
    pub async fn lookup_for_ip(
        &self,
        inst: &Arc<Instance>,
        domain: &str,
        strategy: Strategy,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let [_, prefer, fallback] = strategy.0;
        let mut result = self
            .lookup_ip(
                inst,
                domain,
                IpOption {
                    v4: prefer == 4 || prefer == 0,
                    v6: prefer == 6 || prefer == 0,
                },
            )
            .await;
        if fallback != 0 && result.as_ref().is_ok_and(|(ips, _)| ips.is_empty())
            || fallback != 0 && result.is_err()
        {
            result = self
                .lookup_ip(
                    inst,
                    domain,
                    IpOption {
                        v4: fallback == 4,
                        v6: fallback == 6,
                    },
                )
                .await;
        }
        match result {
            Ok((ips, _)) if ips.is_empty() => Err(DnsError::Empty),
            Ok((ips, _)) => Ok(ips),
            Err(e) => Err(e),
        }
    }
}

/// internet.DomainStrategy as (use/force, preferred family, fallback family).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Strategy(pub [u8; 3]);

impl Strategy {
    pub fn parse(s: &str) -> Option<Self> {
        Some(Self(match s {
            "AsIs" | "" => [0, 0, 0],
            "UseIP" => [1, 0, 0],
            "UseIPv4" => [1, 4, 0],
            "UseIPv6" => [1, 6, 0],
            "UseIPv4v6" => [1, 4, 6],
            "UseIPv6v4" => [1, 6, 4],
            "ForceIP" => [2, 0, 0],
            "ForceIPv4" => [2, 4, 0],
            "ForceIPv6" => [2, 6, 0],
            "ForceIPv4v6" => [2, 4, 6],
            "ForceIPv6v4" => [2, 6, 4],
            _ => return None,
        }))
    }
    pub fn has_strategy(self) -> bool {
        self.0[0] != 0
    }
    pub fn force(self) -> bool {
        self.0[0] == 2
    }
}

/// mergeQueryErrors.
fn merge_query_errors(domain: &str, errs: Vec<DnsError>) -> DnsError {
    if errs.is_empty() {
        return DnsError::Empty;
    }
    let mut first: Option<&DnsError> = None;
    for err in &errs {
        if err.is(&DnsError::NotFound) {
            continue;
        }
        match first {
            None => first = Some(err),
            Some(f) if !err.is(f) => {
                return DnsError::wrap(
                    format!("app/dns: returning nil for domain {domain}"),
                    DnsError::Multi(errs.clone()),
                );
            }
            _ => {}
        }
    }
    match first {
        Some(f) if f.is(&DnsError::Empty) => DnsError::Empty,
        Some(f) => DnsError::wrap(
            format!("app/dns: returning nil for domain {domain}"),
            f.clone(),
        ),
        None => DnsError::wrap(
            format!("app/dns: returning nil for domain {domain}"),
            DnsError::NotFound,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_duration_formats_like_time_duration() {
        assert_eq!(go_duration(Duration::ZERO), "0s");
        assert_eq!(go_duration(Duration::from_nanos(500)), "500ns");
        assert_eq!(go_duration(Duration::from_nanos(1_250)), "1.25µs");
        assert_eq!(go_duration(Duration::from_micros(23_456_789)), "23.456789s");
        assert_eq!(go_duration(Duration::from_nanos(23_456_789)), "23.456789ms");
        assert_eq!(go_duration(Duration::from_secs(3600)), "1h0m0s");
        assert_eq!(go_duration(Duration::from_millis(61_500)), "1m1.5s");
    }

    #[test]
    fn query_matches_dnsmessage_pack_with_edns0() {
        let opt = edns0(Some("203.0.113.77".parse().unwrap()), 0).unwrap();
        let q = build_query(7, "example.com.", TYPE_A, Some(&opt)).unwrap();
        assert_eq!(&q[..12], &[0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
        let tail = &q[q.len() - opt.len()..];
        // root, OPT, class 1350, TTL 0xe0008000, ECS family 1 /24 with three address bytes.
        assert_eq!(
            tail,
            &[
                0, 0, 41, 5, 70, 0xe0, 0, 0x80, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 0, 203, 0, 113
            ]
        );
        assert!(build_query(1, "a..b.", TYPE_A, None).is_err());
    }

    #[test]
    fn response_parsing_keeps_a_and_aaaa_and_min_ttl() {
        let mut m = vec![0, 9, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        put_name(&mut m, "x.example.").unwrap();
        m.extend_from_slice(&[0, 1, 0, 1]);
        for (t, ttl, data) in [
            (5u16, 50u32, vec![1, b'y', 0xc0, 12]),
            (1, 600, vec![192, 0, 2, 1]),
            (
                28,
                0,
                [0u8; 10]
                    .iter()
                    .chain(&[0xff, 0xff, 1, 2, 3, 4])
                    .copied()
                    .collect(),
            ),
        ] {
            m.extend_from_slice(&[0xc0, 12]);
            put16(&mut m, t);
            put16(&mut m, 1);
            m.extend_from_slice(&ttl.to_be_bytes());
            put16(&mut m, data.len() as u16);
            m.extend_from_slice(&data);
        }
        let rec = parse_response(&m).unwrap();
        assert_eq!(rec.req_id, 9);
        // The v4-mapped AAAA answer is dropped, as net.IPAddress + the length check do.
        assert_eq!(rec.ips, vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
        // TTL 0 counts as 1 second, and the CNAME's TTL takes part in the minimum.
        assert!(rec.expire <= Instant::now() + Duration::from_secs(1));
    }

    #[test]
    fn merge_reports_record_not_found_on_timeouts() {
        let both = IpOption { v4: true, v6: true };
        let (ips, ttl, err) = merge(
            both,
            None,
            None,
            vec![DnsError::Deadline, DnsError::Deadline],
        );
        assert!(ips.is_empty() && ttl == 0);
        assert!(err.unwrap().is(&DnsError::NotFound));
        let e = merge_query_errors("a.com", vec![DnsError::NotFound]);
        assert_eq!(
            e.to_string(),
            "app/dns: returning nil for domain a.com > app/dns: record not found"
        );
        assert!(
            merge_query_errors("a.com", vec![DnsError::Empty, DnsError::NotFound])
                .is(&DnsError::Empty)
        );
    }

    #[test]
    fn hosts_unwrap_domains_and_rcodes() {
        let mut loader = Loader::default();
        let dns = Dns::parse(
            &serde_json::json!({
                "hosts": {"a.com": "b.com", "b.com": ["10.0.0.1", "::1"], "blocked.com": "#3",
                          "domain:empty.com": "#0"},
                "servers": ["1.1.1.1", {"address": "localhost", "domains": ["full:x.y"]}]
            }),
            &mut loader,
        )
        .unwrap();
        let v4 = IpOption {
            v4: true,
            v6: false,
        };
        match dns.hosts.lookup("A.com", v4, 5).unwrap() {
            Some(HostAnswer::Ips(ips)) => {
                assert_eq!(ips, vec!["10.0.0.1".parse::<IpAddr>().unwrap()])
            }
            _ => panic!("expected IPs"),
        }
        assert_eq!(
            dns.hosts
                .lookup("blocked.com", v4, 5)
                .err()
                .unwrap()
                .rcode(),
            3
        );
        assert!(
            dns.hosts
                .lookup("x.empty.com", v4, 5)
                .err()
                .unwrap()
                .is(&DnsError::Empty)
        );
        // The localhost server gets the local-TLD rules before its own domains.
        assert_eq!(dns.sort_clients("printer"), vec![1, 0]);
        assert_eq!(dns.sort_clients("x.y"), vec![1, 0]);
        assert_eq!(dns.sort_clients("z.com"), vec![0, 1]);
        assert_eq!(dns.clients[0].name, "UDP:1.1.1.1:53");
    }

    #[test]
    fn server_urls_pick_go_names() {
        let mut loader = Loader::default();
        let dns = Dns::parse(
            &serde_json::json!({"servers": [
                "https://dns.google/dns-query", "https+local://1.1.1.1/dns-query",
                "tcp://8.8.8.8:5353", "tcp+local://9.9.9.9", "h2c://doh.local:8053/q",
                {"address": "2001:db8::1", "port": 5353}
            ]}),
            &mut loader,
        )
        .unwrap();
        let names: Vec<&str> = dns.clients.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "DOH//dns.google",
                "DOHL//1.1.1.1",
                "TCP//8.8.8.8:5353",
                "TCPL//9.9.9.9:53",
                "DOH//doh.local:8053",
                "UDP:[2001:DB8::1]:5353"
            ]
        );
        assert!(Dns::parse(&serde_json::json!({"servers": ["fakedns"]}), &mut loader).is_err());
        assert!(
            Dns::parse(
                &serde_json::json!({"queryStrategy": "UseIPv4", "servers": [{"address": "1.1.1.1", "queryStrategy": "UseIPv6"}]}),
                &mut loader
            )
            .is_err()
        );
    }
}

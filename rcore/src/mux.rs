//! Port of xray-core common/mux server side (mux.cool frames, Xray 26.11.9), including XUDP:
//! UDP sub-sessions with a GlobalID keep their outbound socket when the client reconnects,
//! and replies carry their source address (full cone).
use crate::{
    app::{Base, Counted, Instance, Packet, PacketLink, RESPONSE_HEADER, Stream},
    vless::Address,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc, LazyLock, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context as TaskCx, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{
        AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
        DuplexStream, ReadBuf, ReadHalf, WriteHalf,
    },
    sync::{Mutex as AsyncMutex, Notify, mpsc},
};

const NEW: u8 = 0x01;
const KEEP: u8 = 0x02;
const END: u8 = 0x03;
const KEEP_ALIVE: u8 = 0x04;
const OPTION_DATA: u8 = 0x01;
const OPTION_ERROR: u8 = 0x02;
const TCP: u8 = 0x01;
const UDP: u8 = 0x02;
/// buf.Size: the largest packet a frame may carry and the stream chunk the server writes.
const BUF_SIZE: usize = 8192;
/// Pipe buffer per sub-session (Xray's default per-connection buffer is 512 KiB).
const PIPE: usize = 512 * 1024;
const PACKETS: usize = 64;

#[derive(Debug, PartialEq)]
struct Meta {
    id: u16,
    status: u8,
    option: u8,
    /// Network, address and port of New frames and of Keep frames that carry a UDP address.
    target: Option<(u8, Address, u16)>,
    global_id: [u8; 8],
}

impl Meta {
    fn data(&self) -> bool {
        self.option & OPTION_DATA != 0
    }
    fn udp_target(&self) -> Option<(Address, u16)> {
        match &self.target {
            Some((UDP, address, port)) => Some((address.clone(), *port)),
            _ => None,
        }
    }
}

/// FrameMetadata.UnmarshalFromBuffer (readSourceAndLocal is only set for reverse mux).
fn parse_meta(b: &[u8]) -> Result<Meta> {
    ensure!(b.len() >= 4, "insufficient buffer: {}", b.len());
    let mut meta = Meta {
        id: u16::from_be_bytes([b[0], b[1]]),
        status: b[2],
        option: b[3],
        target: None,
        global_id: [0; 8],
    };
    let mut rest = &b[4..];
    if meta.status == NEW || (meta.status == KEEP && b.len() > 4 && b[4] == UDP) {
        ensure!(b.len() >= 8, "insufficient buffer: {}", b.len());
        let network = b[4];
        let (address, port, used) =
            read_address_port(&b[5..]).context("failed to parse address and port")?;
        ensure!(
            network == TCP || network == UDP,
            "unknown network type: {network}"
        );
        meta.target = Some((network, address, port));
        rest = &b[5 + used..];
    }
    // Application data is essential, to test whether the pipe is closed.
    if meta.status == NEW && meta.data() && meta.udp_target().is_some() && rest.len() >= 8 {
        meta.global_id.copy_from_slice(&rest[..8]);
    }
    Ok(meta)
}

/// protocol.AddressParser with PortThenAddress (1 IPv4, 2 domain, 3 IPv6), as mux uses it.
pub(crate) fn read_address_port(b: &[u8]) -> Result<(Address, u16, usize)> {
    ensure!(b.len() >= 3, "unexpected EOF");
    let port = u16::from_be_bytes([b[0], b[1]]);
    let (address, end) = match b[2] {
        1 => {
            ensure!(b.len() >= 7, "unexpected EOF");
            (Address::Ip(<[u8; 4]>::try_from(&b[3..7])?.into()), 7)
        }
        3 => {
            ensure!(b.len() >= 19, "unexpected EOF");
            let ip = IpAddr::from(<[u8; 16]>::try_from(&b[3..19])?);
            (Address::Ip(ip.to_canonical()), 19)
        }
        2 => {
            ensure!(b.len() >= 4, "unexpected EOF");
            let end = 4 + b[3] as usize;
            ensure!(b.len() >= end, "unexpected EOF");
            (parse_domain(&b[4..end])?, end)
        }
        kind => bail!("unknown address type: {kind}"),
    };
    Ok((address, port, end))
}

fn parse_domain(raw: &[u8]) -> Result<Address> {
    let domain = String::from_utf8_lossy(raw);
    // net.ParseAddress: IP literals (optionally bracketed) sent as domains become IPs.
    if domain.starts_with(|c: char| c == '[' || c.is_ascii_digit())
        && let Ok(ip) = domain
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
    {
        return Ok(Address::Ip(ip.to_canonical()));
    }
    ensure!(
        domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_')),
        "invalid domain name: {domain}"
    );
    Ok(Address::Domain(domain.into_owned()))
}

pub(crate) fn write_address_port(out: &mut Vec<u8>, address: &Address, port: u16) {
    out.extend_from_slice(&port.to_be_bytes());
    match address {
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(3);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            out.push(2);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
    }
}

/// FrameMetadata.WriteTo plus the data length (writeMetaWithFrame) for server-side frames.
fn frame(
    id: u16,
    status: u8,
    option: u8,
    udp: Option<&(Address, u16)>,
    data: Option<&[u8]>,
) -> Vec<u8> {
    let mut f = vec![0, 0];
    f.extend_from_slice(&id.to_be_bytes());
    f.extend_from_slice(&[status, option]);
    if let Some((address, port)) = udp {
        f.push(UDP);
        write_address_port(&mut f, address, *port);
    }
    let meta = (f.len() - 2) as u16;
    f[..2].copy_from_slice(&meta.to_be_bytes());
    if let Some(data) = data {
        f.extend_from_slice(&(data.len() as u16).to_be_bytes());
        f.extend_from_slice(data);
    }
    f
}

/// Stops a session's downlink copy (handle); `error` marks the End frame like Interrupt does.
#[derive(Default)]
struct Stop {
    notify: Notify,
    error: AtomicBool,
}

impl Stop {
    fn request(&self, error: bool) {
        self.error.store(error, Ordering::Relaxed);
        self.notify.notify_one();
    }
    async fn wait(&self) {
        self.notify.notified().await
    }
    fn error(&self) -> bool {
        self.error.load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
enum Up {
    Stream(Arc<AsyncMutex<WriteHalf<DuplexStream>>>),
    Packet(mpsc::Sender<Packet>),
}

struct Session {
    up: Up,
    stop: Arc<Stop>,
    xudp: Option<[u8; 8]>,
}

/// ServerWorker state shared with the sessions' downlink tasks.
struct Worker {
    /// SessionManager; `None` once closed.
    sessions: Mutex<Option<HashMap<u16, Session>>>,
    count: AtomicU64,
    frames: mpsc::Sender<Vec<u8>>,
}

impl Worker {
    fn add(&self, id: u16, session: Session) -> std::result::Result<(), Session> {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(map) = sessions.as_mut() else {
            return Err(session);
        };
        self.count.fetch_add(1, Ordering::Relaxed);
        map.insert(id, session);
        Ok(())
    }

    fn get(&self, id: u16) -> Option<(Up, Arc<Stop>)> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions.as_ref()?.get(&id)?;
        Some((session.up.clone(), session.stop.clone()))
    }

    /// Session.Close for `id`, limited to the instance owning `stop` when given.
    fn close(&self, id: u16, stop: Option<&Arc<Stop>>) {
        let session = {
            let mut sessions = self.sessions.lock().unwrap();
            let Some(map) = sessions.as_mut() else {
                return;
            };
            match map.get(&id) {
                Some(s) if stop.is_none_or(|stop| Arc::ptr_eq(stop, &s.stop)) => map.remove(&id),
                _ => None,
            }
        };
        if let Some(session) = session {
            release(session);
        }
    }

    /// SessionManager.Close.
    fn shutdown(&self) {
        let sessions = self.sessions.lock().unwrap().take();
        for session in sessions.into_iter().flat_map(HashMap::into_values) {
            release(session);
        }
    }

    fn snapshot(&self) -> (usize, u64) {
        let sessions = self.sessions.lock().unwrap();
        (
            sessions.as_ref().map_or(0, HashMap::len),
            self.count.load(Ordering::Relaxed),
        )
    }
}

/// The body of Session.Close: streams lose both directions, XUDP keeps its outbound for a minute.
fn release(session: Session) {
    match session.xudp {
        None => {
            session.stop.request(true);
            if let Up::Stream(up) = session.up {
                tokio::spawn(async move {
                    let _ = up.lock().await.shutdown().await;
                });
            }
        }
        Some(id) => {
            session.stop.request(false);
            if let Some(x) = XUDP.lock().unwrap().get_mut(&id)
                && x.status == Status::Active
            {
                x.status = Status::Expiring;
                x.expire = Instant::now() + Duration::from_secs(60);
                tracing::debug!("XUDP put {id:?}");
            }
        }
    }
}

#[derive(PartialEq)]
enum Status {
    Initializing,
    Active,
    Expiring,
}

#[derive(Clone)]
struct XudpLink {
    up: mpsc::Sender<Packet>,
    down: Arc<AsyncMutex<mpsc::Receiver<Packet>>>,
    failed: Arc<AtomicBool>,
}

struct Xudp {
    status: Status,
    expire: Instant,
    link: Option<XudpLink>,
    /// The mux session currently copying replies (`x.Mux`).
    attached: Option<(Weak<Worker>, u16, Arc<Stop>)>,
}

/// XUDPManager: expired entries are dropped (closing their outbound) by a once-a-minute sweep.
static XUDP: LazyLock<Mutex<HashMap<[u8; 8], Xudp>>> = LazyLock::new(|| {
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(Duration::from_secs(60));
            let now = Instant::now();
            XUDP.lock().unwrap().retain(|id, x| {
                let keep = x.status != Status::Expiring || now <= x.expire;
                if !keep {
                    tracing::debug!("XUDP del {id:?}");
                }
                keep
            });
        }
    });
    Mutex::new(HashMap::new())
});

/// The dispatcher's end of a TCP sub-session. The spawner holds a clone, so the session sees
/// EOF only after a dispatch failure is recorded (Go interrupts the link on failure).
#[derive(Clone)]
struct Pipe(Arc<Mutex<DuplexStream>>);

impl AsyncRead for Pipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_read(cx, buf)
    }
}

impl AsyncWrite for Pipe {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_shutdown(cx)
    }
}

/// Serves a VLESS mux connection (v1.mux.cool) until the client leaves or it idles for a minute.
/// `udp_only` is set for Vision accounts, which may only carry UDP inside mux.
pub async fn serve(
    me: Arc<Instance>,
    base: Base,
    conn: Counted<crate::transport::BoxIo>,
    payload: Vec<u8>,
    skip: Arc<AtomicUsize>,
    udp_only: bool,
) -> Result<()> {
    let (reader, writer) = tokio::io::split(conn);
    let (frames, queue) = mpsc::channel(64);
    tokio::spawn(write_frames(writer, queue, skip));
    let worker = Arc::new(Worker {
        sessions: Mutex::new(Some(HashMap::new())),
        count: AtomicU64::new(0),
        frames,
    });
    let mux = Mux {
        me,
        base: Arc::new(base),
        worker: worker.clone(),
        udp_only,
    };
    let mut reader = BufReader::new(io::Cursor::new(payload).chain(reader));
    let result = tokio::select! {
        result = mux.run(&mut reader) => result,
        _ = idle(&worker) => Ok(()),
    };
    worker.shutdown();
    result
}

/// ServerWorker.monitor: closes the connection after a minute without any session.
async fn idle(worker: &Worker) {
    loop {
        let (size, count) = worker.snapshot();
        tokio::time::sleep(Duration::from_secs(60)).await;
        let (now_size, now_count) = worker.snapshot();
        if size == 0 && now_size == 0 && count == now_count {
            return;
        }
    }
}

/// The VLESS response header goes out with the first frame (BufferedWriter.SetFlushNext).
async fn write_frames<W: AsyncWrite + Unpin>(
    mut out: W,
    mut frames: mpsc::Receiver<Vec<u8>>,
    skip: Arc<AtomicUsize>,
) {
    let mut first = true;
    while let Some(mut batch) = frames.recv().await {
        if first {
            first = false;
            batch.splice(0..0, RESPONSE_HEADER);
            skip.store(batch.len(), Ordering::Relaxed);
        } else {
            while batch.len() < 64 * 1024
                && let Ok(more) = frames.try_recv()
            {
                batch.extend_from_slice(&more);
            }
        }
        if out.write_all(&batch).await.is_err() || out.flush().await.is_err() {
            break;
        }
    }
    let _ = out.shutdown().await;
}

async fn read_meta<R: AsyncRead + Unpin>(r: &mut R) -> Result<Meta> {
    let len = r.read_u16().await? as usize;
    ensure!(len <= 512, "invalid metalen {len}");
    let mut b = vec![0; len];
    r.read_exact(&mut b).await?;
    parse_meta(&b)
}

/// NewStreamReader with one chunk: a 2-byte length, then the data (length 0 is EOF).
async fn read_chunk<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let len = r.read_u16().await? as usize;
    let mut b = vec![0; len];
    r.read_exact(&mut b).await?;
    Ok(b)
}

/// PacketReader: one length-prefixed packet of at most buf.Size bytes.
async fn read_packet<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let len = r.read_u16().await? as usize;
    ensure!(len <= BUF_SIZE, "packet size too large: {len}");
    let mut b = vec![0; len];
    r.read_exact(&mut b).await?;
    Ok(b)
}

struct Mux {
    me: Arc<Instance>,
    base: Arc<Base>,
    worker: Arc<Worker>,
    udp_only: bool,
}

impl Mux {
    async fn run<R: AsyncRead + Unpin>(&self, r: &mut BufReader<R>) -> Result<()> {
        loop {
            if r.fill_buf().await?.is_empty() {
                return Ok(());
            }
            let meta = read_meta(r).await.context("failed to read metadata")?;
            let result = match meta.status {
                KEEP_ALIVE if meta.data() => read_chunk(r).await.map(drop),
                KEEP_ALIVE => Ok(()),
                END => {
                    self.worker.close(meta.id, None);
                    if meta.data() {
                        read_chunk(r).await.map(drop)
                    } else {
                        Ok(())
                    }
                }
                NEW => self.new_session(meta, r).await,
                KEEP => self.keep(meta, r).await,
                status => bail!("unknown status: {status}"),
            };
            result.context("failed to process data")?;
        }
    }

    async fn new_session<R: AsyncRead + Unpin>(&self, meta: Meta, r: &mut R) -> Result<()> {
        let (network, address, port) = meta.target.clone().context("missing target")?;
        let udp = network == UDP;
        tracing::info!(
            "received request for {}:{address}:{port}",
            if udp { "udp" } else { "tcp" }
        );
        // It breaks the whole mux connection, as in Go.
        ensure!(!self.udp_only || udp, "unexpected network TCP");
        if meta.global_id != [0; 8] {
            return self.xudp(meta, r).await;
        }
        let stop = Arc::new(Stop::default());
        let failed = Arc::new(AtomicBool::new(false));
        // Unlike Go, the downlink copy starts before Add; if Add fails it is stopped right away.
        let up = if udp {
            let (up, link_up) = mpsc::channel(PACKETS);
            let (link_down, down) = mpsc::channel(PACKETS);
            let link = PacketLink {
                up: link_up,
                down: link_down,
            };
            self.spawn_packets(address, port, link, failed.clone());
            let down = Arc::new(AsyncMutex::new(down));
            let worker = self.worker.clone();
            tokio::spawn(handle_packets(worker, meta.id, down, failed, stop.clone()));
            Up::Packet(up)
        } else {
            let (inner, outer) = tokio::io::duplex(PIPE);
            self.spawn_stream(address, port, inner, failed.clone());
            let (down, up) = tokio::io::split(outer);
            let worker = self.worker.clone();
            tokio::spawn(handle_stream(worker, meta.id, down, failed, stop.clone()));
            Up::Stream(Arc::new(AsyncMutex::new(up)))
        };
        let session = Session {
            up: up.clone(),
            stop: stop.clone(),
            xudp: None,
        };
        if let Err(session) = self.worker.add(meta.id, session) {
            release(session);
            bail!("failed to add new session");
        }
        if !meta.data() {
            return Ok(());
        }
        self.deliver(meta.id, &up, &stop, meta.udp_target(), r)
            .await
    }

    async fn keep<R: AsyncRead + Unpin>(&self, meta: Meta, r: &mut R) -> Result<()> {
        if !meta.data() {
            return Ok(());
        }
        let Some((up, stop)) = self.worker.get(meta.id) else {
            // Notify remote peer to close this session.
            let _ = self
                .worker
                .frames
                .send(frame(meta.id, END, 0, None, None))
                .await;
            return read_chunk(r).await.map(drop);
        };
        self.deliver(meta.id, &up, &stop, meta.udp_target(), r)
            .await
    }

    /// Copies one frame's data into the session; a closed session is dropped and the data discarded.
    async fn deliver<R: AsyncRead + Unpin>(
        &self,
        id: u16,
        up: &Up,
        stop: &Arc<Stop>,
        dest: Option<(Address, u16)>,
        r: &mut R,
    ) -> Result<()> {
        let delivered = match up {
            Up::Stream(up) => {
                let data = read_chunk(r).await?;
                data.is_empty() || up.lock().await.write_all(&data).await.is_ok()
            }
            Up::Packet(up) => {
                let data = read_packet(r).await?;
                up.send(Packet { data, addr: dest }).await.is_ok()
            }
        };
        if !delivered {
            tracing::info!("failed to write to downstream writer. closing session {id}");
            self.worker.close(id, Some(stop));
        }
        Ok(())
    }

    /// handleStatusNew with a GlobalID: reuse (or create) the outbound link for this XUDP flow.
    async fn xudp<R: AsyncRead + Unpin>(&self, meta: Meta, r: &mut R) -> Result<()> {
        let id = meta.global_id;
        let (address, port) = meta.udp_target().context("XUDP without UDP target")?;
        let data = read_packet(r).await?;
        let mut first = Some(Packet {
            data,
            addr: Some((address.clone(), port)),
        });
        let previous = {
            let mut map = XUDP.lock().unwrap();
            match map.get_mut(&id) {
                None => {
                    map.insert(
                        id,
                        Xudp {
                            status: Status::Initializing,
                            expire: Instant::now(),
                            link: None,
                            attached: None,
                        },
                    );
                    None
                }
                Some(x) if x.status == Status::Initializing => {
                    // Nearly impossible; the client gets End after its next Keep frame.
                    tracing::warn!("XUDP hit {id:?}: conflict");
                    return Ok(());
                }
                Some(x) => {
                    x.status = Status::Initializing;
                    Some((x.link.clone(), x.attached.take()))
                }
            }
        };
        let mut link = None;
        if let Some((previous, attached)) = previous {
            // Detach from the previous mux connection.
            if let Some((worker, session, stop)) = attached
                && let Some(worker) = worker.upgrade()
            {
                worker.close(session, Some(&stop));
            }
            if let Some(previous) = previous {
                match previous.up.send(first.take().expect("first packet")).await {
                    Ok(()) => {
                        tracing::info!("XUDP hit {id:?}");
                        link = Some(previous);
                    }
                    Err(mpsc::error::SendError(packet)) => {
                        tracing::info!("XUDP hit {id:?}: io: read/write on closed pipe");
                        first = Some(packet);
                    }
                }
            }
        }
        let link = match (link, first) {
            (Some(link), _) => link,
            (None, first) => {
                let (up, link_up) = mpsc::channel(PACKETS);
                let (link_down, down) = mpsc::channel(PACKETS);
                let failed = Arc::new(AtomicBool::new(false));
                let packets = PacketLink {
                    up: link_up,
                    down: link_down,
                };
                self.spawn_packets(address, port, packets, failed.clone());
                if let Some(first) = first {
                    let _ = up.send(first).await;
                }
                tracing::info!("XUDP new {id:?}");
                XudpLink {
                    up,
                    down: Arc::new(AsyncMutex::new(down)),
                    failed,
                }
            }
        };
        let stop = Arc::new(Stop::default());
        {
            let mut map = XUDP.lock().unwrap();
            let x = map.get_mut(&id).context("XUDP entry vanished")?;
            x.link = Some(link.clone());
            x.attached = Some((Arc::downgrade(&self.worker), meta.id, stop.clone()));
            x.status = Status::Active;
        }
        let session = Session {
            up: Up::Packet(link.up),
            stop: stop.clone(),
            xudp: Some(id),
        };
        if let Err(session) = self.worker.add(meta.id, session) {
            release(session);
            bail!("failed to add new session");
        }
        tokio::spawn(handle_packets(
            self.worker.clone(),
            meta.id,
            link.down,
            link.failed,
            stop,
        ));
        Ok(())
    }

    fn spawn_stream(
        &self,
        address: Address,
        port: u16,
        pipe: DuplexStream,
        failed: Arc<AtomicBool>,
    ) {
        let (me, base) = (self.me.clone(), self.base.clone());
        tokio::spawn(async move {
            let pipe = Pipe(Arc::new(Mutex::new(pipe)));
            let stream = Stream {
                conn: Counted::new(Box::new(pipe.clone()), None, None),
                payload: Vec::new(),
                skip: Arc::default(),
                header_pending: false,
            };
            if let Err(error) = me
                .dispatch_stream(&base, stream, false, address, port)
                .await
            {
                failed.store(true, Ordering::Relaxed);
                log_failure(&me, &base, &error);
            }
            drop(pipe);
        });
    }

    fn spawn_packets(
        &self,
        address: Address,
        port: u16,
        link: PacketLink,
        failed: Arc<AtomicBool>,
    ) {
        let (me, base) = (self.me.clone(), self.base.clone());
        tokio::spawn(async move {
            // Keeps the link open until a failure is recorded.
            let down = link.down.clone();
            if let Err(error) = me.dispatch_packets(&base, address, port, link).await {
                failed.store(true, Ordering::Relaxed);
                log_failure(&me, &base, &error);
            }
            drop(down);
        });
    }
}

fn log_failure(me: &Instance, base: &Base, error: &anyhow::Error) {
    tracing::info!(
        "[{}] {} {error:#}",
        me.config.inbounds[base.index].tag,
        base.peer
    );
}

/// End frame (with OptionError after an interruption), then Session.Close.
async fn end(worker: &Worker, id: u16, error: bool, stop: &Arc<Stop>) {
    let option = if error { OPTION_ERROR } else { 0 };
    let _ = worker.frames.send(frame(id, END, option, None, None)).await;
    worker.close(id, Some(stop));
}

/// handle() for TCP: remote data back to the client in Keep frames of at most 8 KiB.
async fn handle_stream(
    worker: Arc<Worker>,
    id: u16,
    mut down: ReadHalf<DuplexStream>,
    failed: Arc<AtomicBool>,
    stop: Arc<Stop>,
) {
    let mut buf = vec![0u8; BUF_SIZE];
    let error = loop {
        let read = tokio::select! {
            read = down.read(&mut buf) => read,
            _ = stop.wait() => break stop.error(),
        };
        match read {
            Ok(0) => break failed.load(Ordering::Relaxed),
            Ok(n) => {
                let frame = frame(id, KEEP, OPTION_DATA, None, Some(&buf[..n]));
                tokio::select! {
                    sent = worker.frames.send(frame) => if sent.is_err() { break true },
                    _ = stop.wait() => break stop.error(),
                }
            }
            Err(_) => break true,
        }
    };
    drop(down);
    end(&worker, id, error, &stop).await;
}

/// handle() for UDP: each reply becomes a Keep frame tagged with its source address.
async fn handle_packets(
    worker: Arc<Worker>,
    id: u16,
    down: Arc<AsyncMutex<mpsc::Receiver<Packet>>>,
    failed: Arc<AtomicBool>,
    stop: Arc<Stop>,
) {
    let error = 'copy: {
        // A detached XUDP session releases the receiver before its successor can take it.
        let mut down = tokio::select! {
            down = down.lock() => down,
            _ = stop.wait() => break 'copy stop.error(),
        };
        loop {
            let packet = tokio::select! {
                packet = down.recv() => packet,
                _ = stop.wait() => break 'copy stop.error(),
            };
            let Some(packet) = packet else {
                break 'copy failed.load(Ordering::Relaxed);
            };
            let frame = frame(
                id,
                KEEP,
                OPTION_DATA,
                packet.addr.as_ref(),
                Some(&packet.data),
            );
            tokio::select! {
                sent = worker.frames.send(frame) => if sent.is_err() { break 'copy true },
                _ = stop.wait() => break 'copy stop.error(),
            }
        }
    };
    end(&worker, id, error, &stop).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frames_like_go() {
        // New TCP to example.com:443 with data.
        let mut b = vec![0, 5, NEW, OPTION_DATA, TCP, 1, 0xbb, 2, 11];
        b.extend_from_slice(b"example.com");
        let meta = parse_meta(&b).unwrap();
        assert_eq!(
            (meta.id, meta.target),
            (5, Some((TCP, Address::Domain("example.com".into()), 443)))
        );
        // XUDP New: UDP target followed by the GlobalID.
        let mut b = vec![0, 0, NEW, OPTION_DATA, UDP, 0, 53, 1, 8, 8, 8, 8];
        b.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let meta = parse_meta(&b).unwrap();
        assert_eq!(meta.global_id, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            meta.udp_target(),
            Some((Address::Ip([8, 8, 8, 8].into()), 53))
        );
        // Keep with a UDP address is a per-packet destination; plain Keep has none.
        let keep = parse_meta(&[0, 0, KEEP, OPTION_DATA, UDP, 0, 53, 1, 1, 1, 1, 1]).unwrap();
        assert_eq!(
            keep.udp_target(),
            Some((Address::Ip([1, 1, 1, 1].into()), 53))
        );
        assert_eq!(parse_meta(&[0, 3, KEEP, OPTION_DATA]).unwrap().target, None);
        // IPv4-mapped IPv6 and IP literals sent as domains become plain IPs.
        let mut b = vec![0, 1, NEW, 0, TCP, 0, 80, 3];
        b.extend_from_slice(
            &"::ffff:1.2.3.4"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        assert_eq!(
            parse_meta(&b).unwrap().target,
            Some((TCP, Address::Ip([1, 2, 3, 4].into()), 80))
        );
        let mut b = vec![0, 1, NEW, 0, TCP, 0, 80, 2, 5];
        b.extend_from_slice(b"[::1]");
        assert_eq!(
            parse_meta(&b).unwrap().target,
            Some((TCP, Address::Ip("::1".parse().unwrap()), 80))
        );
        for bad in [
            &[0, 1, NEW][..],
            &[0, 1, NEW, 0, 3, 0, 80, 1, 1, 1, 1, 1],
            &[0, 1, NEW, 0, TCP, 0, 80, 9, 1],
            &[0, 1, NEW, 0, TCP, 0, 80, 2, 3, b'a', b' ', b'b'],
        ] {
            assert!(parse_meta(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn writes_frames_like_go() {
        assert_eq!(
            frame(7, END, OPTION_ERROR, None, None),
            [0, 4, 0, 7, END, OPTION_ERROR]
        );
        let source = (Address::Domain("dns.google".into()), 53);
        let mut expected = vec![0, 19, 0, 0, KEEP, OPTION_DATA, UDP, 0, 53, 2, 10];
        expected.extend_from_slice(b"dns.google");
        expected.extend_from_slice(&[0, 2, 0xab, 0xcd]);
        assert_eq!(
            frame(0, KEEP, OPTION_DATA, Some(&source), Some(&[0xab, 0xcd])),
            expected
        );
        let parsed = parse_meta(&expected[2..21]).unwrap();
        assert_eq!(parsed.udp_target(), Some(source));
    }
}

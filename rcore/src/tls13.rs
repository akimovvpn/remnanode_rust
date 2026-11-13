//! TLS 1.3 pieces of Go's crypto/tls as forked by xtls/reality: key schedule (RFC 8446 §7),
//! record protection, REALITY handshake-record padding and Go's dynamic record sizing.
use anyhow::{Context, Result, ensure};
use hmac::{Hmac, Mac};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256, Sha384};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context as TaskContext, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub const RECORD_HEADER: usize = 5;
type Record = ([u8; 5], Vec<u8>);
pub const MAX_PLAINTEXT: usize = 16384;
const TCP_MSS_ESTIMATE: usize = 1208;
const RECORD_SIZE_BOOST: u64 = 128 * 1024;
pub const CONTENT_CCS: u8 = 20;
pub const CONTENT_ALERT: u8 = 21;
pub const CONTENT_HANDSHAKE: u8 = 22;
pub const CONTENT_APP_DATA: u8 = 23;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Suite {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20,
}

impl Suite {
    pub fn by_id(id: u16) -> Option<Self> {
        Some(match id {
            0x1301 => Self::Aes128Gcm,
            0x1302 => Self::Aes256Gcm,
            0x1303 => Self::Chacha20,
            _ => return None,
        })
    }
    fn sha384(self) -> bool {
        self == Self::Aes256Gcm
    }
    pub fn hash_len(self) -> usize {
        if self.sha384() { 48 } else { 32 }
    }
    fn key_len(self) -> usize {
        if self == Self::Aes128Gcm { 16 } else { 32 }
    }
    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm => &aead::AES_256_GCM,
            Self::Chacha20 => &aead::CHACHA20_POLY1305,
        }
    }
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        if self.sha384() {
            Sha384::digest(data).to_vec()
        } else {
            Sha256::digest(data).to_vec()
        }
    }
    fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        if self.sha384() {
            hkdf::Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec()
        } else {
            hkdf::Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec()
        }
    }
    /// HKDF-Expand-Label(secret, "tls13 " + label, context, length).
    pub fn expand_label(self, secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
        let full = format!("tls13 {label}");
        let mut info = Vec::with_capacity(4 + full.len() + context.len());
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push(full.len() as u8);
        info.extend_from_slice(full.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        let mut out = vec![0u8; len];
        if self.sha384() {
            hkdf::Hkdf::<Sha384>::from_prk(secret)
                .expect("prk length")
                .expand(&info, &mut out)
                .expect("hkdf length");
        } else {
            hkdf::Hkdf::<Sha256>::from_prk(secret)
                .expect("prk length")
                .expand(&info, &mut out)
                .expect("hkdf length");
        }
        out
    }
    fn derive_secret(self, secret: &[u8], label: &str, transcript: &[u8]) -> Vec<u8> {
        self.expand_label(secret, label, &self.hash(transcript), self.hash_len())
    }
    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        if self.sha384() {
            let mut m = Hmac::<Sha384>::new_from_slice(key).expect("hmac key");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        } else {
            let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    }
    /// finishedHash: HMAC(ExpandLabel(base, "finished"), Hash(transcript)).
    pub fn finished(self, base: &[u8], transcript: &[u8]) -> Vec<u8> {
        let key = self.expand_label(base, "finished", &[], self.hash_len());
        self.hmac(&key, &self.hash(transcript))
    }
    /// Next application traffic secret for KeyUpdate.
    pub fn next_secret(self, secret: &[u8]) -> Vec<u8> {
        self.expand_label(secret, "traffic upd", &[], self.hash_len())
    }
}

/// The TLS 1.3 secrets a REALITY server needs.
pub struct Schedule {
    pub suite: Suite,
    handshake_secret: Vec<u8>,
}

impl Schedule {
    pub fn new(suite: Suite, shared: &[u8]) -> Self {
        let zeros = vec![0u8; suite.hash_len()];
        let early = suite.extract(&[], &zeros);
        let derived = suite.derive_secret(&early, "derived", &[]);
        Self {
            suite,
            handshake_secret: suite.extract(&derived, shared),
        }
    }
    pub fn handshake_traffic(&self, transcript: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (
            self.suite
                .derive_secret(&self.handshake_secret, "c hs traffic", transcript),
            self.suite
                .derive_secret(&self.handshake_secret, "s hs traffic", transcript),
        )
    }
    pub fn application_traffic(&self, transcript: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let derived = self
            .suite
            .derive_secret(&self.handshake_secret, "derived", &[]);
        let master = self
            .suite
            .extract(&derived, &vec![0u8; self.suite.hash_len()]);
        (
            self.suite
                .derive_secret(&master, "c ap traffic", transcript),
            self.suite
                .derive_secret(&master, "s ap traffic", transcript),
        )
    }
}

/// One direction of record protection (halfConn).
pub struct Cipher {
    pub suite: Suite,
    pub secret: Vec<u8>,
    key: LessSafeKey,
    iv: [u8; 12],
    pub seq: u64,
}

impl Cipher {
    pub fn new(suite: Suite, secret: Vec<u8>) -> Self {
        let key = suite.expand_label(&secret, "key", &[], suite.key_len());
        let iv: [u8; 12] = suite
            .expand_label(&secret, "iv", &[], 12)
            .try_into()
            .expect("iv length");
        Self {
            suite,
            key: LessSafeKey::new(UnboundKey::new(suite.algorithm(), &key).expect("aead key")),
            iv,
            seq: 0,
            secret,
        }
    }
    fn nonce(&self) -> Nonce {
        let mut nonce = self.iv;
        for (i, b) in self.seq.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        Nonce::assume_unique_for_key(nonce)
    }
    /// Seals one record. `pad_to` reproduces REALITY's padding to a recorded record length.
    pub fn seal(
        &mut self,
        content_type: u8,
        payload: &[u8],
        pad_to: Option<usize>,
    ) -> Result<Vec<u8>> {
        ensure!(self.seq < u64::MAX, "tls: record sequence exhausted");
        ensure!(payload.len() <= MAX_PLAINTEXT, "tls: oversized plaintext");
        let mut inner = Vec::with_capacity(payload.len() + 1 + 16);
        inner.extend_from_slice(payload);
        inner.push(content_type);
        if let Some(total) = pad_to {
            ensure!(
                total <= RECORD_HEADER + MAX_PLAINTEXT + 256,
                "tls: oversized ciphertext"
            );
            let padding = total
                .checked_sub(RECORD_HEADER + inner.len() + 16)
                .with_context(|| {
                    format!(
                        "payload[0]: {}, padding: negative",
                        payload.first().copied().unwrap_or(0)
                    )
                })?;
            inner.resize(inner.len() + padding, 0);
        }
        let len = inner.len() + 16;
        ensure!(len <= MAX_PLAINTEXT + 256, "tls: oversized ciphertext");
        let header = [CONTENT_APP_DATA, 3, 3, (len >> 8) as u8, len as u8];
        let nonce = self.nonce();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(header), &mut inner)
            .map_err(|_| anyhow::anyhow!("seal failed"))?;
        self.seq += 1;
        let mut record = header.to_vec();
        record.extend_from_slice(&inner);
        Ok(record)
    }
    /// Opens one record body; returns (content type, content).
    pub fn open(&mut self, header: &[u8; 5], body: &mut [u8]) -> Result<(u8, Vec<u8>)> {
        ensure!(self.seq < u64::MAX, "tls: record sequence exhausted");
        validate_header(header)?;
        ensure!(
            header[0] == CONTENT_APP_DATA,
            "tls: unexpected record type {}",
            header[0]
        );
        ensure!(
            body.len() == u16::from_be_bytes([header[3], header[4]]) as usize,
            "tls: invalid record length"
        );
        let nonce = self.nonce();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(*header), body)
            .map_err(|_| anyhow::anyhow!("tls: bad record MAC"))?;
        self.seq += 1;
        let end = plain
            .iter()
            .rposition(|b| *b != 0)
            .context("tls: unexpected message")?;
        ensure!(end <= MAX_PLAINTEXT, "tls: oversized plaintext");
        Ok((plain[end], plain[..end].to_vec()))
    }
}

/// Reads one TLS record (header, body) from `r`.
pub async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> Result<([u8; 5], Vec<u8>)> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header).await?;
    validate_header(&header)?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok((header, body))
}

fn validate_header(header: &[u8; 5]) -> Result<()> {
    ensure!(header[1..3] == [3, 3], "tls: invalid record version");
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    ensure!(
        len <= MAX_PLAINTEXT + 256,
        "tls: oversized record received with length {len}"
    );
    Ok(())
}

/// Go maxPayloadSizeForWrite with dynamic record sizing (TLS 1.3, AEAD).
struct Sizer {
    bytes_sent: u64,
    packets_sent: usize,
}

impl Sizer {
    fn next(&mut self) -> usize {
        if self.bytes_sent >= RECORD_SIZE_BOOST {
            return MAX_PLAINTEXT;
        }
        let payload = TCP_MSS_ESTIMATE - RECORD_HEADER - 16 - 1;
        let pkt = self.packets_sent;
        self.packets_sent += 1;
        if pkt > 1000 {
            return MAX_PLAINTEXT;
        }
        (payload * (pkt + 1)).min(MAX_PLAINTEXT)
    }
}

/// Vision switches each direction only after its command frame is consumed or flushed.
#[derive(Clone, Default)]
pub struct DirectControl(
    Arc<AtomicU8>,
    /// The raw client socket under the TLS layer, for splicing the direct downlink.
    Arc<std::sync::OnceLock<Arc<tokio::net::TcpStream>>>,
);

impl DirectControl {
    pub fn read_direct(&self) {
        self.0.fetch_or(1, Ordering::Release);
    }
    pub fn write_direct(&self) {
        self.0.fetch_or(2, Ordering::Release);
    }
    fn flags(&self) -> u8 {
        self.0.load(Ordering::Acquire)
    }
    pub fn attach(&self, socket: Arc<tokio::net::TcpStream>) {
        let _ = self.1.set(socket);
    }
    /// The client socket once Vision writes directly (inbound.CanSpliceCopy == 1).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn splice_target(&self) -> Option<Arc<tokio::net::TcpStream>> {
        (self.flags() & 2 != 0)
            .then(|| self.1.get().cloned())
            .flatten()
    }
}

/// Demand-driven record I/O: no task reads ahead into Vision's direct TCP bytes.
pub struct Stream<R, W> {
    reader: R,
    writer: W,
    read: Cipher,
    write: Cipher,
    control: DirectControl,
    header: [u8; 5],
    header_pos: usize,
    body: Vec<u8>,
    body_pos: usize,
    plain: Vec<u8>,
    plain_pos: usize,
    handshake: Vec<u8>,
    pending: Vec<u8>,
    pending_pos: usize,
    reply: u8,
    ignored: usize,
    max_ignored: usize,
    read_closed: bool,
    shutdown_started: bool,
    read_error: Option<String>,
    write_error: Option<String>,
    sizer: Sizer,
    max_plaintext: usize,
    max_received: usize,
    /// Client side: NewSessionTicket messages are discarded (session tickets are disabled).
    client: bool,
}

pub fn stream<R, W>(
    reader: R,
    writer: W,
    read: Cipher,
    write: Cipher,
    bytes_sent: u64,
) -> (Stream<R, W>, DirectControl) {
    let control = DirectControl::default();
    (
        Stream {
            reader,
            writer,
            read,
            write,
            control: control.clone(),
            header: [0; 5],
            header_pos: 0,
            body: Vec::new(),
            body_pos: 0,
            plain: Vec::new(),
            plain_pos: 0,
            handshake: Vec::new(),
            pending: Vec::new(),
            pending_pos: 0,
            reply: 0,
            ignored: 0,
            max_ignored: 32,
            read_closed: false,
            shutdown_started: false,
            read_error: None,
            write_error: None,
            sizer: Sizer {
                bytes_sent,
                packets_sent: 0,
            },
            client: false,
            max_plaintext: MAX_PLAINTEXT,
            max_received: MAX_PLAINTEXT + 256,
        },
        control,
    )
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn poll_fill<R: AsyncRead + Unpin>(
    reader: &mut R,
    cx: &mut TaskContext<'_>,
    bytes: &mut [u8],
    pos: &mut usize,
) -> Poll<io::Result<bool>> {
    while *pos < bytes.len() {
        let mut buf = ReadBuf::new(&mut bytes[*pos..]);
        ready!(Pin::new(&mut *reader).poll_read(cx, &mut buf))?;
        let n = buf.filled().len();
        if n == 0 {
            return Poll::Ready(Ok(false));
        }
        *pos += n;
    }
    Poll::Ready(Ok(true))
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Stream<R, W> {
    pub fn set_max_ignored(&mut self, limit: usize) {
        self.max_ignored = limit.max(1);
    }

    pub fn set_max_plaintext(&mut self, limit: usize) {
        self.max_plaintext = limit.clamp(1, MAX_PLAINTEXT);
    }

    pub fn set_max_received(&mut self, ciphertext: usize) {
        self.max_received = ciphertext.min(MAX_PLAINTEXT + 256);
    }

    pub fn set_client(&mut self) {
        self.client = true;
    }

    fn poll_record(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<Option<Record>>> {
        if !ready!(poll_fill(
            &mut self.reader,
            cx,
            &mut self.header,
            &mut self.header_pos
        ))? {
            return if self.header_pos == 0 {
                Poll::Ready(Ok(None))
            } else {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tls: truncated record header",
                )))
            };
        }
        if self.body.is_empty() {
            validate_header(&self.header).map_err(invalid)?;
            if self.header[0] != CONTENT_APP_DATA {
                return Poll::Ready(Err(invalid("tls: unexpected record type")));
            }
            let size = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
            if size > self.max_received {
                return Poll::Ready(Err(invalid("tls: record_size_limit exceeded")));
            }
            self.body.resize(size, 0);
        }
        if !ready!(poll_fill(
            &mut self.reader,
            cx,
            &mut self.body,
            &mut self.body_pos
        ))? {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tls: truncated record body",
            )));
        }
        self.header_pos = 0;
        self.body_pos = 0;
        Poll::Ready(Ok(Some((self.header, std::mem::take(&mut self.body)))))
    }

    fn queue(&mut self, kind: u8, content: &[u8]) -> io::Result<()> {
        debug_assert_eq!(self.pending_pos, self.pending.len());
        self.pending = self.write.seal(kind, content, None).map_err(invalid)?;
        self.pending_pos = 0;
        self.sizer.bytes_sent += self.pending.len() as u64;
        Ok(())
    }

    fn poll_drain(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            let n = ready!(
                Pin::new(&mut self.writer).poll_write(cx, &self.pending[self.pending_pos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "tls: failed to write record",
                )));
            }
            self.pending_pos += n;
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_reply(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if self.reply == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = &self.write_error {
            return Poll::Ready(Err(invalid(error)));
        }
        let result: Poll<io::Result<()>> = (|| {
            ready!(self.poll_drain(cx))?;
            if self.reply == 1 {
                self.queue(CONTENT_HANDSHAKE, &[24, 0, 0, 1, 0])?;
                self.write = Cipher::new(
                    self.write.suite,
                    self.write.suite.next_secret(&self.write.secret),
                );
                self.reply = 2;
                ready!(self.poll_drain(cx))?;
            }
            ready!(Pin::new(&mut self.writer).poll_flush(cx))?;
            self.reply = 0;
            Poll::Ready(Ok(()))
        })();
        if let Poll::Ready(Err(error)) = &result {
            self.write_error = Some(error.to_string());
        }
        result
    }

    fn ignored(&mut self) -> io::Result<()> {
        self.ignored = self.ignored.saturating_add(1);
        if self.ignored > self.max_ignored {
            return Err(invalid("tls: too many non-advancing records"));
        }
        Ok(())
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.plain_pos < self.plain.len() {
                let n = buf.remaining().min(self.plain.len() - self.plain_pos);
                buf.put_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
                self.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if self.read_closed {
                return Poll::Ready(Ok(()));
            }
            ready!(self.poll_reply(cx))?;
            if self.control.flags() & 1 != 0 {
                return Pin::new(&mut self.reader).poll_read(cx, buf);
            }
            let Some((header, mut body)) = ready!(self.poll_record(cx))? else {
                if !self.handshake.is_empty() {
                    return Poll::Ready(Err(invalid("tls: truncated handshake")));
                }
                self.read_closed = true;
                return Poll::Ready(Ok(()));
            };
            let (kind, content) = self.read.open(&header, &mut body).map_err(invalid)?;
            if kind != CONTENT_HANDSHAKE && !self.handshake.is_empty() {
                return Poll::Ready(Err(invalid(
                    "tls: handshake interleaved with another record type",
                )));
            }
            match kind {
                CONTENT_APP_DATA => {
                    if content.is_empty() {
                        self.ignored()?;
                        continue;
                    }
                    self.ignored = 0;
                    self.plain = content;
                    self.plain_pos = 0;
                }
                CONTENT_ALERT => {
                    if content.len() != 2 {
                        return Poll::Ready(Err(invalid("tls: malformed alert")));
                    }
                    match content[1] {
                        0 => {
                            self.read_closed = true;
                            return Poll::Ready(Ok(()));
                        }
                        90 => self.ignored()?, // TLS 1.3 ignores user_canceled regardless of alert level.
                        code => {
                            return Poll::Ready(Err(invalid(format!(
                                "tls: received alert {code}"
                            ))));
                        }
                    }
                }
                CONTENT_HANDSHAKE => {
                    if content.is_empty() {
                        return Poll::Ready(Err(invalid("tls: empty handshake record")));
                    }
                    self.ignored()?;
                    self.handshake.extend_from_slice(&content);
                    while self.client && self.handshake.len() >= 4 && self.handshake[0] == 4 {
                        let len = 4
                            + (((self.handshake[1] as usize) << 16)
                                | ((self.handshake[2] as usize) << 8)
                                | self.handshake[3] as usize);
                        if len > 1 << 16 {
                            return Poll::Ready(Err(invalid("tls: oversized NewSessionTicket")));
                        }
                        if self.handshake.len() < len {
                            break;
                        }
                        self.handshake.drain(..len);
                    }
                    if self.handshake.len() < 4 || (self.client && self.handshake[0] == 4) {
                        continue;
                    }
                    if self.handshake[..4] != [24, 0, 0, 1] {
                        return Poll::Ready(Err(invalid("tls: invalid post-handshake message")));
                    }
                    if self.handshake.len() < 5 {
                        continue;
                    }
                    if self.handshake.len() != 5 || self.handshake[4] > 1 {
                        return Poll::Ready(Err(invalid("tls: invalid KeyUpdate")));
                    }
                    self.reply = self.handshake[4];
                    self.handshake.clear();
                    self.read = Cipher::new(
                        self.read.suite,
                        self.read.suite.next_secret(&self.read.secret),
                    );
                }
                _ => return Poll::Ready(Err(invalid("tls: unexpected content type"))),
            }
        }
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for Stream<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = &this.read_error {
            return Poll::Ready(Err(invalid(error)));
        }
        let result = this.poll_read_inner(cx, buf);
        if let Poll::Ready(Err(error)) = &result {
            this.read_error = Some(error.to_string());
        }
        result
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for Stream<R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = &this.write_error {
            return Poll::Ready(Err(invalid(error)));
        }
        if this.shutdown_started {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tls: write after shutdown",
            )));
        }
        let result = (|| {
            ready!(this.poll_reply(cx))?;
            ready!(this.poll_drain(cx))?;
            if bytes.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if this.control.flags() & 2 != 0 {
                return Pin::new(&mut this.writer).poll_write(cx, bytes);
            }
            let n = bytes.len().min(this.sizer.next()).min(this.max_plaintext);
            this.queue(CONTENT_APP_DATA, &bytes[..n])?;
            // The copied input is accepted even if its record still needs a later flush.
            if let Poll::Ready(result) = this.poll_drain(cx) {
                result?;
            }
            Poll::Ready(Ok(n))
        })();
        if let Poll::Ready(Err(error)) = &result {
            this.write_error = Some(error.to_string());
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = &this.write_error {
            return Poll::Ready(Err(invalid(error)));
        }
        let result = (|| {
            ready!(this.poll_reply(cx))?;
            ready!(this.poll_drain(cx))?;
            Pin::new(&mut this.writer).poll_flush(cx)
        })();
        if let Poll::Ready(Err(error)) = &result {
            this.write_error = Some(error.to_string());
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = &this.write_error {
            return Poll::Ready(Err(invalid(error)));
        }
        let result = (|| {
            ready!(this.poll_reply(cx))?;
            ready!(this.poll_drain(cx))?;
            if !this.shutdown_started {
                this.shutdown_started = true;
                if this.control.flags() == 0 {
                    this.queue(CONTENT_ALERT, &[1, 0])?;
                    ready!(this.poll_drain(cx))?;
                }
            }
            ready!(Pin::new(&mut this.writer).poll_flush(cx))?;
            Pin::new(&mut this.writer).poll_shutdown(cx)
        })();
        if let Poll::Ready(Err(error)) = &result {
            this.write_error = Some(error.to_string());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8448 §3 (simple 1-RTT handshake) key schedule vectors.
    #[test]
    fn key_schedule_matches_rfc8448() {
        let shared = unhex(
            "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d",
        );
        let schedule = Schedule::new(Suite::Aes128Gcm, &shared);
        assert_eq!(
            schedule.handshake_secret,
            unhex(
                "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac"
            )
        );
        let s_hs = unhex(
            "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38",
        );
        assert_eq!(
            Suite::Aes128Gcm.expand_label(&s_hs, "key", &[], 16),
            unhex("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc")
        );
        assert_eq!(
            Suite::Aes128Gcm.expand_label(&s_hs, "iv", &[], 12),
            unhex("5d 31 3e b2 67 12 76 ee 13 00 0b 30")
        );
    }

    #[test]
    fn records_round_trip_with_reality_padding() {
        let secret = vec![7u8; 32];
        let mut w = Cipher::new(Suite::Chacha20, secret.clone());
        let mut r = Cipher::new(Suite::Chacha20, secret);
        let record = w
            .seal(CONTENT_HANDSHAKE, &[8, 0, 0, 2, 0, 0], Some(100))
            .unwrap();
        assert_eq!(record.len(), 100);
        let header: [u8; 5] = record[..5].try_into().unwrap();
        let mut body = record[5..].to_vec();
        assert_eq!(
            r.open(&header, &mut body).unwrap(),
            (CONTENT_HANDSHAKE, vec![8, 0, 0, 2, 0, 0])
        );
        assert!(w.seal(CONTENT_HANDSHAKE, &[1; 200], Some(100)).is_err());
    }

    #[test]
    fn dynamic_record_sizes_match_go() {
        let mut s = Sizer {
            bytes_sent: 0,
            packets_sent: 0,
        };
        assert_eq!([s.next(), s.next(), s.next()], [1186, 2372, 3558]);
        s.bytes_sent = RECORD_SIZE_BOOST;
        assert_eq!(s.next(), MAX_PLAINTEXT);
    }
    fn session(
        capacity: usize,
    ) -> (
        Stream<
            tokio::io::ReadHalf<tokio::io::DuplexStream>,
            tokio::io::WriteHalf<tokio::io::DuplexStream>,
        >,
        DirectControl,
        tokio::io::DuplexStream,
    ) {
        let (server, client) = tokio::io::duplex(capacity);
        let (r, w) = tokio::io::split(server);
        let (stream, control) = stream(
            r,
            w,
            Cipher::new(Suite::Aes128Gcm, vec![7; 32]),
            Cipher::new(Suite::Aes128Gcm, vec![8; 32]),
            0,
        );
        (stream, control, client)
    }

    #[tokio::test]
    async fn fragmented_records_and_key_update_request() {
        let (mut stream, _, mut client) = session(1);
        let peer = tokio::spawn(async move {
            let suite = Suite::Aes128Gcm;
            let mut send = Cipher::new(suite, vec![7; 32]);
            // KeyUpdate itself may span records, including its four-byte header.
            for part in [&[24, 0][..], &[0, 1, 1][..]] {
                for byte in send.seal(CONTENT_HANDSHAKE, part, None).unwrap() {
                    client.write_all(&[byte]).await.unwrap();
                    tokio::task::yield_now().await;
                }
            }
            let (header, mut body) = read_record(&mut client).await.unwrap();
            let mut receive = Cipher::new(suite, vec![8; 32]);
            assert_eq!(
                receive.open(&header, &mut body).unwrap(),
                (CONTENT_HANDSHAKE, vec![24, 0, 0, 1, 0])
            );
            send = Cipher::new(suite, suite.next_secret(&send.secret));
            client
                .write_all(&send.seal(CONTENT_APP_DATA, b"new key", None).unwrap())
                .await
                .unwrap();
            let (header, mut body) = read_record(&mut client).await.unwrap();
            receive = Cipher::new(suite, suite.next_secret(&receive.secret));
            assert_eq!(
                receive.open(&header, &mut body).unwrap(),
                (CONTENT_APP_DATA, b"reply".to_vec())
            );
        });
        let mut back = [0; 7];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_exact(&mut back),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&back, b"new key");
        stream.write_all(b"reply").await.unwrap();
        stream.flush().await.unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_bad_key_updates_and_alerts() {
        for (kind, content) in [
            (CONTENT_HANDSHAKE, vec![24, 0, 0, 1, 2]),
            (CONTENT_HANDSHAKE, vec![24, 0, 0, 2, 0]),
            (CONTENT_HANDSHAKE, vec![24, 0, 0, 1, 0, 24, 0, 0, 1, 0]),
            (CONTENT_ALERT, vec![1]),
            (CONTENT_ALERT, vec![1, 42]),
            (CONTENT_ALERT, vec![2, 0, 0]),
        ] {
            let (mut stream, _, mut client) = session(65536);
            let mut send = Cipher::new(Suite::Aes128Gcm, vec![7; 32]);
            client
                .write_all(&send.seal(kind, &content, None).unwrap())
                .await
                .unwrap();
            assert_eq!(
                stream.read(&mut [0; 1]).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test]
    async fn negotiated_record_limit_bounds_application_writes() {
        let (mut stream, _, mut peer) = session(65536);
        stream.set_max_plaintext(63);
        stream.write_all(&[3; 130]).await.unwrap();
        let mut cipher = Cipher::new(Suite::Aes128Gcm, vec![8; 32]);
        for size in [63, 63, 4] {
            let (header, mut body) = read_record(&mut peer).await.unwrap();
            let (kind, content) = cipher.open(&header, &mut body).unwrap();
            assert_eq!(kind, CONTENT_APP_DATA);
            assert_eq!(content, vec![3; size]);
        }
    }

    #[tokio::test]
    async fn receive_record_limit_counts_padding_and_keeps_the_boundary_valid() {
        for oversized in [false, true] {
            let (mut stream, _, mut peer) = session(65536);
            stream.set_max_received(80);
            let mut cipher = Cipher::new(Suite::Aes128Gcm, vec![7; 32]);
            let record = cipher
                .seal(
                    CONTENT_APP_DATA,
                    b"x",
                    Some(RECORD_HEADER + 80 + usize::from(oversized)),
                )
                .unwrap();
            peer.write_all(&record).await.unwrap();
            let mut byte = [0];
            if oversized {
                assert_eq!(
                    stream.read(&mut byte).await.unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            } else {
                assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
                assert_eq!(byte, [b'x']);
            }
        }
    }

    #[tokio::test]
    async fn client_bounds_session_ticket_record_floods() {
        let (mut stream, _, mut peer) = session(65536);
        stream.set_client();
        stream.set_max_ignored(1);
        let mut cipher = Cipher::new(Suite::Aes128Gcm, vec![7; 32]);
        for _ in 0..2 {
            peer.write_all(&cipher.seal(CONTENT_HANDSHAKE, &[4, 0, 0, 0], None).unwrap())
                .await
                .unwrap();
        }
        peer.write_all(&cipher.seal(CONTENT_APP_DATA, b"x", None).unwrap())
            .await
            .unwrap();
        assert_eq!(
            stream.read(&mut [0; 1]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn direct_read_drains_plaintext_then_preserves_tcp_bytes() {
        let (mut stream, control, mut client) = session(65536);
        let mut send = Cipher::new(Suite::Aes128Gcm, vec![7; 32]);
        let mut bytes = send.seal(CONTENT_APP_DATA, b"frame-tail", None).unwrap();
        bytes.extend_from_slice(b"raw TCP");
        client.write_all(&bytes).await.unwrap();
        let mut first = [0; 5];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"frame");
        control.read_direct();
        let mut rest = [0; 12];
        stream.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"-tailraw TCP");
        // Either direction being direct suppresses the outer TLS close_notify.
        stream.shutdown().await.unwrap();
        let mut wire = Vec::new();
        client.read_to_end(&mut wire).await.unwrap();
        assert!(wire.is_empty());
    }

    #[tokio::test]
    async fn direct_write_follows_flushed_frame_without_close_notify() {
        let (mut stream, control, mut client) = session(7);
        let receiver = tokio::spawn(async move {
            let (header, mut body) = read_record(&mut client).await.unwrap();
            let mut receive = Cipher::new(Suite::Aes128Gcm, vec![8; 32]);
            assert_eq!(
                receive.open(&header, &mut body).unwrap(),
                (CONTENT_APP_DATA, b"command2".to_vec())
            );
            let mut raw = Vec::new();
            client.read_to_end(&mut raw).await.unwrap();
            assert_eq!(&raw, b"raw TCP");
        });
        stream.write_all(b"command2").await.unwrap();
        stream.flush().await.unwrap();
        control.write_direct();
        stream.write_all(b"raw TCP").await.unwrap();
        stream.shutdown().await.unwrap();
        receiver.await.unwrap();
    }

    #[test]
    fn drop_closes_reader_without_a_background_task() {
        struct Reader(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Reader {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        impl AsyncRead for Reader {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (stream, _) = stream(
            Reader(dropped.clone()),
            tokio::io::sink(),
            Cipher::new(Suite::Aes128Gcm, vec![7; 32]),
            Cipher::new(Suite::Aes128Gcm, vec![8; 32]),
            0,
        );
        drop(stream);
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn record_limits_and_sequence_exhaustion() {
        let suite = Suite::Aes128Gcm;
        let mut cipher = Cipher::new(suite, vec![7; 32]);
        assert!(
            cipher
                .seal(CONTENT_APP_DATA, &vec![0; MAX_PLAINTEXT + 1], None)
                .is_err()
        );
        assert!(
            cipher
                .seal(
                    CONTENT_APP_DATA,
                    &[],
                    Some(MAX_PLAINTEXT + 257 + RECORD_HEADER)
                )
                .is_err()
        );
        let mut record = cipher.seal(CONTENT_APP_DATA, b"ok", None).unwrap();
        let header: [u8; 5] = record[..5].try_into().unwrap();
        cipher.seq = u64::MAX;
        assert!(cipher.seal(CONTENT_APP_DATA, b"no", None).is_err());
        assert!(cipher.open(&header, &mut record[5..]).is_err());
        assert!(validate_header(&[23, 3, 1, 0, 20]).is_err());
        // A valid AEAD tag does not make an oversized plaintext record valid.
        let mut oversized = vec![3; MAX_PLAINTEXT + 1];
        oversized.push(CONTENT_APP_DATA);
        let size = oversized.len() + 16;
        let header = [23, 3, 3, (size >> 8) as u8, size as u8];
        let mut cipher = Cipher::new(suite, vec![7; 32]);
        cipher
            .key
            .seal_in_place_append_tag(cipher.nonce(), Aad::from(header), &mut oversized)
            .unwrap();
        assert!(
            cipher
                .open(&header, &mut oversized)
                .unwrap_err()
                .to_string()
                .contains("oversized plaintext")
        );
    }
    #[tokio::test]
    async fn small_write_reaches_peer_without_flush() {
        let (mut stream, _, mut client) = session(65536);
        stream.write_all(b"ping").await.unwrap();
        let (header, mut body) = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read_record(&mut client),
        )
        .await
        .expect("write_all did not send the record")
        .unwrap();
        let mut receive = Cipher::new(Suite::Aes128Gcm, vec![8; 32]);
        assert_eq!(
            receive.open(&header, &mut body).unwrap(),
            (CONTENT_APP_DATA, b"ping".to_vec())
        );
    }
    #[tokio::test]
    async fn cancelled_pending_write_does_not_acknowledge_another_buffer() {
        use std::task::Waker;
        let (mut stream, _, mut peer) = session(1);
        let mut cx = TaskContext::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"ping"),
            Poll::Ready(Ok(4))
        ));
        assert!(stream.pending_pos < stream.pending.len());
        // Cancelling this Pending call must consume none of its input.
        assert!(
            Pin::new(&mut stream)
                .poll_write(&mut cx, b"cancelled")
                .is_pending()
        );
        let received = tokio::spawn(async move {
            let mut receive = Cipher::new(Suite::Aes128Gcm, vec![8; 32]);
            for expected in [&b"ping"[..], &b"x"[..]] {
                let (header, mut body) = read_record(&mut peer).await.unwrap();
                assert_eq!(
                    receive.open(&header, &mut body).unwrap(),
                    (CONTENT_APP_DATA, expected.to_vec())
                );
            }
        });
        assert_eq!(stream.write(b"x").await.unwrap(), 1);
        stream.flush().await.unwrap();
        received.await.unwrap();
    }
}

#[cfg(test)]
mod learned_limits_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn learned_limit_counts_empty_records_and_resets_after_data() {
        for over_limit in [false, true] {
            let (server, mut peer) = tokio::io::duplex(1024);
            let (r, w) = tokio::io::split(server);
            let (mut stream, _) = stream(
                r,
                w,
                Cipher::new(Suite::Aes128Gcm, vec![7; 32]),
                Cipher::new(Suite::Aes128Gcm, vec![8; 32]),
                0,
            );
            stream.set_max_ignored(1);
            let mut tx = Cipher::new(Suite::Aes128Gcm, vec![7; 32]);
            peer.write_all(&tx.seal(CONTENT_APP_DATA, &[], None).unwrap())
                .await
                .unwrap();
            if over_limit {
                peer.write_all(&tx.seal(CONTENT_APP_DATA, &[], None).unwrap())
                    .await
                    .unwrap();
            }
            peer.write_all(&tx.seal(CONTENT_APP_DATA, b"x", None).unwrap())
                .await
                .unwrap();
            let mut byte = [0];
            assert_eq!(stream.read_exact(&mut byte).await.is_ok(), !over_limit);
            if !over_limit {
                peer.write_all(&tx.seal(CONTENT_APP_DATA, &[], None).unwrap())
                    .await
                    .unwrap();
                peer.write_all(&tx.seal(CONTENT_APP_DATA, b"y", None).unwrap())
                    .await
                    .unwrap();
                stream.read_exact(&mut byte).await.unwrap();
                assert_eq!(byte, [b'y']);
            }
        }
    }
}

//! Port of github.com/xtls/reality (pinned by Xray-core v26.11.9) server side: tls.go Server(),
//! the [REALITY] sections of handshake_server_tls13.go and the record-length mimicry in conn.go.
use crate::tls13::{
    self, CONTENT_APP_DATA, CONTENT_CCS, CONTENT_HANDSHAKE, Cipher, RECORD_HEADER, Schedule, Suite,
};
use crate::transport::{BoxIo, Prefixed};
use anyhow::{Context, Result, bail, ensure};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use std::{
    collections::HashSet,
    sync::LazyLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const X25519: u16 = 0x001d;
const X25519_MLKEM768: u16 = 0x11ec;
const MLKEM768_EK: usize = 1184;
const MLKEM768_CT: usize = 1088;
const SIZE: usize = 17 * 1024;

#[derive(Clone)]
pub struct Config {
    pub dest: String,
    pub server_names: HashSet<String>,
    pub private_key: [u8; 32],
    pub short_ids: HashSet<[u8; 8]>,
    pub min_client_ver: Option<[u8; 3]>,
    pub max_client_ver: Option<[u8; 3]>,
    pub max_time_diff: Duration,
    pub show: bool,
}

/// Process-wide ed25519 key and Go-encoded self-signed certificate (handshake_server_tls13.go init()).
struct CertKey {
    pair: Ed25519KeyPair,
    public: [u8; 32],
    cert: Vec<u8>,
}

static CERT: LazyLock<CertKey> = LazyLock::new(|| {
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .expect("system randomness");
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("ed25519 seed");
    let public: [u8; 32] = pair
        .public_key()
        .as_ref()
        .try_into()
        .expect("ed25519 public key");
    CertKey {
        cert: go_certificate(&pair, &public),
        pair,
        public,
    }
});

/// DER of x509.CreateCertificate(&x509.Certificate{SerialNumber: 0}) self-signed with ed25519:
/// v3, serial 0, empty issuer/subject, zero-time validity, no extensions.
fn go_certificate(pair: &Ed25519KeyPair, public: &[u8; 32]) -> Vec<u8> {
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match body.len() {
            n if n < 0x80 => out.push(n as u8),
            n if n < 0x100 => out.extend_from_slice(&[0x81, n as u8]),
            n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
        }
        out.extend_from_slice(body);
        out
    }
    let ed25519_alg = tlv(0x30, &[0x06, 0x03, 0x2b, 0x65, 0x70]);
    let zero_time = tlv(0x18, b"00010101000000Z");
    let tbs = tlv(
        0x30,
        &[
            tlv(0xa0, &[0x02, 0x01, 0x02]),
            vec![0x02, 0x01, 0x00],
            ed25519_alg.clone(),
            vec![0x30, 0x00],
            tlv(0x30, &[zero_time.clone(), zero_time].concat()),
            vec![0x30, 0x00],
            tlv(
                0x30,
                &[
                    ed25519_alg.clone(),
                    tlv(0x03, &[&[0u8][..], public].concat()),
                ]
                .concat(),
            ),
        ]
        .concat(),
    );
    let signature = pair.sign(&tbs);
    tlv(
        0x30,
        &[
            tbs,
            ed25519_alg,
            tlv(0x03, &[&[0u8][..], signature.as_ref()].concat()),
        ]
        .concat(),
    )
}

/// Fields of clientHelloMsg that REALITY uses.
pub struct ClientHello {
    pub original: Vec<u8>,
    pub random: [u8; 32],
    session_id: Vec<u8>,
    pub server_name: String,
    tls13: bool,
    key_shares: Vec<(u16, Vec<u8>)>,
    pub alpn: Vec<String>,
}

fn take<'a>(d: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    (d.len() >= n).then(|| {
        let (head, rest) = d.split_at(n);
        *d = rest;
        head
    })
}
fn u8_vec<'a>(d: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = *take(d, 1)?.first()? as usize;
    take(d, n)
}
fn u16_of(d: &mut &[u8]) -> Option<u16> {
    take(d, 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}
fn u16_vec<'a>(d: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = u16_of(d)? as usize;
    take(d, n)
}

impl ClientHello {
    /// clientHelloMsg.unmarshal (the fields REALITY reads) plus readClientHello's version pick.
    pub fn parse(original: &[u8]) -> Option<Self> {
        let mut d = original;
        ensure_some(*take(&mut d, 1)?.first()? == 1)?;
        let body_len = take(&mut d, 3)?;
        ensure_some(
            d.len() == u32::from_be_bytes([0, body_len[0], body_len[1], body_len[2]]) as usize,
        )?;
        take(&mut d, 2)?;
        let random: [u8; 32] = take(&mut d, 32)?.try_into().ok()?;
        let session_id = u8_vec(&mut d)?.to_vec();
        ensure_some(session_id.len() <= 32)?;
        let suites = u16_vec(&mut d)?;
        ensure_some(suites.len() % 2 == 0)?;
        u8_vec(&mut d)?;
        let mut hello = Self {
            original: original.to_vec(),
            random,
            session_id,
            server_name: String::new(),
            tls13: false,
            key_shares: Vec::new(),
            alpn: Vec::new(),
        };
        if d.is_empty() {
            return Some(hello);
        }
        let mut exts = u16_vec(&mut d)?;
        ensure_some(d.is_empty())?;
        let mut seen = HashSet::new();
        while !exts.is_empty() {
            let kind = u16_of(&mut exts)?;
            let mut data = u16_vec(&mut exts)?;
            ensure_some(seen.insert(kind))?;
            match kind {
                0 => {
                    let mut names = u16_vec(&mut data)?;
                    ensure_some(!names.is_empty())?;
                    while !names.is_empty() {
                        let name_type = *take(&mut names, 1)?.first()?;
                        let name = u16_vec(&mut names)?;
                        ensure_some(!name.is_empty())?;
                        if name_type != 0 {
                            continue;
                        }
                        ensure_some(hello.server_name.is_empty())?;
                        hello.server_name = String::from_utf8(name.to_vec()).ok()?;
                        ensure_some(!hello.server_name.ends_with('.'))?;
                    }
                }
                43 => {
                    let mut versions = u8_vec(&mut data)?;
                    while !versions.is_empty() {
                        if u16_of(&mut versions)? == 0x0304 {
                            hello.tls13 = true;
                        }
                    }
                }
                51 => {
                    let mut shares = u16_vec(&mut data)?;
                    while !shares.is_empty() {
                        let group = u16_of(&mut shares)?;
                        let key = u16_vec(&mut shares)?;
                        ensure_some(!key.is_empty())?;
                        hello.key_shares.push((group, key.to_vec()));
                    }
                }
                16 => {
                    let mut list = u16_vec(&mut data)?;
                    ensure_some(!list.is_empty())?;
                    while !list.is_empty() {
                        let proto = u8_vec(&mut list)?;
                        ensure_some(!proto.is_empty())?;
                        hello.alpn.push(String::from_utf8_lossy(proto).into_owned());
                    }
                }
                _ => continue,
            }
            if !matches!(kind, 0 | 43 | 51 | 16) {
                continue;
            }
            ensure_some(data.is_empty())?;
        }
        Some(hello)
    }
}

fn ensure_some(ok: bool) -> Option<()> {
    ok.then_some(())
}

/// What the target sent: its ServerHello (to reuse) and the record lengths to mimic.
struct TargetFlight {
    hello: Vec<u8>,
    suite: Suite,
    group: u16,
    share_at: usize,
    lens: [usize; 7],
    coalesced: bool,
}

/// serverHelloMsg checks from tls.go: TLS 1.2 legacy version, TLS 1.3 selected, TLS 1.3 suite,
/// and an X25519 or X25519MLKEM768 share. Returns (suite, group, share offset).
fn parse_server_hello(m: &[u8]) -> Option<(Suite, u16, usize)> {
    let mut d = m;
    ensure_some(*take(&mut d, 1)?.first()? == 2)?;
    let length = take(&mut d, 3)?;
    ensure_some(d.len() == u32::from_be_bytes([0, length[0], length[1], length[2]]) as usize)?;
    ensure_some(u16_of(&mut d)? == 0x0303)?;
    take(&mut d, 32)?;
    ensure_some(u8_vec(&mut d)?.len() <= 32)?;
    let suite = Suite::by_id(u16_of(&mut d)?)?;
    ensure_some(*take(&mut d, 1)?.first()? == 0)?;
    let mut exts = u16_vec(&mut d)?;
    ensure_some(d.is_empty())?;
    let mut seen = HashSet::new();
    let (mut version, mut share) = (0u16, None);
    while !exts.is_empty() {
        let kind = u16_of(&mut exts)?;
        ensure_some(seen.insert(kind))?;
        let mut data = u16_vec(&mut exts)?;
        match kind {
            43 => {
                version = u16_of(&mut data)?;
                ensure_some(data.is_empty())?;
            }
            51 => {
                let group = u16_of(&mut data)?;
                let key = u16_vec(&mut data)?;
                ensure_some(data.is_empty())?;
                share = Some((group, key.len(), m.len() - exts.len() - key.len()));
            }
            _ => {}
        }
    }
    let (group, len, at) = share?;
    ensure_some(version == 0x0304)?;
    ensure_some(
        (group == X25519 && len == 32) || (group == X25519_MLKEM768 && len == MLKEM768_CT + 32),
    )?;
    Some((suite, group, at))
}

fn version_value(v: &[u8; 3]) -> u32 {
    u32::from_be_bytes([0, v[0], v[1], v[2]])
}

/// REALITY authentication of a ClientHello (tls.go): X25519(privateKey, client share) ->
/// HKDF-SHA256(random[:20], "REALITY") -> AES-256-GCM-open(session_id, AAD = hello with session_id zeroed).
pub fn authenticate(config: &Config, hello: &ClientHello) -> Option<[u8; 32]> {
    let (mut pub1, mut pub2) = (None, None);
    for (group, data) in &hello.key_shares {
        if *group == X25519_MLKEM768 && data.len() == MLKEM768_EK + 32 {
            if pub2.is_some() {
                pub2 = None;
                break;
            }
            pub2 = Some(&data[MLKEM768_EK..]);
            continue;
        }
        if *group == X25519 && data.len() == 32 {
            if pub1.is_some() {
                pub2 = None;
                break;
            }
            pub1 = Some(&data[..]);
            break;
        }
    }
    let peer: [u8; 32] = pub1.or(Some(pub2?))?.try_into().ok()?;
    let secret = x25519_dalek::StaticSecret::from(config.private_key);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
    if !shared.was_contributory() {
        return None;
    }
    let mut auth_key = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&hello.random[..20]), shared.as_bytes())
        .expand(b"REALITY", &mut auth_key)
        .ok()?;
    ensure_some(hello.session_id.len() == 32)?;
    let mut aad = hello.original.clone();
    aad.get_mut(39..71)?.fill(0);
    let mut plain = hello.session_id.clone();
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &auth_key).ok()?);
    let nonce = Nonce::try_assume_unique_for_key(&hello.random[20..32]).ok()?;
    // Go copies the 32-byte session_id: 16 bytes of ciphertext plus the 16-byte tag.
    let opened = key.open_in_place(nonce, Aad::from(&aad), &mut plain).ok()?;
    let ver: [u8; 3] = opened[..3].try_into().ok()?;
    let time = u32::from_be_bytes(opened[4..8].try_into().ok()?);
    let short_id: [u8; 8] = opened[8..16].try_into().ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    let ok = config
        .min_client_ver
        .is_none_or(|m| version_value(&ver) >= version_value(&m))
        && config
            .max_client_ver
            .is_none_or(|m| version_value(&ver) <= version_value(&m))
        && (config.max_time_diff.is_zero()
            || Duration::from_secs((now - time as i64).unsigned_abs()) <= config.max_time_diff)
        && config.short_ids.contains(&short_id);
    if config.show {
        tracing::info!(
            "REALITY ClientVer: {ver:?} ClientTime: {time} ClientShortId: {short_id:?} accepted: {ok}"
        );
    }
    ok.then_some(auth_key)
}

async fn dial(dest: &str) -> Result<TcpStream> {
    TcpStream::connect(dest)
        .await
        .with_context(|| format!("REALITY: failed to dial dest: {dest}"))
}

/// Reads the client's ClientHello handshake message, forwarding every byte to the target.
async fn read_client_hello(
    client: &mut TcpStream,
    target: &mut TcpStream,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut message = Vec::new();
    let mut at = 0;
    loop {
        // Consume complete handshake records already buffered.
        while raw.len() >= at + RECORD_HEADER {
            let len = u16::from_be_bytes([raw[at + 3], raw[at + 4]]) as usize;
            ensure!(
                len <= tls13::MAX_PLAINTEXT,
                "tls: oversized ClientHello record"
            );
            if raw.len() < at + RECORD_HEADER + len {
                break;
            }
            ensure!(
                raw[at] == CONTENT_HANDSHAKE,
                "tls: first record does not look like a TLS handshake"
            );
            message.extend_from_slice(&raw[at + RECORD_HEADER..at + RECORD_HEADER + len]);
            at += RECORD_HEADER + len;
            if message.len() >= 4 {
                let need = 4 + u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
                ensure!(need <= 65536, "tls: handshake message too large");
                if message.len() >= need {
                    message.truncate(need);
                    return Ok((message, raw.split_off(at)));
                }
            }
        }
        let mut chunk = [0u8; 16384];
        let n = client.read(&mut chunk).await?;
        ensure!(n > 0, "EOF");
        target.write_all(&chunk[..n]).await?;
        raw.extend_from_slice(&chunk[..n]);
        ensure!(
            raw.len() <= 256 * 1024,
            "tls: excessive ClientHello framing"
        );
    }
}

/// Reads the target's flight and records its layout: goroutine 2 of tls.go Server() and its `f:` loop.
/// Err(Some(saved)) means "relay to the target" (no ServerHello recorded), Err(None) means "close".
async fn learn_target(
    target: &mut TcpStream,
) -> std::result::Result<TargetFlight, Option<Vec<u8>>> {
    let mut saved: Vec<u8> = Vec::new();
    let mut cursor = 0;
    let mut lens = [0usize; 7];
    let mut hello: Option<(Vec<u8>, Suite, u16, usize)> = None;
    let mut coalesced = false;
    let mut buf = vec![0u8; SIZE];
    let fail = |lens: &[usize; 7], saved: Vec<u8>| (lens[0] == 0).then_some(saved);
    'f: loop {
        let n = match target.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            _ => return Err(None), // Go closes the client when the target ends early.
        };
        saved.extend_from_slice(&buf[..n]);
        if saved.len() - cursor > SIZE {
            break 'f;
        }
        for i in 0..7 {
            if lens[i] != 0 {
                continue;
            }
            let rest = &saved[cursor..];
            if i == 6 && rest.is_empty() {
                break;
            }
            if rest.len() <= RECORD_HEADER {
                continue 'f;
            }
            let bad = u16::from_be_bytes([rest[1], rest[2]]) != 0x0303
                || (i == 0 && (rest[0] != CONTENT_HANDSHAKE || rest[5] != 2))
                || (i == 1 && (rest[0] != CONTENT_CCS || rest[5] != 1))
                || (i > 1 && rest[0] != CONTENT_APP_DATA);
            if bad {
                break 'f;
            }
            let len = RECORD_HEADER + u16::from_be_bytes([rest[3], rest[4]]) as usize;
            if len > SIZE || (i == 1 && len != 6) {
                break 'f;
            }
            if i == 2 && len > 512 {
                // The target sent EncryptedExtensions..Finished in one record.
                lens[2] = len;
                coalesced = true;
                break;
            }
            if i == 6 {
                lens[6] = len;
                break;
            }
            if rest.len() < len {
                continue 'f;
            }
            if i == 0 {
                let message = &rest[RECORD_HEADER..len];
                let Some((suite, group, at)) = parse_server_hello(message) else {
                    break 'f;
                };
                hello = Some((message.to_vec(), suite, group, at));
            }
            lens[i] = len;
            cursor += len;
        }
        let (hello, suite, group, share_at) = hello.ok_or(None)?;
        return Ok(TargetFlight {
            hello,
            suite,
            group,
            share_at,
            lens,
            coalesced,
        });
    }
    Err(fail(&lens, saved))
}

/// Accepts a REALITY connection. Unauthenticated clients are relayed to the target and Err is returned.
pub async fn accept(
    config: &Config,
    mut client: TcpStream,
    policy_timeout: Duration,
) -> Result<(BoxIo, tls13::DirectControl)> {
    let peer = client.peer_addr()?;
    let mut target = tokio::time::timeout(policy_timeout, dial(&config.dest))
        .await
        .context("REALITY target dial timed out")??;
    let first =
        tokio::time::timeout(policy_timeout, read_client_hello(&mut client, &mut target)).await;
    let (hello, leftover) = match first {
        Ok(Ok((message, leftover))) => (ClientHello::parse(&message), leftover),
        _ => (None, Vec::new()),
    };
    if config.show {
        match &hello {
            Some(h) => tracing::info!(
                "REALITY remoteAddr: {peer}\ttls13: {}\tSNI: {:?}\tkey shares: {:?}",
                h.tls13,
                h.server_name,
                h.key_shares
                    .iter()
                    .map(|(g, d)| (*g, d.len()))
                    .collect::<Vec<_>>()
            ),
            None => tracing::info!("REALITY remoteAddr: {peer}\tfailed to read client hello"),
        }
    }
    let auth_key = hello
        .as_ref()
        .filter(|h| h.tls13 && config.server_names.contains(&h.server_name))
        .and_then(|h| authenticate(config, h));
    let (Some(hello), Some(auth_key)) = (hello, auth_key) else {
        // Not a REALITY client: it gets the real target, byte for byte.
        let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
        bail!(
            "REALITY: processed invalid connection from {peer}: authentication failed or validation criteria not met"
        );
    };
    let flight = match tokio::time::timeout(policy_timeout, learn_target(&mut target)).await {
        Ok(Ok(flight)) => flight,
        Ok(Err(Some(saved))) => {
            client.write_all(&saved).await.ok();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
            bail!(
                "REALITY: processed invalid connection from {peer}: target sent incorrect server hello or handshake incomplete"
            );
        }
        _ => bail!(
            "REALITY: processed invalid connection from {peer}: handshake did not complete successfully"
        ),
    };
    let (tcp_read, mut tcp_write) = client.into_split();
    let mut reader = Prefixed {
        prefix: leftover,
        pos: 0,
        inner: tcp_read,
    };
    let (read, write, sent) = tokio::time::timeout(
        policy_timeout,
        handshake(&mut reader, &mut tcp_write, &hello, &auth_key, flight),
    )
    .await
    .context("REALITY: handshake timeout")??;
    drop(target);
    // shortcut: initial flight lengths only; add fingerprint-matched post-handshake probes before claiming full camouflage parity.
    let (stream, direct) = tls13::stream(reader, tcp_write, read, write, sent);
    Ok((Box::new(stream), direct))
}

/// handshake() + readClientFinished(): returns the application ciphers and bytes sent.
async fn handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    hello: &ClientHello,
    auth_key: &[u8; 32],
    flight: TargetFlight,
) -> Result<(Cipher, Cipher, u64)>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let suite = flight.suite;
    let rng = SystemRandom::new();
    let peer = hello
        .key_shares
        .iter()
        .find(|(g, _)| *g == flight.group)
        .map(|(_, d)| d.clone())
        .context("REALITY: client lacks the target's key share")?;
    let mut eph = [0u8; 32];
    rng.fill(&mut eph).map_err(|_| anyhow::anyhow!("rng"))?;
    let eph = x25519_dalek::StaticSecret::from(eph);
    let x_peer: [u8; 32] = if flight.group == X25519_MLKEM768 {
        peer[MLKEM768_EK..].try_into()?
    } else {
        peer[..].try_into()?
    };
    let x_shared = eph.diffie_hellman(&x25519_dalek::PublicKey::from(x_peer));
    ensure!(
        x_shared.was_contributory(),
        "REALITY: invalid X25519 key share"
    );
    let mut shared = x_shared.as_bytes().to_vec();
    let x_public = x25519_dalek::PublicKey::from(&eph);
    // The target's own ServerHello, with only the key share replaced.
    let mut server_hello = flight.hello.clone();
    let at = flight.share_at;
    if flight.group == X25519_MLKEM768 {
        use ml_kem::ml_kem_768::EncapsulationKey;
        let key = peer[..MLKEM768_EK]
            .try_into()
            .map_err(|_| anyhow::anyhow!("ML-KEM key size"))?;
        let ek = EncapsulationKey::new(key)
            .map_err(|_| anyhow::anyhow!("invalid ML-KEM-768 encapsulation key"))?;
        let mut m = [0u8; 32];
        rng.fill(&mut m).map_err(|_| anyhow::anyhow!("rng"))?;
        let (ciphertext, mlkem_shared) = ek.encapsulate_deterministic(&m.into());
        shared = [mlkem_shared.as_slice(), &shared].concat();
        server_hello[at..at + MLKEM768_CT].copy_from_slice(ciphertext.as_slice());
        server_hello[at + MLKEM768_CT..at + MLKEM768_CT + 32].copy_from_slice(x_public.as_bytes());
    } else {
        server_hello[at..at + 32].copy_from_slice(x_public.as_bytes());
    }
    let mut transcript = hello.original.clone();
    transcript.extend_from_slice(&server_hello);
    let schedule = Schedule::new(suite, &shared);
    let (c_hs, s_hs) = schedule.handshake_traffic(&transcript);
    let mut out = Cipher::new(suite, s_hs.clone());
    let mut flight_bytes = vec![
        CONTENT_HANDSHAKE,
        3,
        3,
        (server_hello.len() >> 8) as u8,
        server_hello.len() as u8,
    ];
    flight_bytes.extend_from_slice(&server_hello);
    flight_bytes.extend_from_slice(&[CONTENT_CCS, 3, 3, 0, 1, 1]);
    let lens = flight.lens;
    // EncryptedExtensions: REALITY skips ALPN negotiation; only the server_name ack.
    let ee: Vec<u8> = if hello.server_name.is_empty() {
        vec![8, 0, 0, 2, 0, 0]
    } else {
        vec![8, 0, 0, 6, 0, 4, 0, 0, 0, 0]
    };
    transcript.extend_from_slice(&ee);
    // Certificate: Go's cert with the signature replaced by HMAC-SHA512(AuthKey, ed25519 public key).
    let mut cert = CERT.cert.clone();
    let cert_len = cert.len();
    cert[cert_len - 64..].copy_from_slice(&hmac_sha512(auth_key, &CERT.public));
    let mut cert_msg = vec![11];
    cert_msg.extend_from_slice(&((1 + 3 + 3 + cert_len + 2) as u32).to_be_bytes()[1..]);
    cert_msg.push(0);
    cert_msg.extend_from_slice(&((3 + cert_len + 2) as u32).to_be_bytes()[1..]);
    cert_msg.extend_from_slice(&(cert_len as u32).to_be_bytes()[1..]);
    cert_msg.extend_from_slice(&cert);
    cert_msg.extend_from_slice(&[0, 0]);
    transcript.extend_from_slice(&cert_msg);
    // CertificateVerify (ed25519, scheme 0x0807).
    let mut signed = vec![0x20u8; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    signed.extend_from_slice(&suite.hash(&transcript));
    let mut cv = vec![15, 0, 0, 68, 0x08, 0x07, 0, 64];
    cv.extend_from_slice(CERT.pair.sign(&signed).as_ref());
    transcript.extend_from_slice(&cv);
    let finished = suite.finished(&s_hs, &transcript);
    let mut fin = vec![20, 0, 0, finished.len() as u8];
    fin.extend_from_slice(&finished);
    transcript.extend_from_slice(&fin);
    if flight.coalesced {
        flight_bytes.extend_from_slice(&out.seal(
            CONTENT_HANDSHAKE,
            &[ee, cert_msg, cv, fin].concat(),
            Some(lens[2]),
        )?);
    } else {
        for (msg, len) in [
            (ee, lens[2]),
            (cert_msg, lens[3]),
            (cv, lens[4]),
            (fin, lens[5]),
        ] {
            flight_bytes.extend_from_slice(&out.seal(CONTENT_HANDSHAKE, &msg, Some(len))?);
        }
    }
    let (c_ap, s_ap) = schedule.application_traffic(&transcript);

    let mut write = Cipher::new(suite, s_ap);
    if !flight.coalesced && lens[6] != 0 {
        // Fake NewSessionTicket: an empty application-data record of the target's ticket length.
        flight_bytes.extend_from_slice(&write.seal(CONTENT_APP_DATA, &[], Some(lens[6]))?);
    }
    writer.write_all(&flight_bytes).await?;
    let mut read = Cipher::new(suite, c_hs.clone());
    read_client_finished(reader, &mut read, suite, &c_hs, &transcript).await?;
    Ok((Cipher::new(suite, c_ap), write, flight_bytes.len() as u64))
}

/// Reassemble the Finished handshake across TLS records, then verify its MAC in constant time.
async fn read_client_finished<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    read: &mut Cipher,
    suite: Suite,
    secret: &[u8],
    transcript: &[u8],
) -> Result<()> {
    let mut message = Vec::new();
    let mut useless = 0;
    loop {
        let (header, mut body) = tls13::read_record(reader).await?;
        if header[0] == CONTENT_CCS && body == [1] {
            useless += 1;
            ensure!(useless <= 32, "tls: too many ignored records");
            continue;
        }
        ensure!(
            header[..3] == [CONTENT_APP_DATA, 3, 3],
            "tls: unexpected message"
        );
        let (kind, content) = read.open(&header, &mut body)?;
        ensure!(kind == CONTENT_HANDSHAKE, "tls: unexpected message");
        message.extend_from_slice(&content);
        if message.len() < 4 {
            continue;
        }
        let length = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
        ensure!(
            message[0] == 20 && length == suite.hash_len(),
            "tls: unexpected Finished message"
        );
        ensure!(
            message.len() <= 4 + length,
            "tls: trailing handshake bytes after Finished"
        );
        if message.len() < 4 + length {
            continue;
        }
        use hmac::Mac;
        let key = suite.expand_label(secret, "finished", &[], suite.hash_len());
        let hash = suite.hash(transcript);
        let valid = if suite == Suite::Aes256Gcm {
            let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(&key).expect("HMAC key");
            mac.update(&hash);
            mac.verify_slice(&message[4..]).is_ok()
        } else {
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key).expect("HMAC key");
            mac.update(&hash);
            mac.verify_slice(&message[4..]).is_ok()
        };
        ensure!(valid, "tls: invalid client finished hash");
        return Ok(());
    }
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    use hmac::Mac;
    let mut m = hmac::Hmac::<sha2::Sha512>::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_parses_and_carries_hmac_signature_slot() {
        let cert = &CERT.cert;
        // SEQUENCE { tbs, alg, BIT STRING (0 unused bits, 64-byte signature) } ends with the signature.
        assert_eq!(cert[0], 0x30);
        assert_eq!(&cert[cert.len() - 67..cert.len() - 64], &[0x03, 0x41, 0x00]);
        assert!(cert.windows(15).any(|w| w == b"00010101000000Z"));
    }

    #[test]
    fn rejects_client_hello_without_hybrid_share_first() {
        let config = Config {
            dest: String::new(),
            server_names: HashSet::new(),
            private_key: [1; 32],
            short_ids: HashSet::from([[0; 8]]),
            min_client_ver: None,
            max_client_ver: None,
            max_time_diff: Duration::ZERO,
            show: false,
        };
        let hello = ClientHello {
            original: vec![0; 80],
            random: [0; 32],
            session_id: vec![0; 32],
            server_name: String::new(),
            tls13: true,
            key_shares: vec![
                (X25519, vec![9; 32]),
                (X25519_MLKEM768, vec![9; MLKEM768_EK + 32]),
            ],
            alpn: Vec::new(),
        };
        assert!(
            authenticate(&config, &hello).is_none(),
            "X25519 before X25519MLKEM768 must be rejected"
        );
    }
}

#[cfg(test)]
mod authentication_tests {
    use super::*;
    fn authorized_hello(
        timestamp: u32,
        version: [u8; 3],
        short_id: [u8; 8],
    ) -> (Config, ClientHello, [u8; 32]) {
        let config = Config {
            dest: String::new(),
            server_names: HashSet::new(),
            private_key: [7; 32],
            short_ids: HashSet::from([short_id]),
            min_client_ver: None,
            max_client_ver: None,
            max_time_diff: Duration::from_secs(60),
            show: false,
        };
        let client_secret = x25519_dalek::StaticSecret::from([3; 32]);
        let public = x25519_dalek::PublicKey::from(&client_secret);
        let server =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(config.private_key));
        let shared = client_secret.diffie_hellman(&server);
        let random = [2; 32];
        let mut auth_key = [0; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&random[..20]), shared.as_bytes())
            .expand(b"REALITY", &mut auth_key)
            .unwrap();
        let mut original = vec![0; 80];
        original[0] = 1;
        let mut plain = vec![0; 16];
        plain[..3].copy_from_slice(&version);
        plain[4..8].copy_from_slice(&timestamp.to_be_bytes());
        plain[8..].copy_from_slice(&short_id);
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &auth_key).unwrap());
        key.seal_in_place_append_tag(
            Nonce::try_assume_unique_for_key(&random[20..]).unwrap(),
            Aad::from(&original),
            &mut plain,
        )
        .unwrap();
        original[39..71].copy_from_slice(&plain);
        let mut hybrid = vec![0; MLKEM768_EK];
        hybrid.extend_from_slice(public.as_bytes());
        let hello = ClientHello {
            original,
            random,
            session_id: plain,
            server_name: String::new(),
            tls13: true,
            key_shares: vec![
                (X25519_MLKEM768, hybrid),
                (X25519, public.as_bytes().to_vec()),
            ],
            alpn: Vec::new(),
        };
        (config, hello, auth_key)
    }
    #[test]
    fn authentication_checks_aad_short_id_version_time_and_bounds() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let (mut config, mut hello, key) = authorized_hello(now, [26, 11, 9], [1; 8]);
        assert_eq!(authenticate(&config, &hello), Some(key));
        config.min_client_ver = Some([26, 11, 10]);
        assert!(authenticate(&config, &hello).is_none());
        config.min_client_ver = None;
        config.max_client_ver = Some([26, 11, 8]);
        assert!(authenticate(&config, &hello).is_none());
        config.max_client_ver = None;
        config.short_ids.clear();
        assert!(authenticate(&config, &hello).is_none());
        config.short_ids.insert([1; 8]);
        hello.original[0] ^= 1;
        assert!(authenticate(&config, &hello).is_none());
        hello.original.truncate(40);
        assert!(authenticate(&config, &hello).is_none());
        let (config, hello, _) = authorized_hello(now - 120, [26, 11, 9], [1; 8]);
        assert!(authenticate(&config, &hello).is_none());
    }
    #[tokio::test]
    async fn client_finished_can_span_records_and_rejects_trailing_messages() {
        use tokio::io::AsyncWriteExt;
        let suite = Suite::Aes128Gcm;
        let secret = vec![5; 32];
        let transcript = b"handshake transcript";
        let expected = suite.finished(&secret, transcript);
        let mut finished = vec![20, 0, 0, 32];
        finished.extend_from_slice(&expected);
        for extra in [false, true] {
            let (mut sender, mut reader) = tokio::io::duplex(1024);
            let mut tx = Cipher::new(suite, secret.clone());
            let mut rx = Cipher::new(suite, secret.clone());
            sender
                .write_all(&tx.seal(CONTENT_HANDSHAKE, &finished[..7], None).unwrap())
                .await
                .unwrap();
            let mut rest = finished[7..].to_vec();
            if extra {
                rest.push(0);
            }
            sender
                .write_all(&tx.seal(CONTENT_HANDSHAKE, &rest, None).unwrap())
                .await
                .unwrap();
            drop(sender);
            assert_eq!(
                read_client_finished(&mut reader, &mut rx, suite, &secret, transcript)
                    .await
                    .is_ok(),
                !extra
            );
        }
    }
}

#[cfg(test)]
mod server_hello_tests {
    use super::*;
    fn message(extra: &[u8], trailing_share: bool) -> Vec<u8> {
        let mut share = vec![0, 29, 0, 32];
        share.extend_from_slice(&[3; 32]);
        if trailing_share {
            share.push(7);
        }
        let mut ext = vec![0, 43, 0, 2, 3, 4, 0, 51];
        ext.extend_from_slice(&(share.len() as u16).to_be_bytes());
        ext.extend(share);
        ext.extend_from_slice(extra);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[1; 32]);
        body.extend_from_slice(&[0, 0x13, 1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend(ext);
        let mut m = vec![2];
        m.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        m.extend(body);
        m
    }
    #[test]
    fn rejects_duplicate_extensions_trailing_share_and_bad_handshake_length() {
        assert!(parse_server_hello(&message(&[], false)).is_some());
        assert!(parse_server_hello(&message(&[0, 43, 0, 2, 3, 4], false)).is_none());
        assert!(parse_server_hello(&message(&[], true)).is_none());
        let mut bad = message(&[], false);
        bad[3] ^= 1;
        assert!(parse_server_hello(&bad).is_none());
    }
}

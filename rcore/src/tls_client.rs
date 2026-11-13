//! Client TLS 1.3 for outbounds: the uTLS fingerprints Xray-core 26.11.9 sends (uTLS
//! a13c59ffe98b) and the REALITY client (transport/internet/reality UClient), on the TLS 1.3
//! handshake the REALITY probe uses. TLS 1.2-only servers and HelloRetryRequest are refused.
use crate::{
    reality_probe::{
        Cursor, certificates, constant_time_equal, extensions, len24, put16, read_server_hello,
        roots, server_hello, validate_certificate_request, validate_chain,
        verify_certificate_signature,
    },
    tls13::{self, Cipher, DirectControl, Schedule},
    transport::BoxIo,
};
use anyhow::{Context, Result, bail, ensure};
use ml_kem::{Decapsulate, KeyExport, ml_kem_768::DecapsulationKey};
use ring::{
    aead,
    agreement::{self, ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey},
    rand::{SecureRandom, SystemRandom},
};
use rustls_pki_types::{CertificateDer, TrustAnchor};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    sync::{LazyLock, Mutex},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

const CCS: &[u8] = &[20, 3, 3, 0, 1, 1];
const LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Fingerprint {
    Chrome,
    Firefox,
}

impl Fingerprint {
    /// tls.GetFingerprint for the fingerprints rcore carries; empty is Chrome, as in Xray 26.
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "" | "chrome" => Some(Self::Chrome),
            "firefox" => Some(Self::Firefox),
            _ => None,
        }
    }

    /// Captured from Xray 26.11.9 (HelloChrome_Auto = Chrome 155, HelloFirefox_Auto).
    fn template(self) -> &'static [u8] {
        match self {
            Self::Chrome => include_bytes!("../tests/fixtures/clienthello-chrome155.bin"),
            Self::Firefox => include_bytes!("../tests/fixtures/clienthello-firefox.bin"),
        }
    }
}

pub struct Reality {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub spider_x: String,
    pub spider_y: [i64; 10],
}

pub struct Client {
    /// SNI and certificate name; the caller fills in the destination address when empty.
    pub server_name: String,
    pub fingerprint: Fingerprint,
    pub alpn: Vec<String>,
    pub reality: Option<Reality>,
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| anyhow::anyhow!("TLS client random failed"))?;
    Ok(b)
}

fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

/// BoringSSL GREASE values: cipher, group, first and second extension, version.
fn grease_values() -> Result<[u16; 5]> {
    let mut v = random::<5>()?.map(|b| {
        let b = (b & 0xf0) | 0x0a;
        u16::from_be_bytes([b, b])
    });
    if v[3] == v[2] {
        v[3] ^= 0x1010;
    }
    Ok(v)
}

struct Keys {
    x25519: StaticSecret,
    hybrid_x25519: StaticSecret,
    mlkem: DecapsulationKey,
    p256: Option<EphemeralPrivateKey>,
}

fn replace_grease(list: &[u8], value: u16) -> Vec<u8> {
    list.chunks(2)
        .flat_map(|c| {
            let v = u16::from_be_bytes([c[0], c[1]]);
            if is_grease(v) { value } else { v }.to_be_bytes()
        })
        .collect()
}

/// The fingerprint's ClientHello with fresh randoms, keys, GREASE and ECH GREASE; Chrome's
/// extensions are shuffled like ShuffleChromeTLSExtensions.
fn client_hello(
    fingerprint: Fingerprint,
    server_name: &str,
    alpn: &[String],
    session: &[u8; 32],
) -> Result<(Vec<u8>, Keys)> {
    ensure!(
        server_name.len() <= 253 && !server_name.as_bytes().contains(&0),
        "invalid TLS server name"
    );
    ensure!(
        alpn.iter().all(|p| !p.is_empty() && p.len() <= 255)
            && alpn.iter().map(|p| p.len() + 1).sum::<usize>() <= u16::MAX as usize - 2,
        "invalid TLS ALPN protocols"
    );
    let template = fingerprint.template();
    let rng = SystemRandom::new();
    let grease = grease_values()?;
    let mlkem = DecapsulationKey::from_seed(random::<64>()?.into());
    let x25519 = StaticSecret::from(random::<32>()?);
    // uTLS Chrome uses a separate X25519 key inside the hybrid share; Firefox reuses one.
    let hybrid_x25519 = match fingerprint {
        Fingerprint::Chrome => StaticSecret::from(random::<32>()?),
        Fingerprint::Firefox => x25519.clone(),
    };
    let mut p256 = None;
    let mut hello = template[..6].to_vec();
    hello.extend_from_slice(&random::<32>()?);
    let mut c = Cursor(&template[38..]);
    ensure!(c.vector8()?.len() == 32, "invalid ClientHello template");
    hello.push(32);
    hello.extend_from_slice(session);
    put16(&mut hello, &replace_grease(c.vector16()?, grease[0]));
    let compression = c.vector8()?;
    hello.push(compression.len() as u8);
    hello.extend_from_slice(compression);
    let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut grease_ext = 0;
    for (id, body) in extensions(c.vector16()?)? {
        let id = if is_grease(id) {
            grease_ext += 1;
            grease[1 + grease_ext.min(2)]
        } else {
            id
        };
        let body = match id {
            0 => {
                if server_name.is_empty() || server_name.parse::<std::net::IpAddr>().is_ok() {
                    continue;
                }
                let mut name = vec![0];
                put16(&mut name, server_name.as_bytes());
                let mut names = Vec::new();
                put16(&mut names, &name);
                names
            }
            10 => {
                let mut groups = Vec::new();
                put16(
                    &mut groups,
                    &replace_grease(Cursor(body).vector16()?, grease[1]),
                );
                groups
            }
            43 => {
                let versions = replace_grease(Cursor(body).vector8()?, grease[4]);
                let mut out = vec![versions.len() as u8];
                out.extend_from_slice(&versions);
                out
            }
            16 => {
                if alpn.is_empty() {
                    continue;
                }
                let mut list = Vec::new();
                for p in alpn {
                    list.push(p.len() as u8);
                    list.extend_from_slice(p.as_bytes());
                }
                let mut out = Vec::new();
                put16(&mut out, &list);
                out
            }
            51 => {
                let mut shares = Vec::new();
                let mut list = Cursor(Cursor(body).vector16()?);
                while !list.0.is_empty() {
                    let group = list.u16()?;
                    let old = list.vector16()?;
                    match group {
                        0x11ec => {
                            let mut hybrid = mlkem.encapsulation_key().to_bytes().to_vec();
                            hybrid.extend_from_slice(PublicKey::from(&hybrid_x25519).as_bytes());
                            shares.extend_from_slice(&group.to_be_bytes());
                            put16(&mut shares, &hybrid);
                        }
                        0x001d => {
                            shares.extend_from_slice(&group.to_be_bytes());
                            put16(&mut shares, PublicKey::from(&x25519).as_bytes());
                        }
                        0x0017 => {
                            let key = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
                                .map_err(|_| anyhow::anyhow!("P-256 key generation failed"))?;
                            let public = key
                                .compute_public_key()
                                .map_err(|_| anyhow::anyhow!("P-256 public key failed"))?;
                            shares.extend_from_slice(&group.to_be_bytes());
                            put16(&mut shares, public.as_ref());
                            p256 = Some(key);
                        }
                        g if is_grease(g) => {
                            shares.extend_from_slice(&grease[1].to_be_bytes());
                            put16(&mut shares, old);
                        }
                        _ => bail!("unsupported key share in fingerprint"),
                    }
                }
                let mut out = Vec::new();
                put16(&mut out, &shares);
                out
            }
            0xfe0d => {
                // GREASE ECH: type, KDF/AEAD, config ID, X25519 enc, random payload.
                let mut ech = body[..5].to_vec();
                let payload_len = match fingerprint {
                    Fingerprint::Chrome => 128 + 32 * (random::<1>()?[0] as usize % 4) + 16,
                    Fingerprint::Firefox => {
                        ech[3..5].copy_from_slice(if random::<1>()?[0] & 1 == 0 {
                            &[0, 1]
                        } else {
                            &[0, 3]
                        });
                        223 + 16
                    }
                };
                ech.push(random::<1>()?[0]);
                put16(
                    &mut ech,
                    PublicKey::from(&StaticSecret::from(random::<32>()?)).as_bytes(),
                );
                let mut payload = vec![0u8; payload_len];
                rng.fill(&mut payload)
                    .map_err(|_| anyhow::anyhow!("TLS client random failed"))?;
                put16(&mut ech, &payload);
                ech
            }
            _ => body.to_vec(),
        };
        exts.push((id, body));
    }
    if fingerprint == Fingerprint::Chrome {
        // Fisher-Yates over the movable extensions; GREASE, padding and PSK keep their slots.
        let movable: Vec<usize> = (0..exts.len())
            .filter(|&i| !is_grease(exts[i].0) && !matches!(exts[i].0, 21 | 41))
            .collect();
        for k in (1..movable.len()).rev() {
            let r = u64::from_le_bytes(random::<8>()?) as usize % (k + 1);
            exts.swap(movable[k], movable[r]);
        }
    }
    let mut body = Vec::new();
    for (id, data) in &exts {
        body.extend_from_slice(&id.to_be_bytes());
        put16(&mut body, data);
    }
    ensure!(
        body.len() <= u16::MAX as usize,
        "TLS client extensions too large"
    );
    put16(&mut hello, &body);
    ensure!(
        hello.len() <= tls13::MAX_PLAINTEXT,
        "TLS ClientHello too large"
    );
    let len = hello.len() - 4;
    hello[1..4].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
    Ok((
        hello,
        Keys {
            x25519,
            hybrid_x25519,
            mlkem,
            p256,
        },
    ))
}

/// REALITY: the session ID carries the Xray version, time and short ID, sealed with
/// AES-256-GCM under HKDF(X25519(client, server key), random[:20], "REALITY").
fn seal_reality_session(
    hello: &mut [u8],
    secret: &StaticSecret,
    reality: &Reality,
) -> Result<[u8; 32]> {
    let mut plain = [0u8; 16];
    let version: Vec<u8> = crate::config::VERSION
        .split('.')
        .map(|v| v.parse().unwrap_or(0))
        .collect();
    plain[..3].copy_from_slice(&version[..3]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    plain[4..8].copy_from_slice(&now.to_be_bytes());
    plain[8..].copy_from_slice(&reality.short_id);
    let shared = secret.diffie_hellman(&PublicKey::from(reality.public_key));
    ensure!(
        shared.was_contributory(),
        "REALITY: invalid all-zero shared key"
    );
    let mut auth = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&hello[6..26]), shared.as_bytes())
        .expand(b"REALITY", &mut auth)
        .map_err(|_| anyhow::anyhow!("REALITY: nil authKey"))?;
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &auth)
            .map_err(|_| anyhow::anyhow!("REALITY: invalid authKey"))?,
    );
    let nonce = aead::Nonce::try_assume_unique_for_key(&hello[26..38])
        .map_err(|_| anyhow::anyhow!("REALITY: invalid nonce"))?;
    // The AAD is the whole ClientHello with a zeroed session ID.
    let mut sealed = plain.to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::from(&hello[..]), &mut sealed)
        .map_err(|_| anyhow::anyhow!("REALITY: seal failed"))?;
    hello[39..71].copy_from_slice(&sealed);
    Ok(auth)
}

/// The REALITY certificate: an Ed25519 key whose "signature" is HMAC-SHA512(authKey, key).
fn reality_verified(cert: &CertificateDer<'_>, auth: &[u8; 32]) -> bool {
    use hmac::Mac;
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert.as_ref()) else {
        return false;
    };
    let spki = parsed.public_key();
    if spki.algorithm.algorithm.to_id_string() != "1.3.101.112" {
        return false;
    }
    let Ok(mut mac) = hmac::Hmac::<sha2::Sha512>::new_from_slice(auth) else {
        return false;
    };
    mac.update(&spki.subject_public_key.data);
    mac.verify_slice(&parsed.signature_value.data).is_ok()
}

fn decompress_certificate(body: &[u8]) -> Result<Vec<u8>> {
    let mut c = Cursor(body);
    let algorithm = c.u16()?;
    let len = len24(c.take(3)?);
    ensure!(len <= LIMIT, "compressed certificate too large");
    let compressed_len = len24(c.take(3)?);
    let compressed = c.take(compressed_len)?;
    ensure!(c.0.is_empty(), "trailing compressed certificate");
    let mut out = Vec::new();
    let limit = len as u64 + 1;
    match algorithm {
        1 => flate2::read::ZlibDecoder::new(compressed)
            .take(limit)
            .read_to_end(&mut out)?,
        2 => brotli::Decompressor::new(compressed, 4096)
            .take(limit)
            .read_to_end(&mut out)?,
        3 => {
            let mut decoder = zstd::stream::read::Decoder::new(compressed)?;
            decoder.window_log_max(20)?;
            decoder.take(limit).read_to_end(&mut out)?
        }
        other => bail!("unsupported certificate compression {other}"),
    };
    ensure!(out.len() == len, "invalid decompressed certificate length");
    Ok(out)
}

static ROOTS: LazyLock<Result<Vec<TrustAnchor<'static>>, String>> =
    LazyLock::new(|| roots().map_err(|e| format!("{e:#}")));

/// Runs the handshake on `tcp` and returns the application stream with its Vision control.
pub async fn connect(mut tcp: TcpStream, client: &Client) -> Result<(BoxIo, DirectControl)> {
    let roots = ROOTS
        .as_ref()
        .map_err(|e| anyhow::anyhow!("TLS roots: {e}"))?;
    let session = match client.reality {
        Some(_) => [0u8; 32],
        None => random::<32>()?,
    };
    let (mut hello, keys) = client_hello(
        client.fingerprint,
        &client.server_name,
        &client.alpn,
        &session,
    )?;
    let auth = match &client.reality {
        Some(reality) => Some(seal_reality_session(&mut hello, &keys.x25519, reality)?),
        None => None,
    };
    let session = hello[39..71].to_vec();
    let mut record = vec![22, 3, 1];
    put16(&mut record, &hello);
    tcp.write_all(&record).await?;
    let mut sent = record.len() as u64;
    let sh = read_server_hello(&mut tcp).await?;
    let (suite, group, share) = server_hello(&sh[4..], &session)?;
    let shared = match group {
        0x001d => {
            let peer = <[u8; 32]>::try_from(share).context("invalid X25519 server share")?;
            let shared = keys.x25519.diffie_hellman(&PublicKey::from(peer));
            ensure!(shared.was_contributory(), "invalid all-zero X25519 share");
            shared.as_bytes().to_vec()
        }
        0x11ec => {
            ensure!(share.len() == 1088 + 32, "invalid hybrid server share");
            let ct = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(&share[..1088])
                .map_err(|_| anyhow::anyhow!("invalid ML-KEM ciphertext"))?;
            let mut shared = keys.mlkem.decapsulate(&ct).to_vec();
            let peer = <[u8; 32]>::try_from(&share[1088..])?;
            let x = keys.hybrid_x25519.diffie_hellman(&PublicKey::from(peer));
            ensure!(x.was_contributory(), "invalid all-zero X25519 share");
            shared.extend_from_slice(x.as_bytes());
            shared
        }
        0x0017 => agreement::agree_ephemeral(
            keys.p256
                .context("server selected an unoffered P-256 share")?,
            &UnparsedPublicKey::new(&ECDH_P256, share),
            |s| s.to_vec(),
        )
        .map_err(|_| anyhow::anyhow!("invalid P-256 server share"))?,
        other => bail!("server selected unsupported key share {other:#06x}"),
    };
    let schedule = Schedule::new(suite, &shared);
    let mut transcript = hello;
    transcript.extend_from_slice(&sh);
    let (client_hs, server_hs) = schedule.handshake_traffic(&transcript);
    let mut read = Cipher::new(suite, server_hs.clone());
    let mut pending = Vec::new();
    let (mut certs, mut state, mut bytes) = (Vec::new(), 0, 0);
    let (mut certificate_requested, mut application_settings) = (false, false);
    let mut max_plaintext = tls13::MAX_PLAINTEXT;
    let mut verified = false;
    for _ in 0..64 {
        let (header, mut body) = tls13::read_record(&mut tcp).await?;
        bytes += body.len();
        ensure!(bytes <= LIMIT, "TLS handshake too large");
        ensure!(
            client.fingerprint != Fingerprint::Firefox
                || header[0] != 23
                || body.len() <= tls13::MAX_PLAINTEXT + 17,
            "tls: record_size_limit exceeded"
        );
        if header[0] == 20 {
            ensure!(body == [1], "invalid server CCS");
            continue;
        }
        if header[0] == 21 {
            bail!("tls: received alert {}", body.get(1).copied().unwrap_or(0));
        }
        let (kind, plain) = read.open(&header, &mut body)?;
        if kind == 21 {
            bail!("tls: received alert {}", plain.get(1).copied().unwrap_or(0));
        }
        ensure!(kind == 22, "unexpected TLS handshake record");
        pending.extend_from_slice(&plain);
        while pending.len() >= 4 {
            let len = len24(&pending[1..4]);
            ensure!(len <= LIMIT, "TLS handshake message too large");
            if pending.len() < len + 4 {
                break;
            }
            let message: Vec<u8> = pending.drain(..len + 4).collect();
            let body = &message[4..];
            match (state, message[0]) {
                (0, 8) => {
                    (application_settings, max_plaintext) =
                        encrypted_extensions(body, &client.alpn, client.fingerprint)?;
                    state = 1;
                }
                (1, 13) if !certificate_requested => {
                    validate_certificate_request(body)?;
                    certificate_requested = true;
                }
                (1, 11) | (1, 25) => {
                    certs = if message[0] == 25 {
                        let algorithm = Cursor(body).u16()?;
                        ensure!(
                            client.fingerprint == Fingerprint::Firefox || algorithm == 2,
                            "tls: unoffered certificate compression"
                        );
                        certificates(&decompress_certificate(body)?)?
                    } else {
                        certificates(body)?
                    };
                    verified = auth
                        .as_ref()
                        .is_some_and(|a| reality_verified(&certs[0], a));
                    if !verified {
                        validate_chain(&certs, roots, &client.server_name)?;
                    }
                    state = 2;
                }
                (2, 15) => {
                    verify_certificate_signature(&certs[0], body, suite, &transcript)?;
                    state = 3;
                }
                (3, 20) => {
                    constant_time_equal(body, &suite.finished(&server_hs, &transcript))
                        .map_err(|_| anyhow::anyhow!("tls: server Finished mismatch"))?;
                    transcript.extend_from_slice(&message);
                    ensure!(pending.is_empty(), "unexpected data after server Finished");
                    let (client_ap, server_ap) = schedule.application_traffic(&transcript);
                    let mut write = Cipher::new(suite, client_hs.clone());
                    // crypto/tls buffers the middlebox-compatibility CCS until its Finished flight.
                    let mut flight = CCS.to_vec();
                    if application_settings {
                        let settings = [8, 0, 0, 6, 0, 4, 0x44, 0xcd, 0, 0];
                        flight.extend_from_slice(&write.seal(22, &settings, None)?);
                        transcript.extend_from_slice(&settings);
                    }
                    if certificate_requested {
                        let empty = [11, 0, 0, 4, 0, 0, 0, 0];
                        flight.extend_from_slice(&write.seal(22, &empty, None)?);
                        transcript.extend_from_slice(&empty);
                    }
                    let mut finished = vec![20, 0, 0, suite.hash_len() as u8];
                    finished.extend_from_slice(&suite.finished(&client_hs, &transcript));
                    flight.extend_from_slice(&write.seal(22, &finished, None)?);
                    tcp.write_all(&flight).await?;
                    sent += flight.len() as u64;
                    let (r, w) = tokio::io::split(tcp);
                    let (mut stream, direct) = tls13::stream(
                        r,
                        w,
                        Cipher::new(suite, server_ap),
                        Cipher::new(suite, client_ap),
                        sent,
                    );
                    stream.set_client();
                    stream.set_max_plaintext(max_plaintext);
                    if client.fingerprint == Fingerprint::Firefox {
                        stream.set_max_received(tls13::MAX_PLAINTEXT + 17);
                    }
                    let io: BoxIo = Box::new(stream);
                    if let (Some(reality), false) = (&client.reality, verified) {
                        tracing::error!(
                            "transport/internet/reality: REALITY: received real certificate (potential MITM or redirection)"
                        );
                        let y = reality.spider_y;
                        tokio::spawn(spider(
                            io,
                            client.server_name.clone(),
                            reality.spider_x.clone(),
                            y,
                        ));
                        tokio::time::sleep(Duration::from_millis(rand_between(y[8], y[9]))).await;
                        bail!("REALITY: processed invalid connection");
                    }
                    return Ok((io, direct));
                }
                _ => bail!(
                    "unexpected TLS handshake message {} at state {state}",
                    message[0]
                ),
            }
            transcript.extend_from_slice(&message);
        }
    }
    bail!("too many TLS handshake records")
}

/// EncryptedExtensions: the server may only pick an offered ALPN; ALPS needs h2 (Chrome).
fn encrypted_extensions(
    body: &[u8],
    alpn: &[String],
    fingerprint: Fingerprint,
) -> Result<(bool, usize)> {
    let mut c = Cursor(body);
    let mut selected = None;
    let mut settings = false;
    let mut max_plaintext = tls13::MAX_PLAINTEXT;
    for (id, value) in extensions(c.vector16()?)? {
        match id {
            0 => ensure!(value.is_empty(), "tls: invalid server_name acknowledgement"),
            10 => {
                let mut groups = Cursor(value);
                let list = groups.vector16()?;
                ensure!(
                    !list.is_empty() && list.len().is_multiple_of(2) && groups.0.is_empty(),
                    "tls: invalid supported_groups"
                );
            }
            16 => {
                let mut protocols = Cursor(value);
                let mut list = Cursor(protocols.vector16()?);
                let protocol = list.vector8()?;
                ensure!(
                    protocols.0.is_empty()
                        && list.0.is_empty()
                        && alpn.iter().any(|p| p.as_bytes() == protocol),
                    "tls: server selected unadvertised ALPN protocol"
                );
                selected = Some(protocol.to_vec());
            }
            28 => {
                ensure!(
                    fingerprint == Fingerprint::Firefox,
                    "tls: unoffered record_size_limit"
                );
                let mut limit = Cursor(value);
                let size = limit.u16()? as usize;
                ensure!(
                    limit.0.is_empty() && (64..=tls13::MAX_PLAINTEXT + 1).contains(&size),
                    "tls: invalid record_size_limit"
                );
                // TLS 1.3 record_size_limit includes the inner content type.
                max_plaintext = size - 1;
            }
            0x44cd => settings = true,
            0xfe0d => {} // ECH GREASE retry configurations are not used.
            _ => bail!("tls: unexpected EncryptedExtensions extension {id}"),
        }
    }
    ensure!(c.0.is_empty(), "trailing encrypted extensions");
    ensure!(
        !settings
            || (fingerprint == Fingerprint::Chrome
                && selected.as_deref() == Some(b"h2".as_slice())),
        "tls: unoffered application settings"
    );
    Ok((settings, max_plaintext))
}

fn rand_between(from: i64, to: i64) -> u64 {
    let (from, to) = (from.max(0) as u64, to.max(0) as u64);
    if to <= from {
        return from;
    }
    from + u64::from_le_bytes(random::<8>().unwrap_or_default()) % (to - from)
}

static SPIDER_PATHS: LazyLock<Mutex<HashMap<String, HashSet<String>>>> =
    LazyLock::new(Mutex::default);

fn spider_path(server_name: &str) -> String {
    let paths = SPIDER_PATHS.lock().unwrap();
    let Some(set) = paths.get(server_name) else {
        return "/".into();
    };
    let stop = rand_between(0, set.len() as i64) as usize;
    set.iter().nth(stop).cloned().unwrap_or_else(|| "/".into())
}

/// REALITY's spider: browse the real site over the unverified connection (HTTP/2) so the
/// connection looks like a browser's, learning links from each page.
async fn spider(io: BoxIo, server_name: String, spider_x: String, y: [i64; 10]) -> Result<()> {
    use http_body_util::BodyExt;
    static HREF: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r#"href="([/h].*?)""#).expect("valid regex"));
    let (sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(io),
    )
    .await?;
    tokio::spawn(conn);
    let prefix = format!("https://{server_name}");
    SPIDER_PATHS
        .lock()
        .unwrap()
        .entry(server_name.clone())
        .or_insert_with(|| HashSet::from([spider_x]));
    let first_url = format!("{prefix}{}", spider_path(&server_name));
    let get = |first: bool| {
        let (mut sender, prefix, server_name, first_url) = (
            sender.clone(),
            prefix.clone(),
            server_name.clone(),
            first_url.clone(),
        );
        async move {
            let times = if first { 1 } else { rand_between(y[4], y[5]) };
            let mut url = if first {
                first_url.clone()
            } else {
                format!("{prefix}{}", spider_path(&server_name))
            };
            let mut referer = (!first).then(|| first_url.clone());
            for _ in 0..times {
                let mut request = http::Request::get(&url);
                for (k, v) in crate::browser::chrome_headers("nav", |_| false) {
                    request = request.header(k, v);
                }
                if let Some(r) = &referer {
                    request = request.header("Referer", r);
                }
                let padding = "0".repeat(rand_between(y[0], y[1]) as usize);
                request = request.header("Cookie", format!("padding={padding}"));
                let Ok(request) = request.body(http_body_util::Empty::<bytes::Bytes>::new()) else {
                    return;
                };
                let Ok(response) = sender.send_request(request).await else {
                    return;
                };
                let Ok(body) = http_body_util::Limited::new(response.into_body(), LIMIT)
                    .collect()
                    .await
                else {
                    return;
                };
                let body = body.to_bytes();
                referer = Some(url.clone());
                {
                    let mut paths = SPIDER_PATHS.lock().unwrap();
                    let set = paths.entry(server_name.clone()).or_default();
                    for m in HREF.captures_iter(&String::from_utf8_lossy(&body)) {
                        let path = m[1].trim_start_matches(prefix.as_str()).to_owned();
                        if set.len() >= 1024 {
                            break;
                        }
                        if path.starts_with('/') && path.len() <= 4096 && !path.contains('.') {
                            set.insert(path);
                        }
                    }
                }
                url = format!("{prefix}{}", spider_path(&server_name));
                if !first {
                    tokio::time::sleep(Duration::from_millis(rand_between(y[6], y[7]))).await;
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(30), get(true)).await?;
    for _ in 0..rand_between(y[2], y[3]) {
        tokio::spawn(tokio::time::timeout(Duration::from_secs(30), get(false)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exts(hello: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut c = Cursor(&hello[38..]);
        c.vector8().unwrap();
        c.vector16().unwrap();
        c.vector8().unwrap();
        extensions(c.vector16().unwrap())
            .unwrap()
            .into_iter()
            .map(|(id, b)| (id, b.to_vec()))
            .collect()
    }

    #[test]
    fn rejects_malformed_alpn_and_client_hello_inputs() {
        let alpn = vec!["h2".to_owned()];
        // The selected protocol list must consume the entire ALPN extension.
        let malformed = [0, 10, 0, 16, 0, 6, 0, 3, 2, b'h', b'2', 0];
        assert!(encrypted_extensions(&malformed, &alpn, Fingerprint::Chrome).is_err());
        for name in ["x".repeat(254), "host\0name".into()] {
            assert!(client_hello(Fingerprint::Chrome, &name, &alpn, &[0; 32]).is_err());
        }
        for protocols in [vec![String::new()], vec!["x".repeat(256)]] {
            assert!(
                client_hello(Fingerprint::Chrome, "example.com", &protocols, &[0; 32]).is_err()
            );
        }
    }

    #[test]
    fn rejects_unoffered_or_malformed_encrypted_extensions() {
        for extension in [
            vec![0, 42, 0, 0],          // early_data was not offered
            vec![0, 43, 0, 2, 3, 4],    // supported_versions belongs in ServerHello
            vec![0, 0, 0, 1, 0],        // server_name acknowledgement must be empty
            vec![0, 28, 0, 2, 0x40, 1], // Chrome did not offer record_size_limit
        ] {
            let mut body = Vec::new();
            put16(&mut body, &extension);
            assert!(encrypted_extensions(&body, &["h2".into()], Fingerprint::Chrome).is_err());
        }
    }

    #[test]
    fn compressed_certificate_bounds_zstd_window_memory() {
        // A valid empty Zstandard frame advertising a 64 MiB history window.
        let frame = [0x28, 0xb5, 0x2f, 0xfd, 0, 0x80, 1, 0, 0];
        let mut body = vec![0, 3, 0, 0, 0, 0, 0, frame.len() as u8];
        body.extend_from_slice(&frame);
        assert!(decompress_certificate(&body).is_err());
    }

    #[test]
    fn firefox_negotiates_record_size_limit() {
        let body = [0, 6, 0, 28, 0, 2, 0, 64];
        assert_eq!(
            encrypted_extensions(&body, &["h2".into()], Fingerprint::Firefox).unwrap(),
            (false, 63)
        );
        for size in [0u16, 63, 16386, u16::MAX] {
            let mut invalid = body;
            invalid[6..].copy_from_slice(&size.to_be_bytes());
            assert!(encrypted_extensions(&invalid, &["h2".into()], Fingerprint::Firefox).is_err());
        }
    }

    #[tokio::test]
    async fn spider_bounds_response_size_and_learned_paths() {
        use std::{convert::Infallible, sync::Arc};
        for oversized in [false, true] {
            let name = format!("spider-limit-{oversized}.example");
            let (client, server) = tokio::io::duplex(65536);
            let body = if oversized {
                format!("<a href=\"/oversized\">{}</a>", "x".repeat(LIMIT))
            } else {
                (0..1100)
                    .map(|i| format!("<a href=\"/page{i}\">link</a>"))
                    .collect::<String>()
            };
            let body = Arc::new(bytes::Bytes::from(body));
            let server = tokio::spawn(async move {
                hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(server),
                        hyper::service::service_fn(move |_| {
                            let body = body.clone();
                            async move {
                                Ok::<_, Infallible>(http::Response::new(http_body_util::Full::new(
                                    (*body).clone(),
                                )))
                            }
                        }),
                    )
                    .await
            });
            tokio::time::timeout(
                Duration::from_secs(2),
                spider(Box::new(client), name.clone(), "/".into(), [0; 10]),
            )
            .await
            .unwrap()
            .unwrap();
            server.abort();
            let mut paths = SPIDER_PATHS.lock().unwrap();
            let paths = paths.remove(&name).unwrap();
            if oversized {
                assert_eq!(paths, HashSet::from(["/".into()]));
            } else {
                assert!(paths.len() <= 1024, "{} learned paths", paths.len());
            }
        }
    }

    #[test]
    fn rejects_noncontributory_reality_key() {
        let reality = Reality {
            public_key: [0; 32],
            short_id: [0; 8],
            spider_x: "/".into(),
            spider_y: [0; 10],
        };
        let (mut hello, keys) =
            client_hello(Fingerprint::Chrome, "example.com", &[], &[0; 32]).unwrap();
        assert!(seal_reality_session(&mut hello, &keys.x25519, &reality).is_err());
    }

    async fn reject_handshake_message(
        fingerprint: Fingerprint,
        message: Vec<u8>,
        pad_to: Option<usize>,
    ) -> String {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            use tokio::io::AsyncReadExt;
            let mut header = [0; 5];
            tcp.read_exact(&mut header).await.unwrap();
            let mut hello = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
            tcp.read_exact(&mut hello).await.unwrap();
            let mut c = Cursor(&hello[38..]);
            let session = c.vector8().unwrap();
            c.vector16().unwrap();
            c.vector8().unwrap();
            let exts = extensions(c.vector16().unwrap()).unwrap();
            let shares = exts.iter().find(|(id, _)| *id == 51).unwrap().1;
            let mut list = Cursor(Cursor(shares).vector16().unwrap());
            let mut client_key = None;
            while !list.0.is_empty() {
                let group = list.u16().unwrap();
                let share = list.vector16().unwrap();
                if group == 0x001d {
                    client_key = Some(PublicKey::from(<[u8; 32]>::try_from(share).unwrap()));
                }
            }
            let secret = StaticSecret::from([7; 32]);
            let mut sh = vec![2, 0, 0, 0, 3, 3];
            sh.extend_from_slice(&[9; 32]);
            sh.push(session.len() as u8);
            sh.extend_from_slice(session);
            sh.extend_from_slice(&[0x13, 1, 0]);
            let mut exts = vec![0, 43, 0, 2, 3, 4, 0, 51, 0, 36, 0, 29, 0, 32];
            exts.extend_from_slice(PublicKey::from(&secret).as_bytes());
            put16(&mut sh, &exts);
            let len = sh.len() - 4;
            sh[1..4].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
            let shared = secret.diffie_hellman(&client_key.unwrap());
            let mut transcript = hello;
            transcript.extend_from_slice(&sh);
            let (_, server_secret) = Schedule::new(tls13::Suite::Aes128Gcm, shared.as_bytes())
                .handshake_traffic(&transcript);
            let mut flight = vec![22, 3, 3];
            put16(&mut flight, &sh);
            let mut content = vec![8, 0, 0, 2, 0, 0];
            content.extend_from_slice(&message);
            flight.extend_from_slice(
                &Cipher::new(tls13::Suite::Aes128Gcm, server_secret)
                    .seal(22, &content, pad_to)
                    .unwrap(),
            );
            tcp.write_all(&flight).await.unwrap();
        });
        let client = Client {
            server_name: "example.com".into(),
            fingerprint,
            alpn: vec!["h2".into()],
            reality: None,
        };
        let error = match connect(TcpStream::connect(address).await.unwrap(), &client).await {
            Ok(_) => panic!("malformed handshake accepted"),
            Err(error) => format!("{error:#}"),
        };
        peer.await.unwrap();
        error
    }

    #[tokio::test]
    async fn rejects_invalid_certificate_request_before_waiting_for_a_certificate() {
        for body in [vec![1, 1, 0, 0], vec![0, 0, 0], vec![0, 0, 4, 0, 13, 0, 0]] {
            let mut message = vec![13, 0, 0, body.len() as u8];
            message.extend_from_slice(&body);
            let error = reject_handshake_message(Fingerprint::Chrome, message, None).await;
            assert!(error.contains("CertificateRequest"), "{error}");
        }
    }

    #[tokio::test]
    async fn firefox_rejects_padding_beyond_advertised_record_limit() {
        let error = reject_handshake_message(
            Fingerprint::Firefox,
            vec![255, 0, 0, 0],
            Some(tls13::RECORD_HEADER + tls13::MAX_PLAINTEXT + 18),
        )
        .await;
        assert!(error.contains("record_size_limit"), "{error}");
    }

    #[tokio::test]
    async fn chrome_rejects_unoffered_certificate_compression() {
        let error = reject_handshake_message(
            Fingerprint::Chrome,
            vec![25, 0, 0, 8, 0, 1, 0, 0, 1, 0, 0, 0],
            None,
        )
        .await;
        assert!(
            error.contains("unoffered certificate compression"),
            "{error}"
        );
    }

    #[test]
    fn firefox_hello_keeps_order_and_refreshes_keys() {
        let alpn = vec!["http/1.1".to_owned()];
        let (a, _) = client_hello(Fingerprint::Firefox, "probe.example", &alpn, &[1; 32]).unwrap();
        let (b, _) = client_hello(Fingerprint::Firefox, "probe.example", &alpn, &[1; 32]).unwrap();
        let ids = |h: &[u8]| exts(h).iter().map(|(id, _)| *id).collect::<Vec<_>>();
        let template = Fingerprint::Firefox.template();
        assert_eq!(ids(&a), ids(template));
        assert_eq!(ids(&a), ids(&b));
        assert_ne!(a[6..38], b[6..38]);
        assert_eq!(a.len(), template.len() - 3, "only the ALPN list shrinks");
        let alpn_ext = exts(&a).into_iter().find(|(id, _)| *id == 16).unwrap().1;
        assert_eq!(alpn_ext, b"\x00\x09\x08http/1.1");
        let shares = exts(&a).into_iter().find(|(id, _)| *id == 51).unwrap().1;
        assert_eq!(shares.len(), 2 + (4 + 1216) + (4 + 32) + (4 + 65));
        assert_eq!(
            &shares[2 + 4 + 1184..2 + 4 + 1216],
            &shares[2 + 4 + 1216 + 4..][..32]
        );
    }

    #[test]
    fn chrome_hello_randomizes_grease_and_order() {
        let alpn = vec!["h2".to_owned(), "http/1.1".to_owned()];
        let mut orders = HashSet::new();
        for _ in 0..8 {
            let (h, _) = client_hello(Fingerprint::Chrome, "a.example", &alpn, &[0; 32]).unwrap();
            let e = exts(&h);
            assert!(is_grease(e[0].0) && is_grease(e[e.len() - 1].0));
            assert_ne!(e[0].0, e[e.len() - 1].0);
            orders.insert(
                e.iter()
                    .map(|(id, _)| *id)
                    .filter(|id| !is_grease(*id))
                    .collect::<Vec<_>>(),
            );
            let ech = &e.iter().find(|(id, _)| *id == 0xfe0d).unwrap().1;
            assert!([144, 176, 208, 240].contains(&u16::from_be_bytes([ech[40], ech[41]])));
        }
        assert!(orders.len() > 1, "extension order is shuffled");
    }

    #[test]
    fn reality_session_id_opens_with_the_server_key() {
        let server = StaticSecret::from([7u8; 32]);
        let reality = Reality {
            public_key: *PublicKey::from(&server).as_bytes(),
            short_id: [0xab, 0xcd, 0, 0, 0, 0, 0, 0],
            spider_x: "/".into(),
            spider_y: [0; 10],
        };
        let (mut hello, keys) =
            client_hello(Fingerprint::Chrome, "a.example", &[], &[0; 32]).unwrap();
        let aad = hello.clone();
        let auth = seal_reality_session(&mut hello, &keys.x25519, &reality).unwrap();
        // Server side: the same auth key from its private key and the client's X25519 share.
        let shared = server.diffie_hellman(&PublicKey::from(&keys.x25519));
        let mut expected = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&hello[6..26]), shared.as_bytes())
            .expand(b"REALITY", &mut expected)
            .unwrap();
        assert_eq!(auth, expected);
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &auth).unwrap());
        let mut sealed = hello[39..71].to_vec();
        let plain = key
            .open_in_place(
                aead::Nonce::try_assume_unique_for_key(&hello[26..38]).unwrap(),
                aead::Aad::from(&aad[..]),
                &mut sealed,
            )
            .unwrap();
        assert_eq!(&plain[..4], &[26, 11, 9, 0]);
        assert_eq!(&plain[8..10], &[0xab, 0xcd]);
    }
}

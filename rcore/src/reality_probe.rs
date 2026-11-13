//! Bounded native TLS 1.3 probes for REALITY's target record and CCS camouflage.
use crate::tls13::{self, Cipher, Schedule, Suite};
use anyhow::{Context, Result, bail, ensure};
use ml_kem::{Decapsulate, KeyExport, ml_kem_768::DecapsulationKey};
use ring::rand::{SecureRandom, SystemRandom};
use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use std::{io::Read, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout, timeout_at},
};
use x25519_dalek::{PublicKey, StaticSecret};

const CCS: &[u8] = &[20, 3, 3, 0, 1, 1];
const LIMIT: usize = 1024 * 1024;
const MAX_RECORDS: usize = 64;

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub records: Vec<usize>,
    pub max_ccs: usize,
}
impl Default for ProbeResult {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            max_ccs: 32,
        }
    }
}

/// The two independent Go probes share a deadline but never discard each other's results.
pub async fn probe(dest: &str, server_name: &str, alpn: u8) -> Result<ProbeResult> {
    ensure!(alpn <= 2, "invalid probe ALPN bucket");
    let roots = roots()?;
    let records = async {
        let mut handshake = handshake(dest, server_name, alpn, &roots).await?;
        let mut flight = CCS.to_vec();
        flight.extend_from_slice(&handshake.finished);
        handshake.socket.write_all(&flight).await?;
        collect_records(&mut handshake.socket).await
    };
    let ccs = async {
        let handshake = handshake(dest, server_name, alpn, &roots).await?;
        probe_ccs(handshake.socket).await
    };
    let (records, ccs) = tokio::join!(
        timeout(Duration::from_secs(10), records),
        timeout(Duration::from_secs(10), ccs)
    );
    let mut result = ProbeResult::default();
    match records {
        Ok(Ok(records)) => result.records = records,
        other => tracing::debug!(
            ?other,
            dest,
            server_name,
            alpn,
            "REALITY record probe failed"
        ),
    }
    match ccs {
        Ok(Ok(max_ccs)) => result.max_ccs = max_ccs,
        other => tracing::debug!(?other, dest, server_name, alpn, "REALITY CCS probe failed"),
    }
    Ok(result)
}

pub(crate) fn roots() -> Result<Vec<TrustAnchor<'static>>> {
    let mut roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();
    if let Some(path) = std::env::var_os("SSL_CERT_FILE") {
        let file = std::fs::File::open(path).context("open probe SSL_CERT_FILE")?;
        for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(file)) {
            roots.push(webpki::anchor_from_trusted_cert(&cert?)?.to_owned());
        }
    }
    Ok(roots)
}

struct Keys {
    x25519: StaticSecret,
    hybrid_x25519: StaticSecret,
    mlkem: DecapsulationKey,
}

/// Refresh every cryptographic field in the pinned uTLS fingerprint.
fn client_hello(server_name: &str, alpn: u8) -> Result<(Vec<u8>, Keys)> {
    let template: &[u8] = match alpn {
        0 => include_bytes!("../tests/fixtures/clienthello-golang.bin"),
        1 => include_bytes!("../tests/fixtures/clienthello-golang-http1.bin"),
        2 => include_bytes!("../tests/fixtures/clienthello-chrome155.bin"),
        _ => bail!("invalid probe ALPN bucket"),
    };
    ensure!(
        server_name.len() <= 253 && !server_name.as_bytes().contains(&0),
        "invalid probe server name"
    );
    let random = SystemRandom::new();
    let mut seed = [0u8; 64];
    random
        .fill(&mut seed)
        .map_err(|_| anyhow::anyhow!("probe random failed"))?;
    let mlkem = DecapsulationKey::from_seed(seed.into());
    let mut secret = [0u8; 32];
    random
        .fill(&mut secret)
        .map_err(|_| anyhow::anyhow!("probe random failed"))?;
    let x25519 = StaticSecret::from(secret);
    let public = PublicKey::from(&x25519);
    if alpn == 2 {
        random
            .fill(&mut secret)
            .map_err(|_| anyhow::anyhow!("probe random failed"))?;
    }
    let hybrid_x25519 = StaticSecret::from(secret);
    let hybrid_public = PublicKey::from(&hybrid_x25519);
    let mut hello = template[..38].to_vec();
    random
        .fill(&mut hello[6..38])
        .map_err(|_| anyhow::anyhow!("probe random failed"))?;
    let mut c = Cursor(&template[38..]);
    let session = c.vector8()?;
    hello.push(session.len() as u8);
    let mut fresh_session = vec![0; session.len()];
    random
        .fill(&mut fresh_session)
        .map_err(|_| anyhow::anyhow!("probe random failed"))?;
    hello.extend_from_slice(&fresh_session);
    put16(&mut hello, c.vector16()?);
    let compression = c.vector8()?;
    hello.push(compression.len() as u8);
    hello.extend_from_slice(compression);
    let mut exts = Vec::new();
    for (id, body) in extensions(c.vector16()?)? {
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
            0xfe0d => {
                let mut ech = body.to_vec();
                // ECH GREASE outer: type, cipher suite, config ID, enc vector, payload vector.
                let mut c = Cursor(body);
                ensure!(c.take(1)? == [0], "invalid ECH GREASE template");
                c.take(5)?;
                let enc_len = c.u16()? as usize;
                ensure!(enc_len == 32, "invalid ECH X25519 encapsulated key length");
                c.take(enc_len)?;
                let payload_len = c.u16()? as usize;
                c.take(payload_len)?;
                ensure!(c.0.is_empty(), "invalid ECH GREASE template lengths");
                let mut ech_secret = [0; 32];
                random
                    .fill(&mut ech_secret)
                    .map_err(|_| anyhow::anyhow!("probe random failed"))?;
                ech[8..8 + enc_len]
                    .copy_from_slice(PublicKey::from(&StaticSecret::from(ech_secret)).as_bytes());
                random
                    .fill(&mut ech[5..6])
                    .map_err(|_| anyhow::anyhow!("probe random failed"))?;
                random
                    .fill(&mut ech[10 + enc_len..])
                    .map_err(|_| anyhow::anyhow!("probe random failed"))?;
                ech
            }
            51 => {
                let mut shares = Vec::new();
                let mut c = Cursor(body);
                let mut list = Cursor(c.vector16()?);
                while !list.0.is_empty() {
                    let group = list.u16()?;
                    let old = list.vector16()?;
                    shares.extend_from_slice(&group.to_be_bytes());
                    match group {
                        0x11ec => {
                            let mut hybrid = mlkem.encapsulation_key().to_bytes().to_vec();
                            hybrid.extend_from_slice(hybrid_public.as_bytes());
                            put16(&mut shares, &hybrid);
                        }
                        0x001d => put16(&mut shares, public.as_bytes()),
                        // GREASE shares are opaque and do not negotiate a real group.
                        n if n & 0x0f0f == 0x0a0a => put16(&mut shares, old),
                        _ => bail!("unsupported probe key share"),
                    }
                }
                let mut body = Vec::new();
                put16(&mut body, &shares);
                body
            }
            _ => body.to_vec(),
        };
        exts.extend_from_slice(&id.to_be_bytes());
        put16(&mut exts, &body);
    }
    put16(&mut hello, &exts);
    let len = hello.len() - 4;
    hello[1..4].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
    Ok((
        hello,
        Keys {
            x25519,
            hybrid_x25519,
            mlkem,
        },
    ))
}

struct Handshake {
    socket: TcpStream,
    finished: Vec<u8>,
}

async fn handshake(
    dest: &str,
    server_name: &str,
    alpn: u8,
    roots: &[TrustAnchor<'_>],
) -> Result<Handshake> {
    let (hello, keys) = client_hello(server_name, alpn)?;
    let session_len = hello[38] as usize;
    let session = &hello[39..39 + session_len];
    let mut socket = TcpStream::connect(dest).await?;
    let mut record = vec![22, 3, 1];
    put16(&mut record, &hello);
    socket.write_all(&record).await?;
    let sh = read_server_hello(&mut socket).await?;
    let (suite, group, share) = server_hello(&sh[4..], session)?;
    let (peer, mlkem_shared) = match group {
        0x001d => {
            ensure!(share.len() == 32, "invalid X25519 server share");
            (share, Vec::new())
        }
        0x11ec => {
            ensure!(share.len() == 1088 + 32, "invalid hybrid server share");
            let ct = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(&share[..1088])
                .map_err(|_| anyhow::anyhow!("invalid ML-KEM ciphertext"))?;
            (&share[1088..], keys.mlkem.decapsulate(&ct).to_vec())
        }
        _ => bail!("target selected unsupported key share"),
    };
    let public = PublicKey::from(<[u8; 32]>::try_from(peer)?);
    let secret = if group == 0x11ec {
        &keys.hybrid_x25519
    } else {
        &keys.x25519
    };
    let shared = secret.diffie_hellman(&public);
    ensure!(
        shared.was_contributory(),
        "invalid all-zero target X25519 share"
    );
    let mut hybrid = mlkem_shared;
    hybrid.extend_from_slice(shared.as_bytes());
    let schedule = Schedule::new(suite, &hybrid);
    let mut transcript = hello;
    transcript.extend_from_slice(&sh);
    let (client_secret, server_secret) = schedule.handshake_traffic(&transcript);
    let mut read = Cipher::new(suite, server_secret.clone());
    let mut pending = Vec::new();
    let mut certs = Vec::new();
    let mut state = 0;
    let mut certificate_requested = false;
    let mut application_settings = false;
    let mut bytes = 0;
    for _ in 0..MAX_RECORDS {
        let (header, mut body) = tls13::read_record(&mut socket).await?;
        bytes += body.len();
        ensure!(bytes <= LIMIT, "probe handshake too large");
        if header[0] == 20 {
            ensure!(body == [1], "invalid server CCS");
            continue;
        }
        let (kind, plain) = read.open(&header, &mut body)?;
        ensure!(kind == 22, "unexpected probe handshake record");
        pending.extend_from_slice(&plain);
        while pending.len() >= 4 {
            let len = len24(&pending[1..4]);
            ensure!(len <= LIMIT, "probe handshake message too large");
            if pending.len() < len + 4 {
                break;
            }
            let message: Vec<u8> = pending.drain(..len + 4).collect();
            let body = &message[4..];
            match (state, message[0]) {
                (0, 8) => {
                    application_settings = encrypted_extensions(body, alpn)?;
                    state = 1;
                }
                (1, 13) if !certificate_requested => {
                    validate_certificate_request(body)?;
                    certificate_requested = true;
                }
                (1, 11) | (1, 25) => {
                    ensure!(
                        message[0] != 25 || alpn == 2,
                        "unoffered certificate compression"
                    );
                    certs = if message[0] == 25 {
                        certificates(&decompress_certificate(body)?)?
                    } else {
                        certificates(body)?
                    };
                    validate_chain(&certs, roots, server_name)?;
                    state = 2;
                }
                (2, 15) => {
                    verify_certificate_signature(&certs[0], body, suite, &transcript)?;
                    state = 3;
                }
                (3, 20) => {
                    constant_time_equal(body, &suite.finished(&server_secret, &transcript))?;
                    transcript.extend_from_slice(&message);
                    ensure!(pending.is_empty(), "unexpected data after server Finished");
                    let mut write = Cipher::new(suite, client_secret.clone());
                    let mut finished = Vec::new();
                    if application_settings {
                        let settings = [8, 0, 0, 6, 0, 4, 0x44, 0xcd, 0, 0];
                        finished.extend_from_slice(&write.seal(22, &settings, None)?);
                        transcript.extend_from_slice(&settings);
                    }
                    if certificate_requested {
                        let empty_certificate = [11, 0, 0, 4, 0, 0, 0, 0];
                        finished.extend_from_slice(&write.seal(22, &empty_certificate, None)?);
                        transcript.extend_from_slice(&empty_certificate);
                    }
                    let mut message = vec![20, 0, 0, suite.hash_len() as u8];
                    message.extend_from_slice(&suite.finished(&client_secret, &transcript));
                    finished.extend_from_slice(&write.seal(22, &message, None)?);
                    return Ok(Handshake { socket, finished });
                }
                _ => bail!(
                    "unexpected probe handshake message {} at state {state}",
                    message[0]
                ),
            }
            transcript.extend_from_slice(&message);
        }
    }
    bail!("too many probe handshake records")
}

#[allow(deprecated)]
pub(crate) fn constant_time_equal(a: &[u8], b: &[u8]) -> Result<()> {
    ring::constant_time::verify_slices_are_equal(a, b)
        .map_err(|_| anyhow::anyhow!("target Finished mismatch"))
}

pub(crate) async fn read_server_hello<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut hello = Vec::new();
    for _ in 0..MAX_RECORDS {
        let (header, body) = tls13::read_record(reader).await?;
        ensure!(header[0] == 22, "invalid probe ServerHello record");
        hello.extend_from_slice(&body);
        ensure!(hello.len() <= LIMIT, "ServerHello too large");
        if hello.len() >= 4 {
            ensure!(hello[0] == 2, "missing probe ServerHello");
            let len = len24(&hello[1..4]) + 4;
            ensure!(
                len <= LIMIT && hello.len() <= len,
                "invalid ServerHello length"
            );
            if hello.len() == len {
                return Ok(hello);
            }
        }
    }
    bail!("too many ServerHello records")
}

pub(crate) fn server_hello<'a>(body: &'a [u8], session: &[u8]) -> Result<(Suite, u16, &'a [u8])> {
    let mut c = Cursor(body);
    ensure!(c.u16()? == 0x0303, "invalid ServerHello legacy version");
    let random = c.take(32)?;
    ensure!(
        random
            != [
                0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
                0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
                0xc8, 0xa8, 0x33, 0x9c
            ],
        "target requires unsupported HelloRetryRequest"
    );
    ensure!(c.vector8()? == session, "ServerHello session mismatch");
    let suite = Suite::by_id(c.u16()?).context("target does not support probe TLS 1.3 suites")?;
    ensure!(c.take(1)? == [0], "invalid ServerHello compression");
    let mut key = None;
    let mut version = false;
    for (id, value) in extensions(c.vector16()?)? {
        match id {
            43 => {
                ensure!(value == [3, 4] && !version, "invalid ServerHello version");
                version = true;
            }
            51 => {
                ensure!(key.is_none(), "duplicate ServerHello key share");
                let mut k = Cursor(value);
                let group = k.u16()?;
                let share = k.vector16()?;
                ensure!(k.0.is_empty(), "trailing ServerHello key share");
                key = Some((group, share));
            }
            _ => bail!("unexpected ServerHello extension {id}"),
        }
    }
    ensure!(version && c.0.is_empty(), "invalid TLS 1.3 ServerHello");
    let (group, share) = key.context("missing ServerHello key share")?;
    Ok((suite, group, share))
}

fn encrypted_extensions(body: &[u8], alpn: u8) -> Result<bool> {
    let mut c = Cursor(body);
    let mut selected_protocol = None;
    let mut application_settings = false;
    for (id, value) in extensions(c.vector16()?)? {
        if id == 16 {
            let mut protocols = Cursor(value);
            let mut selected = Cursor(protocols.vector16()?);
            let protocol = selected.vector8()?;
            selected_protocol = Some(protocol);
            ensure!(
                selected.0.is_empty()
                    && protocols.0.is_empty()
                    && ((alpn == 1 && protocol == b"http/1.1")
                        || (alpn == 2 && (protocol == b"h2" || protocol == b"http/1.1"))),
                "target selected unoffered ALPN"
            );
        } else if id == 17613 {
            application_settings = true;
        }
    }
    ensure!(c.0.is_empty(), "trailing encrypted extensions");
    ensure!(
        !application_settings || (alpn == 2 && selected_protocol == Some(b"h2".as_slice())),
        "unoffered application settings"
    );
    Ok(application_settings)
}

fn decompress_certificate(body: &[u8]) -> Result<Vec<u8>> {
    let mut c = Cursor(body);
    ensure!(c.u16()? == 2, "unsupported certificate compression");
    let len = len24(c.take(3)?);
    ensure!(len <= LIMIT, "compressed certificate too large");
    let compressed_len = len24(c.take(3)?);
    let compressed = c.take(compressed_len)?;
    ensure!(c.0.is_empty(), "trailing compressed certificate");
    let mut out = Vec::new();
    brotli::Decompressor::new(compressed, 4096)
        .take(len as u64 + 1)
        .read_to_end(&mut out)?;
    ensure!(out.len() == len, "invalid decompressed certificate length");
    Ok(out)
}

pub(crate) fn validate_certificate_request(body: &[u8]) -> Result<()> {
    let mut request = Cursor(body);
    ensure!(
        request.vector8()?.is_empty(),
        "invalid CertificateRequest context"
    );
    let exts = extensions(request.vector16()?)?;
    ensure!(request.0.is_empty(), "trailing CertificateRequest data");
    let schemes = exts
        .iter()
        .find(|(id, _)| *id == 13)
        .context("CertificateRequest missing signature_algorithms")?
        .1;
    let mut schemes = Cursor(schemes);
    let list = schemes
        .vector16()
        .context("invalid CertificateRequest signature_algorithms")?;
    ensure!(
        !list.is_empty() && list.len().is_multiple_of(2) && schemes.0.is_empty(),
        "invalid CertificateRequest signature_algorithms"
    );
    Ok(())
}

pub(crate) fn certificates(body: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut c = Cursor(body);
    ensure!(
        c.vector8()?.is_empty(),
        "unexpected certificate request context"
    );
    let list_len = len24(c.take(3)?);
    let mut list = Cursor(c.take(list_len)?);
    ensure!(c.0.is_empty(), "trailing certificate data");
    let mut certs = Vec::new();
    while !list.0.is_empty() {
        ensure!(certs.len() < 32, "too many target certificates");
        let len = len24(list.take(3)?);
        ensure!(len > 0, "empty target certificate");
        certs.push(CertificateDer::from(list.take(len)?.to_vec()));
        extensions(list.vector16()?)?;
    }
    ensure!(!certs.is_empty(), "missing target certificate");
    Ok(certs)
}

pub(crate) fn validate_chain(
    certs: &[CertificateDer<'_>],
    roots: &[TrustAnchor<'_>],
    server_name: &str,
) -> Result<()> {
    if server_name.is_empty() {
        return Ok(());
    } // Go sets InsecureSkipVerify only for empty SNI.
    let cert = webpki::EndEntityCert::try_from(&certs[0])?;
    cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        roots,
        &certs[1..],
        UnixTime::now(),
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )?;
    cert.verify_is_valid_for_subject_name(&ServerName::try_from(server_name)?)?;
    Ok(())
}

pub(crate) fn verify_certificate_signature(
    cert: &CertificateDer<'_>,
    body: &[u8],
    suite: Suite,
    transcript: &[u8],
) -> Result<()> {
    let mut c = Cursor(body);
    let scheme = c.u16()?;
    let signature = c.vector16()?;
    ensure!(c.0.is_empty(), "trailing CertificateVerify data");
    let algorithm = match scheme {
        0x0403 => webpki::ring::ECDSA_P256_SHA256,
        0x0503 => webpki::ring::ECDSA_P384_SHA384,
        0x0804 => webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        0x0805 => webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        0x0806 => webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        0x0807 => webpki::ring::ED25519,
        _ => bail!("unsupported target CertificateVerify scheme {scheme:#06x}"),
    };
    let mut message = vec![32; 64];
    message.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    message.extend_from_slice(&suite.hash(transcript));
    webpki::EndEntityCert::try_from(cert)?.verify_signature(algorithm, &message, signature)?;
    Ok(())
}

async fn collect_records<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<usize>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut records = Vec::new();
    let mut bytes = 0;
    while records.len() < MAX_RECORDS {
        let Ok(Ok((header, body))) = timeout_at(deadline, tls13::read_record(reader)).await else {
            break;
        };
        if header[0] != 23 || body.len() < 17 {
            break;
        }
        bytes += body.len() + 5;
        if bytes > LIMIT {
            break;
        }
        records.push(body.len() + 5);
    }
    Ok(records)
}

async fn probe_ccs(socket: TcpStream) -> Result<usize> {
    let (mut reader, mut writer) = socket.into_split();
    let observe = async {
        loop {
            match tls13::read_record(&mut reader).await {
                Ok((header, _)) if header[0] != 21 => (),
                _ => return,
            }
        }
    };
    tokio::pin!(observe);
    for (count, limit) in [(2, 1), (15, 16), (16, 32)] {
        if writer.write_all(&CCS.repeat(count)).await.is_err() {
            return Ok(limit);
        }
        tokio::select! {
            _ = &mut observe => return Ok(limit),
            _ = tokio::time::sleep(Duration::from_secs(1)) => (),
        }
    }
    Ok(usize::MAX)
}

pub(crate) struct Cursor<'a>(pub(crate) &'a [u8]);
impl<'a> Cursor<'a> {
    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= len, "truncated probe handshake");
        let (value, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(value)
    }
    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?))
    }
    pub(crate) fn vector8(&mut self) -> Result<&'a [u8]> {
        let len = self.take(1)?[0] as usize;
        self.take(len)
    }
    pub(crate) fn vector16(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }
}
pub(crate) fn len24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
}
pub(crate) fn put16(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}
pub(crate) fn extensions(bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut c = Cursor(bytes);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while !c.0.is_empty() {
        let id = c.u16()?;
        ensure!(seen.insert(id), "duplicate probe extension");
        out.push((id, c.vector16()?));
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_include_wire_header_and_stop_before_non_application_record() {
        let (mut tx, mut rx) = tokio::io::duplex(128);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut data = vec![23, 3, 3, 0, 17];
            data.extend_from_slice(&[1; 17]);
            data.extend_from_slice(&[23, 3, 3, 0, 18]);
            data.extend_from_slice(&[2; 18]);
            data.extend_from_slice(&[21, 3, 3, 0, 2, 2, 0]);
            tx.write_all(&data).await.unwrap();
        });
        assert_eq!(collect_records(&mut rx).await.unwrap(), vec![22, 23]);
    }

    #[tokio::test]
    async fn truncated_record_is_not_learned() {
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(&[23, 3, 3, 0, 4, 1]).await.unwrap();
        });
        assert!(collect_records(&mut rx).await.unwrap().is_empty());
    }

    #[test]
    fn handshake_parser_rejects_truncation_without_panicking() {
        assert!(certificates(&[0, 0, 0, 4, 0, 0]).is_err());
        assert!(server_hello(&[0; 40], &[0; 32]).is_err());
    }

    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::sync::Arc;
    use tokio_rustls::{
        TlsAcceptor,
        rustls::{self, pki_types::PrivateKeyDer},
    };

    fn fixture_certs() -> (
        CertificateDer<'static>,
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
    ) {
        (
            CertificateDer::from(STANDARD.decode(CA).unwrap()),
            CertificateDer::from(STANDARD.decode(CERT).unwrap()),
            PrivateKeyDer::Pkcs8(STANDARD.decode(KEY).unwrap().into()),
        )
    }

    #[derive(Debug)]
    struct BrotliCompressor;
    impl rustls::compress::CertCompressor for BrotliCompressor {
        fn compress(
            &self,
            input: Vec<u8>,
            _: rustls::compress::CompressionLevel,
        ) -> std::result::Result<Vec<u8>, rustls::compress::CompressionFailed> {
            use std::io::Write;
            let mut out = Vec::new();
            {
                brotli::CompressorWriter::new(&mut out, 4096, 4, 22)
                    .write_all(&input)
                    .map_err(|_| rustls::compress::CompressionFailed)?;
            }
            Ok(out)
        }
        fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
            rustls::CertificateCompressionAlgorithm::Brotli
        }
    }

    async fn tls_server(
        request_certificate: bool,
    ) -> (String, tokio::task::JoinHandle<Result<()>>) {
        let (ca, cert, key) = fixture_certs();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap();
        let builder = if request_certificate {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca).unwrap();
            builder.with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    provider,
                )
                .allow_unauthenticated()
                .build()
                .unwrap(),
            )
        } else {
            builder.with_no_client_auth()
        };
        let mut config = builder.with_single_cert(vec![cert], key).unwrap();
        config.cert_compressors = vec![&BrotliCompressor];
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            let mut tls = TlsAcceptor::from(Arc::new(config)).accept(socket).await?;
            // accept() proves the peer sent an authenticated client Finished.
            tls.flush().await?;
            tokio::time::sleep(Duration::from_millis(20)).await;
            tls.shutdown().await?;
            Ok(())
        });
        (addr, task)
    }

    #[tokio::test]
    async fn verified_native_handshake_sends_finished_and_learns_real_tls_records() {
        let (ca, _, _) = fixture_certs();
        let roots = [webpki::anchor_from_trusted_cert(&ca).unwrap()];
        for (alpn, request_certificate) in (0..=2).flat_map(|alpn| [(alpn, false), (alpn, true)]) {
            let (addr, server) = tls_server(request_certificate).await;
            let mut client = handshake(&addr, "probe.example", alpn, &roots)
                .await
                .unwrap();
            let mut flight = CCS.to_vec();
            flight.extend_from_slice(&client.finished);
            client.socket.write_all(&flight).await.unwrap();
            let records = collect_records(&mut client.socket).await.unwrap();
            assert!(!records.is_empty());
            assert!(records.iter().all(|len| *len >= 22));
            server.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn named_probe_rejects_untrusted_and_mismatched_certificates() {
        let (ca, _, _) = fixture_certs();
        let roots = [webpki::anchor_from_trusted_cert(&ca).unwrap()];
        for (name, roots) in [
            ("probe.example", &[][..]),
            ("other.example", roots.as_slice()),
        ] {
            let (addr, server) = tls_server(false).await;
            assert!(handshake(&addr, name, 1, roots).await.is_err());
            assert!(server.await.unwrap().is_err());
        }
    }

    #[tokio::test]
    async fn ccs_batches_detect_one_sixteen_and_thirty_two_record_limits() {
        for max in [1, 16, 32] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                for _ in 0..=max {
                    let (header, body) = tls13::read_record(&mut socket).await.unwrap();
                    assert_eq!(header[0], 20);
                    assert_eq!(body, [1]);
                }
                socket.write_all(&[21, 3, 3, 0, 2, 2, 10]).await.unwrap();
            });
            assert_eq!(
                probe_ccs(TcpStream::connect(addr).await.unwrap())
                    .await
                    .unwrap(),
                max
            );
            server.await.unwrap();
        }
    }

    #[test]
    fn client_hello_refreshes_random_session_keys_and_preserves_fingerprint_fields() {
        for alpn in 0..=2 {
            let (first, first_keys) = client_hello("changed.example", alpn).unwrap();
            let (second, _) = client_hello("changed.example", alpn).unwrap();
            assert_eq!(len24(&first[1..4]), first.len() - 4);
            assert_ne!(first[6..38], second[6..38]);
            assert_ne!(first[39..71], second[39..71]);
            assert_ne!(first, second);
            assert_eq!(
                PublicKey::from(&first_keys.x25519) == PublicKey::from(&first_keys.hybrid_x25519),
                alpn != 2
            );
            let mut c = Cursor(&first[38..]);
            c.vector8().unwrap();
            c.vector16().unwrap();
            c.vector8().unwrap();
            let exts = extensions(c.vector16().unwrap()).unwrap();
            assert!(exts.iter().any(|(id, _)| *id == 0));
            assert_eq!(exts.iter().any(|(id, _)| *id == 16), alpn != 0);
            if alpn == 2 {
                assert!(
                    exts.iter()
                        .any(|(id, value)| *id == 27 && *value == [2, 0, 2])
                );
            }
        }
    }

    #[test]
    fn compressed_certificate_checks_algorithm_length_and_brotli_stream() {
        let body = [0, 0, 0, 1, 0];
        let mut compressed = Vec::new();
        {
            use std::io::Write;
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 4, 22);
            writer.write_all(&body).unwrap();
        }
        let mut message = vec![0, 2, 0, 0, body.len() as u8];
        message.extend_from_slice(&(compressed.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&compressed);
        assert_eq!(decompress_certificate(&message).unwrap(), body);
        message[4] += 1;
        assert!(decompress_certificate(&message).is_err());
        message[1] = 1;
        assert!(decompress_certificate(&message).is_err());
    }

    #[test]
    fn invalid_certificate_verify_and_finished_are_rejected() {
        let (_, cert, _) = fixture_certs();
        assert!(
            verify_certificate_signature(&cert, &[4, 3, 0, 1, 0], Suite::Aes128Gcm, b"transcript")
                .is_err()
        );
        assert!(constant_time_equal(&[1; 32], &[2; 32]).is_err());
        assert!(constant_time_equal(&[1; 31], &[1; 32]).is_err());
    }

    #[tokio::test]
    async fn record_collection_caps_count_and_rejects_impossible_ciphertext() {
        let mut record = vec![23, 3, 3, 0, 17];
        record.extend_from_slice(&[1; 17]);
        let mut input = record.repeat(MAX_RECORDS + 1).as_slice().to_vec();
        assert_eq!(
            collect_records(&mut input.as_slice()).await.unwrap().len(),
            MAX_RECORDS
        );
        input = vec![23, 3, 3, 0, 1, 0];
        assert!(
            collect_records(&mut input.as_slice())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn application_settings_are_negotiated_only_for_chrome_h2() {
        let body = [0, 13, 0, 16, 0, 5, 0, 3, 2, b'h', b'2', 0x44, 0xcd, 0, 0];
        assert!(encrypted_extensions(&body, 2).unwrap());
        assert!(encrypted_extensions(&body, 1).is_err());
        assert!(encrypted_extensions(&[0, 4, 0x44, 0xcd, 0, 0], 2).is_err());
    }

    #[test]
    fn ech_grease_refreshes_config_id_and_uses_canonical_x25519_encodings() {
        let mut ids = std::collections::BTreeSet::new();
        let mut previous_enc = None;
        for _ in 0..64 {
            let (hello, _) = client_hello("probe.example", 2).unwrap();
            let mut c = Cursor(&hello[38..]);
            c.vector8().unwrap();
            c.vector16().unwrap();
            c.vector8().unwrap();
            let exts = extensions(c.vector16().unwrap()).unwrap();
            let ech = exts.iter().find(|(id, _)| *id == 0xfe0d).unwrap().1;
            assert_eq!(ech[0], 0);
            ids.insert(ech[5]);
            let mut c = Cursor(&ech[6..]);
            let enc = c.vector16().unwrap();
            assert_eq!(enc.len(), 32);
            assert_eq!(enc[31] & 0x80, 0);
            assert!(enc.iter().any(|byte| *byte != 0));
            if let Some(previous) = previous_enc {
                assert_ne!(enc, previous);
            }
            previous_enc = Some(enc.to_vec());
            assert!(!c.vector16().unwrap().is_empty());
            assert!(c.0.is_empty());
        }
        assert!(ids.len() > 1);
    }

    #[tokio::test]
    async fn server_hello_can_span_records_without_unbounded_buffering() {
        let wire = [22, 3, 3, 0, 2, 2, 0, 22, 3, 3, 0, 5, 0, 3, 1, 2, 3];
        assert_eq!(
            read_server_hello(&mut wire.as_slice()).await.unwrap(),
            [2, 0, 0, 3, 1, 2, 3]
        );
        assert!(
            read_server_hello(&mut [22, 3, 3, 0, 4, 2, 255, 255, 255].as_slice())
                .await
                .is_err()
        );
    }
    const CA: &str = "MIIBfzCCASagAwIBAgIUCzOFqaLiRnB3l7kEK4VRBkaVHOEwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTcmNvcmUgcHJvYmUgdGVzdCBDQTAeFw0yNjExMTIyMTQ1MjdaFw0zNjExMDkyMTQ1MjdaMB4xHDAaBgNVBAMME3Jjb3JlIHByb2JlIHRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATXQW8zyDJW6OU3/By6IHWe3b0JTOYzXO4Ex3eKcNewoWMLRglOIjMwF043p3QE2Vt2Tt9wDXh8I78fD+dficEio0IwQDAdBgNVHQ4EFgQU4AttcGsL8XBc0WZioIzdrAksO5YwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDRwAwRAIgG4oFw8i/8VEIWgQpl2V0KBScnRQfv5WrzKZinSmyUMACIEsXYhljxjpRZY2ylLLQWLPTlHOk47H9tWBeflfEGZQQ";
    const CERT: &str = "MIIBiDCCAS2gAwIBAgIUE9Tg4ARBoD4gDOCI6b3RCnvapaQwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTcmNvcmUgcHJvYmUgdGVzdCBDQTAeFw0yNjExMTIyMTQ1MjdaFw0zNjExMDkyMTQ1MjdaMBgxFjAUBgNVBAMMDXByb2JlLmV4YW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9L58HE1QHXi1E2hFo/U5uKAP9xYBw+JY47W36M+F6lYTa32/YXhSF55K7okocx0bnrW8DW+sjCSbsTv5qhPjko08wTTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAYBgNVHREEETAPgg1wcm9iZS5leGFtcGxlMAoGCCqGSM49BAMCA0kAMEYCIQDqPn1V9d/cCGDDI7OdljkAh7uuiwG2tX/885HU8/6tXAIhAKNTqIh5F80MK8fF5/ShTXc1qNySG1BylqoGkMClDluT";
    const KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmUk/uZKNjmXVVan8L4+PQ5pOoiKe89m63Y2ktAIrRTehRANCAAT9L58HE1QHXi1E2hFo/U5uKAP9xYBw+JY47W36M+F6lYTa32/YXhSF55K7okocx0bnrW8DW+sjCSbsTv5qhPjk";
}

//! rcore's VLESS outbound against real Go Xray servers:
//! Go client (socks -> VLESS) -> rcore (VLESS in -> VLESS out) -> Go server -> freedom.
//! Run with XRAY_BINARY=/path/to/xray cargo test -p rcore --test outbound_interop.
mod common;

use anyhow::{Context, Result, ensure};
use base64::Engine;
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    net::TcpStream,
    process::{Child, Command},
};

const ID: &str = "6b1f2b9e-2f7e-4f43-9d2a-1c1d2e3f4a5b";
const SNI: &str = "target.test";
const FLOW: &str = "xtls-rprx-vision";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_port(port: u16) -> Result<()> {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("port {port} never opened")
}

fn spawn_logged(command: &mut Command, dir: &Path, name: &str) -> Result<Child> {
    let log = std::fs::File::create(dir.join(format!("{name}.log")))?;
    command.stderr(Stdio::from(log.try_clone()?));
    command.stdout(Stdio::from(log));
    Ok(command.kill_on_drop(true).spawn()?)
}

async fn openssl(args: &[&str], dir: &Path) -> Result<()> {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .await?;
    ensure!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// A CA and a leaf certificate for `SNI` (webpki needs a CA:FALSE leaf under a real anchor).
async fn certificates(dir: &Path) -> Result<()> {
    std::fs::write(
        dir.join("leaf.ext"),
        format!(
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{SNI}\n"
        ),
    )?;
    openssl(
        &[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            "ca.key",
        ],
        dir,
    )
    .await?;
    openssl(
        &[
            "req",
            "-x509",
            "-new",
            "-key",
            "ca.key",
            "-days",
            "2",
            "-subj",
            "/CN=rcore test CA",
            "-out",
            "ca.pem",
        ],
        dir,
    )
    .await?;
    openssl(
        &[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            "leaf.key",
        ],
        dir,
    )
    .await?;
    openssl(
        &[
            "req",
            "-new",
            "-key",
            "leaf.key",
            "-subj",
            &format!("/CN={SNI}"),
            "-out",
            "leaf.csr",
        ],
        dir,
    )
    .await?;
    openssl(
        &[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            "leaf.ext",
            "-out",
            "leaf.pem",
        ],
        dir,
    )
    .await?;
    Ok(())
}

/// The Go server's inbound stream settings and rcore's matching outbound.
fn profiles(
    kind: &str,
    server_port: u16,
    target_port: u16,
    dir: &Path,
) -> (Value, Value, &'static str) {
    let certs = json!([{"certificateFile": dir.join("leaf.pem"), "keyFile": dir.join("leaf.key")}]);
    let private: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(5));
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let reality_server = json!({"network": "raw", "security": "reality", "realitySettings": {
        "target": format!("127.0.0.1:{target_port}"), "serverNames": [SNI],
        "privateKey": b64.encode(private), "shortIds": ["", "0123abcd"]}});
    let vnext = |flow: &str| {
        json!({"vnext": [{"address": "127.0.0.1", "port": server_port,
        "users": [{"id": ID, "flow": flow, "encryption": "none"}]}]})
    };
    match kind {
        "reality-vision-firefox" => (
            reality_server,
            json!({"protocol": "vless", "settings": vnext(FLOW), "streamSettings": {"network": "raw",
                "security": "reality", "realitySettings": {"spiderX": "/", "publicKey": b64.encode(public.as_bytes()),
                    "serverName": SNI, "fingerprint": "firefox"}}}),
            FLOW,
        ),
        "reality-vision-chrome" => (
            reality_server,
            json!({"protocol": "vless", "settings": vnext(FLOW), "streamSettings": {"network": "raw",
                "security": "reality", "realitySettings": {"password": b64.encode(public.as_bytes()),
                    "serverName": SNI, "shortId": "0123abcd"}}}),
            FLOW,
        ),
        "reality-plain" => (
            reality_server,
            json!({"protocol": "vless", "settings": vnext(""), "streamSettings": {"network": "raw",
                "security": "reality", "realitySettings": {"publicKey": b64.encode(public.as_bytes()),
                    "serverName": SNI, "fingerprint": "chrome"}}}),
            "",
        ),
        "ws-tls-firefox-flat" => (
            json!({"network": "ws", "security": "tls", "wsSettings": {"path": "/downloadmap/latvia", "host": SNI},
                "tlsSettings": {"certificates": certs}}),
            json!({"protocol": "vless", "settings": {"id": ID, "port": server_port, "address": "127.0.0.1", "encryption": "none"},
                "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"host": SNI, "path": "/downloadmap/latvia"},
                    "tlsSettings": {"alpn": ["http/1.1"], "serverName": SNI, "fingerprint": "firefox"}}}),
            "",
        ),
        "raw-tls-vision-chrome" => (
            json!({"network": "raw", "security": "tls",
                "tlsSettings": {"certificates": certs}}),
            json!({"protocol": "vless", "settings": vnext(FLOW), "streamSettings": {"network": "raw",
                "security": "tls", "tlsSettings": {"serverName": SNI}}}),
            FLOW,
        ),
        _ => (
            json!({"network": "raw"}),
            json!({"protocol": "vless", "settings": vnext(""), "streamSettings": {"network": "raw"}}),
            "",
        ),
    }
}

/// A concurrent TLS 1.3 echo site: REALITY's target (openssl s_server serves one connection
/// at a time, which stalls behind the Go server's startup probe) and the inner-TLS peer.
async fn tls_target(dir: &Path, port: u16) -> Result<()> {
    use std::{io::BufReader, sync::Arc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let open = |name: &str| std::fs::File::open(dir.join(name)).map(BufReader::new);
    let certs = rustls_pemfile::certs(&mut open("leaf.pem")?).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut open("leaf.key")?)?.context("leaf key")?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = vec![0u8; 65536];
                while let Ok(n) = tls.read(&mut buf).await
                    && n > 0
                {
                    if tls.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(())
}

/// TLS 1.3 inside the tunnel, so Vision's client side switches both directions to direct.
async fn inner_tls(dir: &Path, socks: u16) -> Result<()> {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let port = free_port();
    tls_target(dir, port).await?;
    let mut roots = rustls::RootCertStore::empty();
    let ca = std::fs::File::open(dir.join("ca.pem"))?;
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(ca)) {
        roots.add(cert?)?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = common::socks_connect(socks, port).await?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(SNI.try_into()?, tcp)
        .await?;
    let (mut r, mut w) = tokio::io::split(tls);
    let big: Vec<u8> = (0..1_000_000u32).map(|i| (i % 253) as u8).collect();
    let sent = big.clone();
    let writer = tokio::spawn(async move {
        for chunk in sent.chunks(16384) {
            w.write_all(chunk).await?;
        }
        anyhow::Ok(w)
    });
    let mut got = vec![0u8; big.len()];
    tokio::time::timeout(Duration::from_secs(20), r.read_exact(&mut got))
        .await
        .context("inner TLS timeout")??;
    writer.await??;
    ensure!(got == big, "inner TLS transfer corrupted");
    Ok(())
}

async fn setup(dir: &Path, xray: &str, kind: &str) -> Result<(Vec<Child>, u16)> {
    certificates(dir).await?;
    let (target_port, server_port, rcore_port, socks_port) =
        (free_port(), free_port(), free_port(), free_port());
    let mut children = Vec::new();
    if kind.starts_with("reality") {
        tls_target(dir, target_port).await?;
    }
    let (server_stream, outbound, flow) = profiles(kind, server_port, target_port, dir);
    let allow_local = json!({"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]});
    let server = json!({"log": {"loglevel": "debug"},
        "inbounds": [{"listen": "127.0.0.1", "port": server_port, "protocol": "vless",
            "settings": {"clients": [{"id": ID, "flow": flow}], "decryption": "none"},
            "streamSettings": server_stream}],
        "outbounds": [{"protocol": "freedom", "settings": allow_local}]});
    let mut outbound = outbound;
    outbound["tag"] = json!("cascade");
    let rcore = json!({"log": {"loglevel": "debug"},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": rcore_port, "protocol": "vless",
            "settings": {"clients": [{"id": ID, "email": "bob"}], "decryption": "none"},
            "streamSettings": {"network": "raw"}}],
        "outbounds": [outbound]});
    let client = json!({"log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": true, "ip": "127.0.0.1"}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": rcore_port,
            "users": [{"id": ID, "encryption": "none"}]}]}, "streamSettings": {"network": "raw"}}]});
    for (name, config) in [("server", &server), ("rcore", &rcore), ("client", &client)] {
        std::fs::write(dir.join(format!("{name}.json")), config.to_string())?;
    }
    children.push(spawn_logged(
        Command::new(xray)
            .args(["run", "-config", "server.json"])
            .current_dir(dir),
        dir,
        "server",
    )?);
    children.push(spawn_logged(
        Command::new(env!("CARGO_BIN_EXE_rcore"))
            .args(["run", "-config", "rcore.json"])
            .env("SSL_CERT_FILE", dir.join("ca.pem"))
            .current_dir(dir),
        dir,
        "rcore",
    )?);
    children.push(spawn_logged(
        Command::new(xray)
            .args(["run", "-config", "client.json"])
            .current_dir(dir),
        dir,
        "client",
    )?);
    for port in [server_port, rcore_port, socks_port] {
        wait_port(port).await?;
    }
    Ok((children, socks_port))
}

async fn run(kind: &str) {
    let Ok(xray) = std::env::var("XRAY_BINARY") else {
        eprintln!("XRAY_BINARY not set: skipped");
        return;
    };
    if Command::new("openssl")
        .arg("version")
        .output()
        .await
        .is_err()
    {
        eprintln!("openssl not found: skipped");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        let (_children, socks) = setup(dir.path(), &xray, kind).await.context("fixture")?;
        common::tcp_checks(socks).await.context("TCP")?;
        inner_tls(dir.path(), socks).await.context("inner TLS")?;
        common::xudp_checks(socks).await.context("UDP")
    })
    .await;
    if !matches!(&result, Ok(Ok(()))) {
        for name in ["rcore", "server", "client"] {
            if let Ok(log) = std::fs::read_to_string(dir.path().join(format!("{name}.log"))) {
                let lines: Vec<_> = log.lines().collect();
                eprintln!("--- {name} ({} lines) ---", lines.len());
                for line in lines.iter().rev().take(60).rev() {
                    eprintln!("{line}");
                }
            }
        }
    }
    result
        .expect("outbound interop exceeded 90 seconds")
        .expect("outbound interop failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn reality_vision_firefox() {
    run("reality-vision-firefox").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reality_vision_chrome_short_id() {
    run("reality-vision-chrome").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reality_without_flow() {
    run("reality-plain").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_tls_firefox_flat_settings() {
    run("ws-tls-firefox-flat").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_tls_vision_chrome() {
    run("raw-tls-vision-chrome").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_plain() {
    run("raw").await;
}

//! rcore's TLS inbound against real Go Xray clients:
//! Go client (socks -> VLESS over TLS) -> rcore (VLESS TLS inbound) -> freedom.
//! Run with XRAY_BINARY=/path/to/xray cargo test -p rcore --test tls_interop.
mod common;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
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
    for _ in 0..200 {
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

/// A CA, and leaf certificates `name.pem`/`name.key` for each (name, SAN DNS name).
async fn certificates(dir: &Path, leaves: &[(&str, &str)]) -> Result<()> {
    openssl(&["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key"], dir).await?;
    openssl(
        &["req", "-x509", "-new", "-key", "ca.key", "-days", "2", "-subj", "/CN=rcore test CA", "-out", "ca.pem"],
        dir,
    )
    .await?;
    for (name, dns) in leaves {
        std::fs::write(
            dir.join(format!("{name}.ext")),
            format!("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{dns}\n"),
        )?;
        let (key, csr, pem, ext) = (
            format!("{name}.key"),
            format!("{name}.csr"),
            format!("{name}.pem"),
            format!("{name}.ext"),
        );
        openssl(&["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", &key], dir).await?;
        openssl(&["req", "-new", "-key", &key, "-subj", &format!("/CN={dns}"), "-out", &csr], dir).await?;
        openssl(
            &["x509", "-req", "-in", &csr, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
              "-days", "2", "-extfile", &ext, "-out", &pem],
            dir,
        )
        .await?;
    }
    Ok(())
}

struct Case {
    name: &'static str,
    network: &'static str,
    settings: Value,
    flow: &'static str,
    fingerprint: &'static str,
    client_tls: Value,
}

fn cases() -> Vec<Case> {
    let none = json!({});
    vec![
        Case { name: "raw-chrome", network: "raw", settings: none.clone(), flow: "", fingerprint: "chrome", client_tls: json!({}) },
        Case { name: "raw-vision-firefox", network: "raw", settings: none.clone(), flow: FLOW, fingerprint: "firefox", client_tls: json!({}) },
        Case { name: "raw-vision-chrome", network: "raw", settings: none.clone(), flow: FLOW, fingerprint: "chrome", client_tls: json!({}) },
        Case { name: "ws", network: "ws", settings: json!({"wsSettings": {"path": "/ws"}}), flow: "", fingerprint: "chrome", client_tls: json!({}) },
        Case { name: "httpupgrade", network: "httpupgrade", settings: json!({"httpupgradeSettings": {"path": "/up"}}), flow: "", fingerprint: "chrome", client_tls: json!({}) },
        Case { name: "xhttp-h2", network: "xhttp", settings: json!({"xhttpSettings": {"path": "/x", "mode": "stream-one"}}), flow: "", fingerprint: "chrome", client_tls: json!({}) },
        Case { name: "xhttp-http11", network: "xhttp", settings: json!({"xhttpSettings": {"path": "/x", "mode": "packet-up"}}), flow: "", fingerprint: "chrome", client_tls: json!({"alpn": ["http/1.1"]}) },
        Case { name: "raw-tls12", network: "raw", settings: none, flow: "", fingerprint: "unsafe", client_tls: json!({"maxVersion": "1.2"}) },
    ]
}

/// Go client socks -> VLESS over TLS -> rcore; returns (processes, socks port).
async fn setup(dir: &Path, xray: &str, case: &Case) -> Result<(Vec<Child>, u16)> {
    let (rcore_port, socks_port) = (free_port(), free_port());
    let certs = json!([{"certificateFile": dir.join("leaf.pem"), "keyFile": dir.join("leaf.key")}]);
    let key_log = dir.join(format!("{}-keys.log", case.name));
    let mut server_stream = json!({"network": case.network, "security": "tls",
        "tlsSettings": {"certificates": certs, "masterKeyLog": key_log}});
    let mut client_stream = json!({"network": case.network, "security": "tls"});
    if let (Value::Object(s), Value::Object(c)) = (&mut server_stream, &mut client_stream) {
        for (k, v) in case.settings.as_object().unwrap() {
            s.insert(k.clone(), v.clone());
            c.insert(k.clone(), v.clone());
        }
    }
    let mut client_tls = json!({"serverName": SNI, "fingerprint": case.fingerprint,
        "certificates": [{"usage": "verify", "certificateFile": dir.join("ca.pem")}]});
    for (k, v) in case.client_tls.as_object().unwrap() {
        client_tls[k] = v.clone();
    }
    client_stream["tlsSettings"] = client_tls;
    let rcore = json!({"log": {"loglevel": "debug"},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": rcore_port, "protocol": "vless",
            "settings": {"clients": [{"id": ID, "email": "bob", "flow": case.flow}], "decryption": "none"},
            "streamSettings": server_stream}],
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]});
    let client = json!({"log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": true, "ip": "127.0.0.1"}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": rcore_port,
            "users": [{"id": ID, "encryption": "none", "flow": case.flow}]}]}, "streamSettings": client_stream}]});
    std::fs::write(dir.join(format!("{}-rcore.json", case.name)), rcore.to_string())?;
    std::fs::write(dir.join(format!("{}-client.json", case.name)), client.to_string())?;
    let rcore = spawn_logged(
        Command::new(env!("CARGO_BIN_EXE_rcore"))
            .args(["run", "-config", &format!("{}-rcore.json", case.name)])
            .current_dir(dir),
        dir,
        &format!("{}-rcore", case.name),
    )?;
    let client = spawn_logged(
        Command::new(xray)
            .args(["run", "-config", &format!("{}-client.json", case.name)])
            .current_dir(dir),
        dir,
        &format!("{}-client", case.name),
    )?;
    wait_port(rcore_port).await?;
    wait_port(socks_port).await?;
    Ok((vec![rcore, client], socks_port))
}

/// A TLS 1.3 echo target, so Vision's inner-TLS detection switches to direct copy.
async fn inner_tls(dir: &Path, socks: u16) -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let chain: Vec<_> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(dir.join("leaf.pem"))?))
            .collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(
        dir.join("leaf.key"),
    )?))?
    .context("leaf key")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let (mut r, mut w) = tokio::io::split(tls);
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                }
            });
        }
    });
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(dir.join("ca.pem"))?)) {
        roots.add(cert?)?;
    }
    let config = rustls::ClientConfig::builder_with_provider(provider)
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

/// A scratch directory, or RCORE_TEST_DIR (kept) to inspect the logs.
fn workdir() -> Result<tempfile::TempDir> {
    match std::env::var_os("RCORE_TEST_DIR") {
        Some(base) => {
            std::fs::create_dir_all(&base)?;
            Ok(tempfile::Builder::new().disable_cleanup(true).tempdir_in(base)?)
        }
        None => Ok(tempfile::tempdir()?),
    }
}

#[tokio::test]
async fn go_clients_over_tls_inbound() -> Result<()> {
    let Ok(xray) = std::env::var("XRAY_BINARY") else {
        return Ok(());
    };
    let dir = workdir()?;
    certificates(dir.path(), &[("leaf", SNI)]).await?;
    for case in cases() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let (_children, socks) = setup(dir.path(), &xray, &case).await?;
            common::tcp_checks(socks).await.context("TCP")?;
            if case.flow == FLOW {
                inner_tls(dir.path(), socks).await.context("Vision inner TLS")?;
            }
            if !case.name.starts_with("xhttp") {
                common::xudp_checks(socks).await.context("UDP")?;
            }
            // masterKeyLog in NSS format, as crypto/tls's KeyLogWriter writes it.
            let keys = std::fs::read_to_string(dir.path().join(format!("{}-keys.log", case.name)))?;
            let label = if case.name.ends_with("tls12") { "CLIENT_RANDOM " } else { "SERVER_TRAFFIC_SECRET_0 " };
            ensure!(keys.lines().any(|l| l.starts_with(label)), "key log: {keys}");
            Result::<()>::Ok(())
        })
        .await
        .with_context(|| format!("{} deadline", case.name))?
        .with_context(|| {
            let log = std::fs::read_to_string(dir.path().join(format!("{}-rcore.log", case.name)));
            format!("{}: rcore log:\n{}", case.name, log.unwrap_or_default())
        })?;
    }
    Ok(())
}

#[tokio::test]
async fn vision_refuses_outer_tls12_like_go() -> Result<()> {
    let Ok(xray) = std::env::var("XRAY_BINARY") else {
        return Ok(());
    };
    let dir = workdir()?;
    certificates(dir.path(), &[("leaf", SNI)]).await?;
    let case = Case {
        name: "vision-tls12",
        network: "raw",
        settings: json!({}),
        flow: FLOW,
        fingerprint: "unsafe",
        client_tls: json!({"maxVersion": "1.2"}),
    };
    let (_children, socks) = setup(dir.path(), &xray, &case).await?;
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = echo.local_addr()?.port();
    let mut s = common::socks_connect(socks, port).await?;
    s.write_all(b"x").await?;
    let mut buf = [0u8; 1];
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await;
    let want = "failed to use xtls-rprx-vision, found outer tls version 771";
    let mut log = String::new();
    for _ in 0..50 {
        log = std::fs::read_to_string(dir.path().join("vision-tls12-rcore.log"))?;
        if log.contains(want) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ensure!(log.contains(want), "{log}");
    Ok(())
}

/// Which alert (if any) a TLS 1.3 client gets for `sni` from a server on `port`.
async fn handshake_alert(port: u16, sni: &str, dir: &Path) -> Result<Option<String>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(dir.join("ca.pem"))?)) {
        roots.add(cert?)?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let name = rustls::pki_types::ServerName::try_from(sni.to_owned())?;
    Ok(
        match tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
        {
            Ok(_) => None,
            Err(e) => Some(format!("{e}")),
        },
    )
}

#[tokio::test]
async fn certificate_selection_and_unknown_sni_match_go() -> Result<()> {
    let dir = tempfile::tempdir()?;
    certificates(dir.path(), &[("a", "a.test"), ("b", "*.b.test")]).await?;
    let mut servers = vec![("rcore".to_owned(), env!("CARGO_BIN_EXE_rcore").to_owned())];
    if let Ok(xray) = std::env::var("XRAY_BINARY") {
        servers.push(("go".to_owned(), xray));
    }
    let mut results = Vec::new();
    for (name, binary) in &servers {
        let port = free_port();
        let certs = json!([
            {"certificateFile": dir.path().join("a.pem"), "keyFile": dir.path().join("a.key")},
            {"certificateFile": dir.path().join("b.pem"), "keyFile": dir.path().join("b.key")}
        ]);
        let config = json!({"inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "tls",
                "tlsSettings": {"certificates": certs, "rejectUnknownSni": true}}}],
            "outbounds": [{"protocol": "freedom"}]});
        std::fs::write(dir.path().join(format!("{name}-sni.json")), config.to_string())?;
        let _child = spawn_logged(
            Command::new(binary)
                .args(["run", "-config", &format!("{name}-sni.json")])
                .current_dir(dir.path()),
            dir.path(),
            &format!("{name}-sni"),
        )?;
        wait_port(port).await?;
        let mut outcome = Vec::new();
        for sni in ["a.test", "x.b.test", "other.test"] {
            outcome.push(handshake_alert(port, sni, dir.path()).await?);
        }
        ensure!(outcome[0].is_none() && outcome[1].is_none(), "{name}: {outcome:?}");
        ensure!(
            outcome[2].as_deref().is_some_and(|e| e.contains("UnrecognisedName")),
            "{name}: {outcome:?}"
        );
        results.push(outcome);
    }
    if let [rust, go] = results.as_slice() {
        ensure!(rust == go, "rcore {rust:?} vs go {go:?}");
    }
    Ok(())
}

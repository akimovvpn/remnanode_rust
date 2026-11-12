//! Real Go Xray REALITY client (uTLS Chrome) against rcore as the REALITY server, with an
//! OpenSSL TLS 1.3 server as the target; unauthenticated visitors must reach the target.
use base64::Engine;
use serde_json::json;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
};

const ID: &str = "6b1f2b9e-2f7e-4f43-9d2a-1c1d2e3f4a5b";
const SNI: &str = "target.test";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("port {port} never opened");
}

/// OpenSSL TLS 1.3 server with a self-signed certificate, serving its status page.
async fn target(dir: &std::path::Path, groups: &str) -> (Child, u16) {
    let (cert, key) = (dir.join("target.pem"), dir.join("target.key"));
    if !cert.exists() {
        let ok = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                &format!("/CN={SNI}"),
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .output()
            .await
            .unwrap();
        assert!(ok.status.success());
    }
    let port = free_port();
    let child = Command::new("openssl")
        .args([
            "s_server",
            "-quiet",
            "-tls1_3",
            "-www",
            "-groups",
            groups,
            "-accept",
            &port.to_string(),
            "-cert",
        ])
        .arg(&cert)
        .arg("-key")
        .arg(&key)
        .args(["-servername", SNI, "-cert2"])
        .arg(&cert)
        .arg("-key2")
        .arg(&key)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_port(port).await;
    (child, port)
}

async fn socks_connect(socks: u16, target: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", socks)).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await.unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target.to_be_bytes());
    s.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "socks connect failed");
    s
}

async fn run(groups: &str) {
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
    if groups.contains("MLKEM") {
        let supported = Command::new("openssl")
            .args(["list", "-tls-groups"])
            .output()
            .await
            .unwrap();
        if !supported.status.success()
            || !String::from_utf8_lossy(&supported.stdout).contains("X25519MLKEM768")
        {
            eprintln!(
                "hybrid target skipped: requires OpenSSL with X25519MLKEM768 support (X25519 still tested)"
            );
            return;
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let (_target, target_port) = target(dir.path(), groups).await;
    let private: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (server_port, socks_port) = (free_port(), free_port());
    let server = json!({ "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": server_port, "protocol": "vless",
            "settings": {"clients": [{"id": ID, "email": "bob"}], "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "target": format!("127.0.0.1:{target_port}"), "serverNames": [SNI],
                "privateKey": b64.encode(private), "shortIds": ["", "0123abcd"], "show": true}}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]
    });
    let client = json!({ "log": {"loglevel": "debug"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": false}}],
        "outbounds": [{"protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": server_port, "users": [{"id": ID, "encryption": "none"}]}]},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "serverName": SNI, "password": b64.encode(public.as_bytes()), "shortId": "0123abcd", "fingerprint": "chrome"}}}]
    });
    std::fs::write(dir.path().join("server.json"), server.to_string()).unwrap();
    std::fs::write(dir.path().join("client.json"), client.to_string()).unwrap();
    let _server = Command::new(env!("CARGO_BIN_EXE_rcore"))
        .args(["run", "-config"])
        .arg(dir.path().join("server.json"))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let _client = Command::new(&xray)
        .args(["run", "-config"])
        .arg(dir.path().join("client.json"))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_port(server_port).await;
    wait_port(socks_port).await;

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while let Ok(n) = s.read(&mut buf).await
                    && n > 0
                {
                    s.write_all(&buf[..n]).await.unwrap();
                }
            });
        }
    });
    let mut s = socks_connect(socks_port, echo_port).await;
    for message in [&b"ping"[..], b"second message", &[7u8; 3000]] {
        s.write_all(message).await.unwrap();
        let mut back = vec![0u8; message.len()];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut back))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(back, message);
    }
    let big: Vec<u8> = (0..4_000_000u32).map(|i| (i % 251) as u8).collect();
    let (mut r, mut w) = s.into_split();
    let sent = big.clone();
    let writer = tokio::spawn(async move { w.write_all(&sent).await.unwrap() });
    let mut got = vec![0u8; big.len()];
    tokio::time::timeout(Duration::from_secs(20), r.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    writer.await.unwrap();
    assert!(got == big, "large transfer corrupted");

    // A normal HTTPS visitor sees the target site through the REALITY port.
    let mut visitor = Command::new("openssl")
        .args([
            "s_client",
            "-quiet",
            "-connect",
            &format!("127.0.0.1:{server_port}"),
            "-servername",
            SNI,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    visitor
        .stdin
        .take()
        .unwrap()
        .write_all(format!("GET / HTTP/1.1\r\nHost: {SNI}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let page = tokio::time::timeout(Duration::from_secs(5), visitor.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let body = String::from_utf8_lossy(&page.stdout);
    assert!(
        body.contains("s_server"),
        "fallback did not reach the target: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reality_with_x25519mlkem768_target() {
    run("X25519MLKEM768:X25519").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reality_with_x25519_target() {
    run("X25519").await;
}

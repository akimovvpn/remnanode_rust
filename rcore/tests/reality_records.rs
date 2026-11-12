//! Compare the REALITY wire camouflage with the pinned Go server, including ticket padding.
use base64::Engine;
use serde_json::json;
use std::{
    path::Path,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    task::JoinHandle,
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
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("subprocess did not listen");
}

// s_server handles one connection at a time; isolate every probe so their idle waits overlap.
async fn target(dir: &Path) -> (u16, JoinHandle<()>) {
    let cert = dir.join("target.pem");
    let key = dir.join("target.key");
    let ca = dir.join("ca.pem");
    let ca_key = dir.join("ca.key");
    let output = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=REALITY test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
        ])
        .arg(&ca_key)
        .arg("-out")
        .arg(&ca)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "CA generation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            &format!("/CN={SNI}"),
            "-addext",
            &format!("subjectAltName=DNS:{SNI}"),
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "extendedKeyUsage=serverAuth",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "-keyout",
        ])
        .arg(&key)
        .arg("-CA")
        .arg(&ca)
        .arg("-CAkey")
        .arg(&ca_key)
        .arg("-out")
        .arg(&cert)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "certificate generation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (mut peer, _) = listener.accept().await.unwrap();
            let port = free_port();
            let (cert, key) = (cert.clone(), key.clone());
            tokio::spawn(async move {
                let _child = Command::new("openssl")
                    .args([
                        "s_server",
                        "-quiet",
                        "-tls1_3",
                        "-www",
                        "-groups",
                        "X25519",
                        "-num_tickets",
                        "2",
                        "-naccept",
                        "1",
                        "-accept",
                    ])
                    .arg(format!("127.0.0.1:{port}"))
                    .arg("-cert")
                    .arg(&cert)
                    .arg("-key")
                    .arg(&key)
                    .args(["-servername", SNI, "-cert2"])
                    .arg(&cert)
                    .arg("-key2")
                    .arg(&key)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .kill_on_drop(true)
                    .spawn()
                    .unwrap();
                let mut upstream = tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
                            break stream;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("OpenSSL target did not listen");
                let _ = tokio::time::timeout(
                    Duration::from_secs(20),
                    tokio::io::copy_bidirectional(&mut peer, &mut upstream),
                )
                .await;
            });
        }
    });
    (port, task)
}

fn spawn(binary: &Path, config: &Path, dir: &Path, name: &str) -> Child {
    let log = std::fs::File::create(dir.join(format!("{name}.log"))).unwrap();
    Command::new(binary)
        .args(["run", "-config"])
        .arg(config)
        .env("SSL_CERT_FILE", dir.join("ca.pem"))
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

async fn capture(server: u16) -> (u16, Arc<Mutex<Vec<(u8, usize)>>>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let records = Arc::new(Mutex::new(Vec::new()));
    let saved = records.clone();
    let task = tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let upstream = TcpStream::connect(("127.0.0.1", server)).await.unwrap();
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = upstream.into_split();
        let upload = async {
            let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
        };
        let download = async {
            loop {
                let mut header = [0u8; 5];
                if server_read.read_exact(&mut header).await.is_err() {
                    break;
                }
                let len = u16::from_be_bytes([header[3], header[4]]) as usize;
                assert!(len <= 18432, "oversized TLS record");
                let mut payload = vec![0; len];
                server_read.read_exact(&mut payload).await.unwrap();
                saved.lock().unwrap().push((header[0], len + 5));
                if client_write.write_all(&header).await.is_err() {
                    break;
                }
                if client_write.write_all(&payload).await.is_err() {
                    break;
                }
            }
        };
        tokio::select! { _ = upload => {}, _ = download => {} }
    });
    (port, records, task)
}

async fn exchange(socks: u16, destination: u16) {
    let mut stream = TcpStream::connect(("127.0.0.1", socks)).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&destination.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS connect failed");
    for message in [b"after ticket padding".as_slice(), b"next encrypted record"] {
        stream.write_all(message).await.unwrap();
        let mut received = vec![0; message.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(
            received, message,
            "padding changed the application cipher sequence"
        );
    }
}

async fn run_server(
    binary: &Path,
    xray: &Path,
    dir: &Path,
    name: &str,
    target: u16,
    echo: u16,
) -> Vec<(u8, usize)> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let private: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    let server_port = free_port();
    let server = json!({"log":{"loglevel":"debug"}, "inbounds":[{
        "listen":"127.0.0.1", "port":server_port, "protocol":"vless",
        "settings":{"clients":[{"id":ID}], "decryption":"none"},
        "streamSettings":{"network":"raw", "security":"reality", "realitySettings":{
            "target":format!("127.0.0.1:{target}"), "serverNames":[SNI],
            "privateKey":b64.encode(private), "shortIds":["0123abcd"], "show":true}}
    }], "outbounds":[{"protocol":"freedom", "settings":{"finalRules":[{"action":"allow", "ip":["127.0.0.1/32"]}]}}]});
    let config = dir.join(format!("{name}-server.json"));
    std::fs::write(&config, server.to_string()).unwrap();
    let _server = spawn(binary, &config, dir, &format!("{name}-server"));
    wait_port(server_port).await;
    // Go warms the detector at startup; its post-handshake collection waits five seconds.
    if name == "go" {
        tokio::time::sleep(Duration::from_secs(6)).await;
    }
    let (proxy_port, records, proxy) = capture(server_port).await;
    let socks = free_port();
    let client = json!({"log":{"loglevel":"debug"},
        "inbounds":[{"listen":"127.0.0.1", "port":socks, "protocol":"socks", "settings":{"udp":false}}],
        "outbounds":[{"protocol":"vless", "settings":{"vnext":[{"address":"127.0.0.1", "port":proxy_port,
            "users":[{"id":ID, "encryption":"none"}]}]},
            "streamSettings":{"network":"raw", "security":"reality", "realitySettings":{
                "serverName":SNI, "password":b64.encode(public.as_bytes()), "shortId":"0123abcd", "fingerprint":"chrome"}}}]});
    let config = dir.join(format!("{name}-client.json"));
    std::fs::write(&config, client.to_string()).unwrap();
    let _client = spawn(xray, &config, dir, &format!("{name}-client"));
    wait_port(socks).await;
    let result =
        tokio::time::timeout(Duration::from_secs(20), tokio::spawn(exchange(socks, echo))).await;
    if !matches!(result, Ok(Ok(()))) {
        for suffix in ["server", "client"] {
            eprintln!(
                "{name}-{suffix}: {}",
                std::fs::read_to_string(dir.join(format!("{name}-{suffix}.log"))).unwrap()
            );
        }
    }
    result
        .expect("authenticated echo timed out")
        .expect("authenticated echo failed");
    proxy.abort();
    let captured = records.lock().unwrap().clone();
    eprintln!("{name} server TLS record types and wire lengths: {captured:?}");
    captured
}

#[tokio::test(flavor = "multi_thread")]
async fn reality_handshake_and_post_handshake_record_lengths_match_go() {
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
    let (target_port, target_task) = target(dir.path()).await;
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        loop {
            let (stream, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut read, mut write) = stream.into_split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let go = run_server(
        Path::new(&xray),
        Path::new(&xray),
        dir.path(),
        "go",
        target_port,
        echo_port,
    )
    .await;
    let rust = run_server(
        Path::new(env!("CARGO_BIN_EXE_rcore")),
        Path::new(&xray),
        dir.path(),
        "rust",
        target_port,
        echo_port,
    )
    .await;
    target_task.abort();
    echo_task.abort();
    // OpenSSL's six-record handshake is followed by its two NewSessionTicket records.
    // Require the reference tickets: otherwise equality could pass with both probes broken.
    assert!(
        go.len() >= 8,
        "reference has no complete handshake and ticket flight: {go:?}"
    );
    assert_eq!(
        go[..6].iter().map(|r| r.0).collect::<Vec<_>>(),
        [22, 20, 23, 23, 23, 23]
    );
    assert!(
        go[6].0 == 23 && go[6].1 > 100 && go[7] == go[6],
        "reference did not replay two ticket records: {go:?}"
    );
    let log = std::fs::read_to_string(dir.path().join("go-server.log")).unwrap();
    assert_eq!(
        log.matches("len(postHandshakeRecord):").count(),
        2,
        "reference probe failed: {log}"
    );
    assert!(
        rust.len() >= 8,
        "Rust omitted post-handshake records: {rust:?}"
    );
    assert_eq!(
        rust[..8],
        go[..8],
        "handshake or post-handshake camouflage differs\n{}",
        std::fs::read_to_string(dir.path().join("rust-server.log")).unwrap()
    );
}

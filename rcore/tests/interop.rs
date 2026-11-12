//! Real Go Xray as a VLESS client (socks in -> vless out) against rcore as the server.
use serde_json::json;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
};

const ID: &str = "6b1f2b9e-2f7e-4f43-9d2a-1c1d2e3f4a5b";

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

#[tokio::test(flavor = "multi_thread")]
async fn go_xray_vless_client_talks_to_rcore() {
    let Ok(xray) = std::env::var("XRAY_BINARY") else {
        eprintln!("XRAY_BINARY not set: skipped");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let (server_port, socks_port) = (free_port(), free_port());
    let server = json!({
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": server_port, "protocol": "vless",
                      "settings": {"clients": [{"id": ID, "email": "bob"}], "decryption": "none"},
                      "sniffing": {"enabled": true, "destOverride": ["http", "tls"]}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]
    });
    let client = json!({
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": false}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": server_port,
                       "users": [{"id": ID, "encryption": "none"}]}]}}]
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

    // Raw TCP echo, several round trips on one connection, plus a large transfer.
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
            .unwrap()
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

    // HTTP request: sniffed as http1 and dialed by its Host (localhost) like Xray's destOverride.
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = http.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = s.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"GET /x HTTP/1.1"));
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let mut s = socks_connect(socks_port, http_port).await;
    s.write_all(format!("GET /x HTTP/1.1\r\nHost: 127.0.0.1:{http_port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.ends_with(b"\r\n\r\nok"),
        "{}",
        String::from_utf8_lossy(&response)
    );
}

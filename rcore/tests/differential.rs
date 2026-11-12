//! Runs identical scenarios through the node's own operations against Go Xray and rcore,
//! over each supported transport, then requires the observable results to be identical.
use base64::Engine;
use remnanode_rust::{core::Core, grpc::Grpc, operations};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
};

const ALICE: &str = "550e8400-e29b-41d4-a716-446655440000";
const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const PATH: &str = "/api/websocket";

#[derive(Clone, Copy, Debug)]
enum Net {
    Raw,
    Ws,
    HttpUpgrade,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(api: u16, proxy: u16, net: Net) -> Value {
    let stream = match net {
        Net::Raw => json!({"network": "raw"}),
        Net::Ws => {
            json!({"network": "ws", "wsSettings": {"path": format!("{PATH}?ed=2048")}, "sockopt": {"trustedXForwardedFor": ["X-Forwarded-For"]}})
        }
        Net::HttpUpgrade => {
            json!({"network": "httpupgrade", "httpupgradeSettings": {"path": PATH}, "sockopt": {"trustedXForwardedFor": ["X-Forwarded-For"]}})
        }
    };
    json!({
        "log": {"loglevel": "warning"},
        "api": {"tag": "REMNAWAVE_API", "services": ["HandlerService", "StatsService", "RoutingService"]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true}},
                   "system": {"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true}},
        "inbounds": [
            {"tag": "REMNAWAVE_API_INBOUND", "listen": "127.0.0.1", "port": api, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}},
            {"tag": "vless", "listen": "127.0.0.1", "port": proxy, "protocol": "vless",
             "settings": {"clients": [], "decryption": "none"},
             "sniffing": {"enabled": true, "destOverride": ["http", "tls"]},
             "streamSettings": stream}
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}},
            {"tag": "BLOCK", "protocol": "blackhole"}
        ],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["REMNAWAVE_API_INBOUND"], "outboundTag": "REMNAWAVE_API"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCK"}
        ]}
    })
}

fn vless_request(target_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut request = vec![0];
    request.extend_from_slice(&uuid_bytes(ALICE));
    request.extend_from_slice(&[0, 1]);
    request.extend_from_slice(&target_port.to_be_bytes());
    request.extend_from_slice(&[1, 127, 0, 0, 1]);
    request.extend_from_slice(payload);
    request
}

fn uuid_bytes(id: &str) -> [u8; 16] {
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
}

/// Reads an HTTP response head; returns it with the Date line removed (it differs per run).
async fn read_head(s: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut byte))
            .await
            .is_err()
            || head.len() > 8192
        {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head)
        .lines()
        .filter(|l| !l.starts_with("Date:"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn masked(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [1u8, 2, 3, 4];
    let mut out = vec![0x80 | opcode];
    if payload.len() < 126 {
        out.push(0x80 | payload.len() as u8);
    } else {
        out.push(0x80 | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// Opens a proxy connection over `net`, sending `request` (as WS early data when asked).
async fn open(
    net: Net,
    proxy: u16,
    request: &[u8],
    early: bool,
    xff: Option<&str>,
) -> (TcpStream, String) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    let xff = xff
        .map(|ip| format!("X-Forwarded-For: {ip}\r\n"))
        .unwrap_or_default();
    let head = match net {
        Net::Raw => {
            s.write_all(request).await.unwrap();
            return (s, String::new());
        }
        Net::Ws => {
            let protocol = if early {
                format!(
                    "Sec-WebSocket-Protocol: {}\r\n",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request)
                )
            } else {
                String::new()
            };
            let req = format!(
                "GET {PATH} HTTP/1.1\r\nHost: 127.0.0.1:{proxy}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {WS_KEY}\r\nSec-WebSocket-Version: 13\r\n{protocol}{xff}\r\n"
            );
            s.write_all(req.as_bytes()).await.unwrap();
            let head = read_head(&mut s).await;
            if !early {
                s.write_all(&masked(2, request)).await.unwrap();
            }
            head
        }
        Net::HttpUpgrade => {
            let req = format!(
                "GET {PATH} HTTP/1.1\r\nHost: 127.0.0.1:{proxy}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {WS_KEY}\r\n{xff}\r\n"
            );
            s.write_all(req.as_bytes()).await.unwrap();
            let head = read_head(&mut s).await;
            s.write_all(request).await.unwrap();
            head
        }
    };
    (s, head)
}

/// Collects the proxied payload until the server closes (or 5s pass); WS frames are decoded.
async fn collect(net: Net, mut s: TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut raw)).await;
    if !matches!(net, Net::Ws) {
        return raw;
    }
    let (mut out, mut d) = (Vec::new(), raw.as_slice());
    while d.len() >= 2 {
        let opcode = d[0] & 0x0f;
        let (len, at) = match d[1] & 0x7f {
            126 => (u16::from_be_bytes([d[2], d[3]]) as usize, 4),
            127 => (
                u64::from_be_bytes(d[2..10].try_into().unwrap()) as usize,
                10,
            ),
            n => (n as usize, 2),
        };
        if d.len() < at + len {
            break;
        }
        match opcode {
            0..=2 => out.extend_from_slice(&d[at..at + len]),
            8 => {
                out.extend_from_slice(b"<close:");
                out.extend_from_slice(&d[at..at + len]);
                out.push(b'>');
            }
            _ => {}
        }
        d = &d[at + len..];
    }
    out
}

/// IP lists carry wall-clock "last seen" dates; keep everything else.
fn without_dates(mut v: Value) -> Value {
    fn walk(v: &mut Value) {
        match v {
            Value::Object(map) => {
                map.remove("date");
                map.remove("lastSeen");
                map.values_mut().for_each(walk);
            }
            Value::Array(items) => items.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut v);
    v
}

async fn transcript(binary: &str, net: Net) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let (api, proxy) = (free_port(), free_port());
    let path = dir.path().join("config.json");
    std::fs::write(&path, config(api, proxy, net).to_string()).unwrap();
    let mut log = serde_json::Map::new();
    let test = Command::new(binary)
        .args(["run", "-test", "-config"])
        .arg(&path)
        .output()
        .await
        .unwrap();
    log.insert("test_ok".into(), json!(test.status.success()));
    assert!(
        test.status.success(),
        "{binary}: {}",
        String::from_utf8_lossy(&test.stdout)
    );
    let mut child = Command::new(binary)
        .args(["run", "-config"])
        .arg(&path)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let endpoint = format!("http://127.0.0.1:{api}");
    let mut ready = false;
    for _ in 0..100 {
        if let Ok(mut grpc) = Grpc::connect(&endpoint).await
            && grpc.sys_stats().await.is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "{binary}: API never became ready");
    let mut core = Core::new(binary.into(), dir.path().into(), endpoint);
    let mut op = async |path: &str, body: Value| {
        operations::handle(path, &body, &mut core)
            .await
            .map(without_dates)
            .map_err(|e| e.to_string())
    };
    let add = json!({"data":[{"type":"vless","tag":"vless","username":"alice","uuid":ALICE,"flow":""}],"hashData":{"vlessUuid":ALICE}});
    log.insert(
        "add_user".into(),
        json!(op("/node/handler/add-user", add).await),
    );

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = [0u8; 5];
                if s.read_exact(&mut b).await.is_ok() {
                    let _ = s.write_all(&b).await;
                }
                let mut rest = [0u8; 64];
                let _ = s.read(&mut rest).await;
            });
        }
    });
    let (s, head) = open(net, proxy, &vless_request(echo_port, b"hello"), false, None).await;
    log.insert("handshake".into(), json!(head));
    log.insert("echo".into(), json!(collect(net, s).await));

    let mut bt = vec![19];
    bt.extend_from_slice(b"BitTorrent protocol");
    bt.extend_from_slice(&[0; 48]);
    let started = std::time::Instant::now();
    let (s, _) = open(net, proxy, &vless_request(6881, &bt), false, None).await;
    log.insert("bittorrent".into(), json!(collect(net, s).await));
    log.insert(
        "bittorrent_closed_fast".into(),
        json!(started.elapsed() < Duration::from_secs(3)),
    );

    match net {
        Net::Raw => {
            let started = std::time::Instant::now();
            let mut private = vec![0];
            private.extend_from_slice(&uuid_bytes(ALICE));
            private.extend_from_slice(&[0, 1, 0, 80, 1, 10, 0, 0, 1]);
            let (mut s, _) = open(net, proxy, &private, false, None).await;
            let mut first = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), s.read(&mut first)).await;
            log.insert(
                "private_held_open".into(),
                json!(read.is_err() && started.elapsed() >= Duration::from_secs(2)),
            );
        }
        Net::Ws | Net::HttpUpgrade => {
            if let Net::Ws = net {
                // Early data in Sec-WebSocket-Protocol carries the whole VLESS request.
                let request = vless_request(echo_port, b"early");
                let sent = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&request);
                let (s, head) = open(net, proxy, &request, true, None).await;
                // The early data embeds this run's echo port; compare that it is echoed verbatim.
                log.insert(
                    "early_handshake".into(),
                    json!(head.replace(&sent, "<echoed early data>")),
                );
                log.insert("early_echo".into(), json!(collect(net, s).await));
                for (name, request) in [
                    (
                        "wrong_path",
                        "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n".to_owned(),
                    ),
                    (
                        "not_websocket",
                        format!("GET {PATH} HTTP/1.1\r\nHost: x\r\n\r\n"),
                    ),
                    (
                        "wrong_method",
                        format!("POST {PATH} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"),
                    ),
                    (
                        "post_upgrade",
                        format!(
                            "POST {PATH} HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 0\r\n\r\n"
                        ),
                    ),
                    (
                        "bad_version",
                        format!(
                            "GET {PATH} HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 8\r\nSec-WebSocket-Key: {WS_KEY}\r\n\r\n"
                        ),
                    ),
                ] {
                    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
                    s.write_all(request.as_bytes()).await.unwrap();
                    log.insert(name.into(), json!(read_head(&mut s).await));
                }
            } else {
                let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
                s.write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
                    .await
                    .unwrap();
                let mut rest = Vec::new();
                let _ =
                    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut rest)).await;
                log.insert("wrong_path_closed_silently".into(), json!(rest));
            }
            // A trusted X-Forwarded-For replaces the source IP the node sees as online.
            let (s, _) = open(
                net,
                proxy,
                &vless_request(echo_port, b"hello"),
                false,
                Some("203.0.113.5, 10.0.0.1"),
            )
            .await;
            tokio::time::sleep(Duration::from_millis(400)).await;
            log.insert(
                "xff_online".into(),
                json!(
                    op(
                        "/node/stats/get-user-online-status",
                        json!({"username": "alice"})
                    )
                    .await
                ),
            );
            log.insert(
                "xff_ips".into(),
                json!(op("/node/stats/get-users-ip-list", json!({})).await),
            );
            drop(s);
        }
    }

    tokio::time::sleep(Duration::from_millis(1500)).await;
    for (name, path, body) in [
        (
            "users_stats",
            "/node/stats/get-users-stats",
            json!({"reset": false}),
        ),
        (
            "inbound_stats",
            "/node/stats/get-inbound-stats",
            json!({"tag": "vless", "reset": false}),
        ),
        (
            "outbound_direct",
            "/node/stats/get-outbound-stats",
            json!({"tag": "direct", "reset": false}),
        ),
        (
            "outbound_block",
            "/node/stats/get-outbound-stats",
            json!({"tag": "BLOCK", "reset": false}),
        ),
        (
            "online",
            "/node/stats/get-user-online-status",
            json!({"username": "alice"}),
        ),
        ("users_ips", "/node/stats/get-users-ip-list", json!({})),
        (
            "combined_reset",
            "/node/stats/get-combined-stats",
            json!({"reset": true}),
        ),
        (
            "combined_after_reset",
            "/node/stats/get-combined-stats",
            json!({"reset": false}),
        ),
    ] {
        log.insert(name.into(), json!(op(path, body).await));
    }
    let remove = json!({"username": "alice", "hashData": {"vlessUuid": ALICE}});
    log.insert(
        "remove_user".into(),
        json!(op("/node/handler/remove-user", remove.clone()).await),
    );
    let (s, _) = open(net, proxy, &vless_request(echo_port, b"hello"), false, None).await;
    log.insert("after_remove".into(), json!(collect(net, s).await));
    log.insert(
        "remove_again".into(),
        json!(op("/node/handler/remove-user", remove).await),
    );
    child.kill().await.ok();
    Value::Object(log)
}

async fn compare(net: Net) {
    let rust = transcript(env!("CARGO_BIN_EXE_rcore"), net).await;
    assert_eq!(rust["echo"], json!(b"\0\0hello"), "{net:?}: {rust:#}");
    assert_eq!(rust["bittorrent_closed_fast"], true);
    let Ok(go) = std::env::var("XRAY_BINARY") else {
        eprintln!("XRAY_BINARY not set: skipped the comparison with Go Xray");
        return;
    };
    let go = transcript(&go, net).await;
    // The API inbound counts raw HTTP/2 bytes of the gRPC server itself; Go's grpc-go and tonic
    // frame differently, so only that inbound's byte counts are excluded.
    let strip = |mut v: Value| {
        for key in ["combined_reset", "combined_after_reset"] {
            if let Some(list) = v[key]["Ok"]["inbounds"].as_array_mut() {
                list.retain(|i| i["inbound"] != "REMNAWAVE_API_INBOUND");
            }
        }
        v
    };
    let (go, rust) = (strip(go), strip(rust));
    let mut diffs = Vec::new();
    for (key, value) in go.as_object().unwrap() {
        if rust[key] != *value {
            diffs.push(format!("{key}:\n  go:    {value}\n  rcore: {}", rust[key]));
        }
    }
    assert!(
        diffs.is_empty(),
        "{net:?}: rcore differs from Go Xray:\n{}",
        diffs.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_tcp_matches_go_xray() {
    compare(Net::Raw).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_matches_go_xray() {
    compare(Net::Ws).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn httpupgrade_matches_go_xray() {
    compare(Net::HttpUpgrade).await;
}

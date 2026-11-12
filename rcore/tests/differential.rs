//! Runs identical scenarios through the node's own operations against Go Xray and rcore,
//! then requires the observable results (responses, bytes, stats) to be identical.
use remnanode_rust::{core::Core, grpc::Grpc, operations};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
};

const ALICE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(api: u16, proxy: u16) -> Value {
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
             "sniffing": {"enabled": true, "destOverride": ["http", "tls"]}}
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

/// Sends a request and collects everything until the server closes (or 5s pass).
async fn exchange(proxy: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out)).await;
    out
}

async fn transcript(binary: &str) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let (api, proxy) = (free_port(), free_port());
    let path = dir.path().join("config.json");
    std::fs::write(&path, config(api, proxy).to_string()).unwrap();
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
            .map_err(|e| e.to_string())
    };
    let add = json!({"data":[{"type":"vless","tag":"vless","username":"alice","uuid":ALICE,"flow":""}],"hashData":{"vlessUuid":ALICE}});
    log.insert(
        "add_user".into(),
        json!(op("/node/handler/add-user", add).await),
    );

    // Echo through VLESS: exact bytes back, including the 2-byte VLESS response header.
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0u8; 5];
        s.read_exact(&mut b).await.unwrap();
        s.write_all(&b).await.unwrap();
    });
    log.insert(
        "echo".into(),
        json!(exchange(proxy, &vless_request(echo_port, b"hello")).await),
    );

    // BitTorrent handshake: sniffed and routed to the blackhole.
    let mut bt = vec![19];
    bt.extend_from_slice(b"BitTorrent protocol");
    bt.extend_from_slice(&[0; 48]);
    let started = std::time::Instant::now();
    log.insert(
        "bittorrent".into(),
        json!(exchange(proxy, &vless_request(6881, &bt)).await),
    );
    log.insert(
        "bittorrent_closed_fast".into(),
        json!(started.elapsed() < Duration::from_secs(3)),
    );

    // Private targets are blackholed by freedom's default final rule (not allowed by finalRules).
    let started = std::time::Instant::now();
    let mut private = vec![0];
    private.extend_from_slice(&uuid_bytes(ALICE));
    private.extend_from_slice(&[0, 1, 0, 80, 1, 10, 0, 0, 1]);
    let mut stream = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    stream.write_all(&private).await.unwrap();
    let mut first = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut first)).await;
    log.insert(
        "private_held_open".into(),
        json!(read.is_err() && started.elapsed() >= Duration::from_secs(2)),
    );
    drop(stream);

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
        json!(op("/node/handler/remove-user", remove).await),
    );
    log.insert(
        "after_remove".into(),
        json!(exchange(proxy, &vless_request(echo_port, b"hello")).await),
    );
    log.insert(
        "remove_again".into(),
        json!(
            op(
                "/node/handler/remove-user",
                json!({"username": "alice", "hashData": {"vlessUuid": ALICE}})
            )
            .await
        ),
    );
    child.kill().await.ok();
    Value::Object(log)
}

#[tokio::test(flavor = "multi_thread")]
async fn rcore_matches_go_xray_for_node_operations() {
    let rust = transcript(env!("CARGO_BIN_EXE_rcore")).await;
    eprintln!("rcore transcript: {rust:#}");
    assert_eq!(rust["echo"], json!([0, 0, 104, 101, 108, 108, 111]));
    assert_eq!(rust["bittorrent_closed_fast"], true);
    assert_eq!(rust["private_held_open"], true);
    let Ok(go) = std::env::var("XRAY_BINARY") else {
        eprintln!("XRAY_BINARY not set: skipped the comparison with Go Xray");
        return;
    };
    let go = transcript(&go).await;
    // The API inbound counts raw HTTP/2 bytes of the gRPC server itself; Go's grpc-go and tonic frame
    // differently, so only that inbound's byte counts are excluded. Everything users see must match.
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
        "rcore differs from Go Xray:\n{}",
        diffs.join("\n")
    );
}

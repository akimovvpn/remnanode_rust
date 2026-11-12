use remnanode_rust::{
    core::Core,
    grpc::{Grpc, SingleString, User},
    operations,
};
use serde_json::json;
use std::{net::TcpListener, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

#[derive(Clone, PartialEq, prost::Message)]
struct InboundUsers {
    #[prost(message, repeated, tag = "1")]
    users: Vec<User>,
}

// Set XRAY_BINARY to opt into network RPC tests against a real local Xray.
#[tokio::test]
async fn real_xray_native_rpc_add_remove_and_stats() {
    let Ok(binary) = std::env::var("XRAY_BINARY") else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let listeners: Vec<_> = (0..6)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<_> = listeners
        .iter()
        .map(|s| s.local_addr().unwrap().port())
        .collect();
    let port = ports[0];
    let certificate = Command::new(&binary)
        .args(["tls", "cert", "--domain=localhost"])
        .output()
        .await
        .unwrap();
    assert!(certificate.status.success());
    let certificate: serde_json::Value = serde_json::from_slice(&certificate.stdout).unwrap();
    let config = json!({
        "log":{"loglevel":"debug"},
        "api":{"tag":"api","services":["HandlerService","StatsService"]},
        "stats":{},
        "policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true}},"system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true}},
        "inbounds":[
            {"tag":"api-in","listen":"127.0.0.1","port":port,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}},
            {"tag":"vless","listen":"127.0.0.1","port":ports[1],"protocol":"vless","settings":{"clients":[],"decryption":"none"}},
            {"tag":"trojan","listen":"127.0.0.1","port":ports[2],"protocol":"trojan","settings":{"clients":[]}},
            {"tag":"ss","listen":"127.0.0.1","port":ports[3],"protocol":"shadowsocks","settings":{"clients":[{"password":"seed-password","method":"aes-128-gcm"}]}},
            {"tag":"ss22","listen":"127.0.0.1","port":ports[4],"protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-128-gcm","password":"MDEyMzQ1Njc4OTAxMjM0NQ==","clients":[{"email":"seed","password":"MDEyMzQ1Njc4OTAxMjM0NQ=="}]}},
            {"tag":"hy","listen":"127.0.0.1","port":ports[5],"protocol":"hysteria","settings":{"version":2,"clients":[]},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"certificates":[certificate]}}}
        ],
        "outbounds":[{"tag":"direct","protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}],
        "routing":{"rules":[{"type":"field","inboundTag":["api-in"],"outboundTag":"api"}]}
    });
    let path = temp.path().join("xray.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    drop(listeners);
    let mut child = Command::new(&binary)
        .args(["run", "-c"])
        .arg(&path)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let endpoint = format!("http://127.0.0.1:{port}");
    let mut ready = false;
    for _ in 0..60 {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("Xray exited: {status}");
        }
        if let Ok(mut grpc) = Grpc::connect(&endpoint).await
            && grpc.sys_stats().await.is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "Xray gRPC never became ready");
    let mut core = Core::new(binary.into(), temp.path().into(), endpoint);
    core.inbound_ciphers.insert("ss".into(), 5);
    let id = "550e8400-e29b-41d4-a716-446655440000";
    let body = json!({"data":[
        {"type":"vless","tag":"vless","username":"alice","uuid":id,"flow":""},
        {"type":"trojan","tag":"trojan","username":"alice","password":"secret"},
        {"type":"shadowsocks","tag":"ss","username":"alice","password":"secret","cipherType":5,"ivCheck":false},
        {"type":"shadowsocks22","tag":"ss22","username":"alice","password":"MDEyMzQ1Njc4OTAxMjM0NQ=="},
        {"type":"hysteria","tag":"hy","username":"alice","password":"secret"}
    ],"hashData":{"vlessUuid":id}});
    assert_eq!(
        operations::handle("/node/handler/add-user", &body, &mut core)
            .await
            .unwrap()["success"],
        true
    );
    let mut grpc = Grpc::connect(&core.endpoint).await.unwrap();
    for tag in ["vless", "trojan", "ss", "ss22", "hy"] {
        assert!(core.inbounds[tag].contains(id));
        let response: InboundUsers = grpc
            .call(
                "/xray.app.proxyman.command.HandlerService/GetInboundUsers",
                SingleString { value: tag.into() },
            )
            .await
            .unwrap();
        assert!(
            response.users.iter().any(|user| user.email == "alice"),
            "missing account on {tag}"
        );
    }
    assert!(
        operations::handle("/node/stats/get-system-stats", &json!({}), &mut core)
            .await
            .unwrap()["xrayInfo"]["numGoroutine"]
            .as_u64()
            .unwrap()
            > 0
    );
    let stats = operations::handle(
        "/node/stats/get-all-inbounds-stats",
        &json!({"reset":false}),
        &mut core,
    )
    .await
    .unwrap();
    assert!(
        stats["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|stat| stat["inbound"] == "vless")
    );
    assert_eq!(
        operations::handle(
            "/node/stats/get-user-ip-list",
            &json!({"userId":"alice"}),
            &mut core
        )
        .await
        .unwrap(),
        json!({"ips":[]})
    );
    assert_eq!(
        operations::handle(
            "/node/stats/get-user-online-status",
            &json!({"username":"missing-user"}),
            &mut core
        )
        .await
        .unwrap(),
        json!({"isOnline":false})
    );
    assert!(
        operations::handle("/node/stats/get-users-ip-list", &json!({}), &mut core)
            .await
            .unwrap()["users"]
            .is_array()
    );
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = echo.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = echo.accept().await.unwrap();
        eprintln!("echo accepted");
        let mut payload = [0u8; 5];
        socket.read_exact(&mut payload).await.unwrap();
        eprintln!("echo received {:?}", payload);
        socket.write_all(&payload).await.unwrap();
        eprintln!("echo sent");
    });
    let mut proxy = tokio::net::TcpStream::connect(("127.0.0.1", ports[1]))
        .await
        .unwrap();
    let mut request = vec![0];
    request.extend_from_slice(uuid::Uuid::parse_str(id).unwrap().as_bytes());
    request.extend_from_slice(&[0, 1]);
    request.extend_from_slice(&target_port.to_be_bytes());
    request.extend_from_slice(&[1, 127, 0, 0, 1]);
    request.extend_from_slice(b"hello");
    proxy.write_all(&request).await.unwrap();
    let mut response = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), proxy.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"\0\0hello");
    echo.await.unwrap();
    drop(proxy);
    let stats = operations::handle(
        "/node/stats/get-users-stats",
        &json!({"reset":true}),
        &mut core,
    )
    .await
    .unwrap();
    let alice = stats["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["username"] == "alice")
        .unwrap();
    assert!(alice["uplink"].as_i64().unwrap() >= 5 && alice["downlink"].as_i64().unwrap() >= 5);
    assert_eq!(
        operations::handle(
            "/node/stats/get-users-stats",
            &json!({"reset":false}),
            &mut core
        )
        .await
        .unwrap(),
        json!({"users":[]})
    );
    assert_eq!(
        operations::handle(
            "/node/handler/remove-user",
            &json!({"username":"alice","hashData":{"vlessUuid":id}}),
            &mut core
        )
        .await
        .unwrap()["success"],
        true
    );
    assert!(core.inbounds.values().all(|hashes| hashes.is_empty()));
    // Removing an absent account must also be idempotent on real Xray status errors.
    operations::handle(
        "/node/handler/remove-user",
        &json!({"username":"alice","hashData":{"vlessUuid":id}}),
        &mut core,
    )
    .await
    .unwrap();
    for tag in ["vless", "trojan", "ss", "ss22", "hy"] {
        let response: InboundUsers = grpc
            .call(
                "/xray.app.proxyman.command.HandlerService/GetInboundUsers",
                SingleString { value: tag.into() },
            )
            .await
            .unwrap();
        assert!(
            response.users.iter().all(|user| user.email != "alice"),
            "account survived on {tag}"
        );
    }
    let bulk = json!({"affectedInboundTags":["vless","trojan","ss","ss22","hy"],"users":[{
        "userData":{"userId":"bob","hashUuid":id,"vlessUuid":id,"trojanPassword":"secret","ssPassword":"0123456789012345"},
        "inboundData":[{"type":"vless","tag":"vless","flow":""},{"type":"trojan","tag":"trojan"},{"type":"shadowsocks","tag":"ss"},{"type":"shadowsocks22","tag":"ss22"},{"type":"hysteria","tag":"hy"}]
    }]});
    operations::handle("/node/handler/add-users", &bulk, &mut core)
        .await
        .unwrap();
    for tag in ["vless", "trojan", "ss", "ss22", "hy"] {
        let response: InboundUsers = grpc
            .call(
                "/xray.app.proxyman.command.HandlerService/GetInboundUsers",
                SingleString { value: tag.into() },
            )
            .await
            .unwrap();
        assert!(
            response.users.iter().any(|user| user.email == "bob"),
            "missing bulk account on {tag}"
        );
    }
    operations::handle(
        "/node/handler/remove-users",
        &json!({"users":[{"userId":"bob","hashUuid":id}]}),
        &mut core,
    )
    .await
    .unwrap();
    child.kill().await.unwrap();
}

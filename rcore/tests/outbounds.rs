//! VLESS -> rcore -> real Go Xray SOCKS5, preserving TCP/UDP and proxy authentication.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
};

const ID: [u8; 16] = [1; 16];
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
async fn start(dir: &Path, name: &str, binary: &str, config: Value, port: u16) -> Result<Child> {
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, config.to_string())?;
    let child = Command::new(binary)
        .args(["run", "-config"])
        .arg(path)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(child);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("{name} failed to listen");
}
fn config(port: u16, outbound: Value) -> Value {
    json!({"inbounds":[{"tag":"in","listen":"127.0.0.1","port":port,"protocol":"vless",
        "settings":{"clients":[{"id":"01010101-0101-0101-0101-010101010101"}],"decryption":"none"}}],
        "outbounds":[outbound]})
}
async fn vless(port: u16, dest: u16, udp: bool, domain: bool) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let mut request = vec![0];
    request.extend_from_slice(&ID);
    request.extend_from_slice(&[0, if udp { 2 } else { 1 }]);
    request.extend_from_slice(&dest.to_be_bytes());
    if domain {
        request.extend_from_slice(b"\x02\x09localhost");
    } else {
        request.extend_from_slice(&[1, 127, 0, 0, 1]);
    }
    stream.write_all(&request).await?;
    Ok(stream)
}
async fn exchange(port: u16, tcp: u16, udp: u16) -> Result<()> {
    for domain in [false, true] {
        let mut stream = vless(port, tcp, false, domain).await?;
        stream.write_all(b"tcp via selected outbound").await?;
        let mut response = [0u8; 27];
        stream.read_exact(&mut response).await?;
        ensure!(response[..2] == [0, 0] && &response[2..] == b"tcp via selected outbound");
        stream.shutdown().await?;
    }
    let mut stream = vless(port, udp, true, false).await?;
    for (i, payload) in [b"first UDP packet".as_slice(), b"second UDP packet"]
        .into_iter()
        .enumerate()
    {
        stream
            .write_all(&(payload.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(payload).await?;
        if i == 1 {
            stream.shutdown().await?;
        }
        if i == 0 {
            let mut header = [0; 2];
            stream.read_exact(&mut header).await?;
            ensure!(header == [0, 0]);
        }
        let size = stream.read_u16().await?;
        let mut reply = vec![0; size as usize];
        stream.read_exact(&mut reply).await?;
        ensure!(reply == payload, "UDP payload changed");
    }
    Ok(())
}
async fn echoes() -> Result<(u16, u16)> {
    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let tcp_port = tcp.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                tokio::io::copy(&mut r, &mut w).await.ok();
            });
        }
    });
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_port = udp.local_addr()?.port();
    tokio::spawn(async move {
        let mut buf = vec![0; 65535];
        while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
            tokio::time::sleep(Duration::from_millis(75)).await;
            udp.send_to(&buf[..n], peer).await.ok();
        }
    });
    Ok((tcp_port, udp_port))
}
#[tokio::test]
async fn go_socks_outbound_relays_tcp_udp_with_and_without_auth() -> Result<()> {
    let Ok(xray) = std::env::var("XRAY_BINARY") else {
        return Ok(());
    };
    tokio::time::timeout(Duration::from_secs(20),async {
        let dir=tempfile::tempdir()?; let (tcp,udp)=echoes().await?;
        for auth in [false,true] {
            let (proxy,node)=(free_port(),free_port());
            let mut settings=json!({"udp":true,"ip":"127.0.0.1"});
            let mut remote=json!({"address":"127.0.0.1","port":proxy});
            if auth {settings["auth"]=json!("password");settings["accounts"]=json!([{"user":"alice","pass":"correct"}]);remote["user"]=json!("alice");remote["pass"]=json!("correct");}
            let _proxy=start(dir.path(),"proxy",&xray,json!({"inbounds":[{"listen":"127.0.0.1","port":proxy,"protocol":"socks","settings":settings}],
                "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8","::1/128"]}]}}]}),proxy).await?;
            let _node=start(dir.path(),"node",env!("CARGO_BIN_EXE_rcore"),config(node,json!({"protocol":"socks","settings":remote})),node).await?;
            exchange(node,tcp,udp).await.context("VLESS -> Rust -> Go SOCKS5 echo")?;
        }
        Result::<()>::Ok(())
    }).await.context("SOCKS interoperability deadline")?
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn freedom_applies_interface_and_fast_open_to_tcp_and_udp() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let dir = tempfile::tempdir()?;
        let (tcp, udp) = echoes().await?;
        let port = free_port();
        let _node = start(
            dir.path(),
            "node",
            env!("CARGO_BIN_EXE_rcore"),
            config(
                port,
                json!({"protocol":"freedom",
            "settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8","::1/128"]}]},
            "streamSettings":{"sockopt":{"interface":"lo","tcpFastOpen":true}}}),
            ),
            port,
        )
        .await?;
        exchange(port, tcp, udp).await
    })
    .await
    .context("interface relay deadline")?
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn missing_interface_never_connects_through_default_route() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let port = free_port();
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let _node = start(
        dir.path(),
        "node",
        env!("CARGO_BIN_EXE_rcore"),
        config(
            port,
            json!({"protocol":"freedom",
        "settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]},
        "streamSettings":{"sockopt":{"interface":"missing-device"}}}),
        ),
        port,
    )
    .await?;
    let mut stream = vless(port, echo.local_addr()?.port(), false, false).await?;
    stream.write_all(b"must not escape").await?;
    ensure!(
        tokio::time::timeout(Duration::from_millis(500), echo.accept())
            .await
            .is_err(),
        "outbound escaped onto default interface"
    );
    let mut buf = [0];
    ensure!(
        matches!(
            tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        ),
        "failed route stayed open"
    );
    Ok(())
}

#[tokio::test]
async fn rejected_socks_auth_does_not_fall_back_to_direct() -> Result<()> {
    let Ok(xray) = std::env::var("XRAY_BINARY") else {
        return Ok(());
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let dir = tempfile::tempdir()?;
        let (proxy, node) = (free_port(), free_port());
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let _proxy = start(dir.path(), "proxy", &xray, json!({"inbounds":[{"listen":"127.0.0.1","port":proxy,"protocol":"socks",
            "settings":{"auth":"password","accounts":[{"user":"alice","pass":"correct"}]}}],"outbounds":[{"protocol":"freedom"}]}), proxy).await?;
        let mut cfg = config(node, json!({"tag":"direct","protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}));
        cfg["outbounds"].as_array_mut().unwrap().push(json!({"tag":"proxy","protocol":"socks","settings":{"address":"127.0.0.1","port":proxy,"user":"alice","pass":"wrong"}}));
        cfg["routing"] = json!({"rules":[{"inboundTag":["in"],"outboundTag":"proxy"}]});
        let _node = start(dir.path(), "node", env!("CARGO_BIN_EXE_rcore"), cfg, node).await?;
        let mut stream = vless(node, target.local_addr()?.port(), false, false).await?;
        stream.write_all(b"must not bypass proxy").await?;
        ensure!(tokio::time::timeout(Duration::from_millis(500), target.accept()).await.is_err(), "proxy failure leaked onto direct outbound");
        let mut buf = [0];
        ensure!(matches!(tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await, Ok(Ok(0)) | Ok(Err(_))), "rejected proxy connection stayed open");
        Result::<()>::Ok(())
    }).await.context("SOCKS rejection deadline")?
}

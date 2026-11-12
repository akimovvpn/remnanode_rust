//! Go Xray Vision client -> rcore REALITY server -> local plaintext or TLS application.
//! Run with XRAY_BINARY=/path/to/xray cargo test -p rcore --test vision_interop.
use anyhow::{Context, Result, ensure};
use base64::Engine;
use serde_json::json;
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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

async fn socks_connect(socks: u16, target: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    ensure!(greeting == [5, 0], "SOCKS greeting: {greeting:?}");
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await?;
    ensure!(reply[1] == 0, "SOCKS connect reply: {reply:?}");
    Ok(stream)
}

async fn setup(dir: &Path, xray: &str) -> Result<(Vec<Child>, u16)> {
    let cert = dir.join("target.pem");
    let key = dir.join("target.key");
    let certificate = Command::new("openssl")
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
        .await?;
    ensure!(
        certificate.status.success(),
        "certificate: {}",
        String::from_utf8_lossy(&certificate.stderr)
    );
    let (target_port, server_port, socks_port) = (free_port(), free_port(), free_port());
    let target = spawn_logged(
        Command::new("openssl")
            .args([
                "s_server",
                "-quiet",
                "-tls1_3",
                "-www",
                "-groups",
                "X25519",
                "-accept",
                &target_port.to_string(),
                "-cert",
            ])
            .arg(&cert)
            .arg("-key")
            .arg(&key)
            .args(["-servername", SNI, "-cert2"])
            .arg(&cert)
            .arg("-key2")
            .arg(&key)
            .stdin(Stdio::null()),
        dir,
        "reality-target",
    )?;
    wait_port(target_port).await?;
    let private: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let server = json!({"log": {"loglevel": "debug"},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": server_port, "protocol": "vless",
            "settings": {"flow": FLOW, "clients": [{"id": ID, "email": "vision"}], "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "target": format!("127.0.0.1:{target_port}"), "serverNames": [SNI],
                "privateKey": b64.encode(private), "shortIds": ["0123abcd"]}}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]
    });
    let client = json!({"log": {"loglevel": "debug"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": false}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": server_port,
            "users": [{"id": ID, "encryption": "none", "flow": FLOW}]}]},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "serverName": SNI, "password": b64.encode(public.as_bytes()), "shortId": "0123abcd", "fingerprint": "chrome"}}}]
    });
    std::fs::write(dir.join("server.json"), server.to_string())?;
    std::fs::write(dir.join("client.json"), client.to_string())?;
    let server = spawn_logged(
        Command::new(env!("CARGO_BIN_EXE_rcore"))
            .args(["run", "-config"])
            .arg(dir.join("server.json")),
        dir,
        "rcore",
    )?;
    let client = spawn_logged(
        Command::new(xray)
            .args(["run", "-config"])
            .arg(dir.join("client.json")),
        dir,
        "xray",
    )?;
    wait_port(server_port).await?;
    wait_port(socks_port).await?;
    Ok((vec![target, server, client], socks_port))
}

fn payload(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i % 251) as u8).collect()
}

async fn plaintext(socks: u16) -> Result<()> {
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let port = echo.local_addr()?.port();
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await?;
        let mut buffer = [0; 65536];
        loop {
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            stream.write_all(&buffer[..n]).await?;
        }
        std::io::Result::Ok(())
    });
    let mut stream = socks_connect(socks, port).await?;
    for message in [&b"ping"[..], b"second message", &[7; 3000]] {
        stream.write_all(message).await?;
        let mut received = vec![0; message.len()];
        tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut received))
            .await
            .context("plaintext message echo timed out")??;
        ensure!(received == message, "plaintext echo corrupted");
    }
    let data = payload(4_000_000);
    let (mut reader, mut writer) = stream.into_split();
    let upload = data.clone();
    let sending = tokio::spawn(async move { writer.write_all(&upload).await });
    let mut received = vec![0; data.len()];
    reader.read_exact(&mut received).await?;
    sending.await??;
    ensure!(received == data, "large plaintext echo corrupted");
    drop(reader);
    echo_task.abort();
    Ok(())
}

async fn inner_tls(dir: &Path, socks: u16, version: &str) -> Result<()> {
    let port = free_port();
    let mut server = Command::new("openssl")
        .args([
            "s_server",
            "-quiet",
            version,
            "-accept",
            &port.to_string(),
            "-cert",
        ])
        .arg(dir.join("target.pem"))
        .arg("-key")
        .arg(dir.join("target.key"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(std::fs::File::create(
            dir.join("inner-server.log"),
        )?))
        .kill_on_drop(true)
        .spawn()?;
    wait_port(port).await?;
    let bridge = TcpListener::bind("127.0.0.1:0").await?;
    let bridge_port = bridge.local_addr()?.port();
    let forwarding = tokio::spawn(async move {
        let (mut app, _) = bridge.accept().await?;
        let mut tunnel = socks_connect(socks, port).await?;
        tokio::io::copy_bidirectional(&mut app, &mut tunnel).await?;
        anyhow::Ok(())
    });
    let mut client = Command::new("openssl")
        .args([
            "s_client",
            "-quiet",
            "-ign_eof",
            version,
            "-connect",
            &format!("127.0.0.1:{bridge_port}"),
            "-servername",
            SNI,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(std::fs::File::create(
            dir.join("inner-client.log"),
        )?))
        .kill_on_drop(true)
        .spawn()?;
    let upload = payload(2_000_000);
    let download = payload(3_000_000);
    let request_header = format!(
        "POST /vision HTTP/1.1\r\nHost: {SNI}\r\nContent-Length: {}\r\n\r\n",
        upload.len()
    );
    let mut request = request_header.into_bytes();
    request.extend_from_slice(&upload);
    let expected_request = request.clone();
    let mut client_in = client.stdin.take().context("client stdin")?;
    let sending = tokio::spawn(async move {
        client_in.write_all(&request).await?;
        Ok::<_, std::io::Error>(client_in)
    });
    let mut received_request = vec![0; expected_request.len()];
    let mut server_out = server.stdout.take().context("server stdout")?;
    server_out
        .read_exact(&mut received_request)
        .await
        .context("inner TLS upload")?;
    let mut client_in = sending.await??;
    ensure!(
        received_request == expected_request,
        "{version} HTTP upload corrupted"
    );
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        download.len()
    )
    .into_bytes();
    response.extend_from_slice(&download);
    let expected_response = response.clone();
    let mut server_in = server.stdin.take().context("server stdin")?;
    let sending = tokio::spawn(async move {
        server_in.write_all(&response).await?;
        // Keep OpenSSL alive until the receiving side has consumed the response.
        Ok::<_, std::io::Error>(server_in)
    });
    let mut received_response = vec![0; expected_response.len()];
    client
        .stdout
        .take()
        .context("client stdout")?
        .read_exact(&mut received_response)
        .await
        .context("inner TLS download")?;
    let _server_in = sending.await??;
    ensure!(
        received_response == expected_response,
        "{version} HTTP download corrupted"
    );
    // A second request exercises uplink after the peer has announced its direct-copy decision.
    let followup = b"GET /after-response HTTP/1.1\r\nHost: target.test\r\n\r\n";
    client_in.write_all(followup).await?;
    let mut received_followup = vec![0; followup.len()];
    server_out.read_exact(&mut received_followup).await?;
    ensure!(
        received_followup == followup,
        "{version} followup request corrupted"
    );
    forwarding.abort();
    let log = std::fs::read_to_string(dir.join("xray.log"))?;
    if version == "-tls1_3" {
        ensure!(
            log.lines()
                .any(|line| line.contains("XtlsPadding ") && line.ends_with(" 2"))
                && log.contains("command 2"),
            "TLS 1.3 did not switch both directions to direct copy"
        );
    } else {
        ensure!(
            log.contains("found tls 1.2!"),
            "client did not recognize inner TLS 1.2"
        );
        ensure!(
            !log.contains("command 2")
                && !log
                    .lines()
                    .any(|line| line.contains("XtlsPadding ") && line.ends_with(" 2")),
            "TLS 1.2 incorrectly switched to direct copy"
        );
    }
    Ok(())
}

async fn run(version: Option<&str>) {
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
    let result = tokio::time::timeout(Duration::from_secs(45), async {
        let (_processes, socks) = setup(dir.path(), &xray).await.context("Vision fixture")?;
        match version {
            Some(version) => inner_tls(dir.path(), socks, version).await,
            None => plaintext(socks).await,
        }
    })
    .await;
    if !matches!(&result, Ok(Ok(()))) {
        for name in [
            "rcore",
            "xray",
            "reality-target",
            "inner-server",
            "inner-client",
        ] {
            if let Ok(log) = std::fs::read_to_string(dir.path().join(format!("{name}.log"))) {
                let lines: Vec<_> = log.lines().collect();
                eprintln!("--- {name} ({} lines) ---", lines.len());
                for line in lines.iter().take(30) {
                    eprintln!("{line}");
                }
                if lines.len() > 60 {
                    eprintln!("... omitted {} lines ...", lines.len() - 60);
                }
                for line in lines.iter().skip(lines.len().max(60) - 30) {
                    eprintln!("{line}");
                }
            }
        }
    }
    result
        .expect("Vision interop exceeded 45 seconds")
        .expect("Vision interop failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn vision_plaintext_multiple_and_large_echo() {
    run(None).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vision_inner_tls13_http_upload_and_download() {
    run(Some("-tls1_3")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vision_inner_tls12_http_upload_and_download() {
    run(Some("-tls1_2")).await;
}

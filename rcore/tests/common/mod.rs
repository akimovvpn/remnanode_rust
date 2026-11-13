//! UDP checks through a Go Xray SOCKS inbound; Go clients carry this UDP as XUDP (mux.cool).
use anyhow::{Context, Result, ensure};
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

async fn udp_associate(socks: u16) -> Result<(TcpStream, UdpSocket)> {
    let mut control = TcpStream::connect(("127.0.0.1", socks)).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    control.read_exact(&mut greeting).await?;
    ensure!(greeting == [5, 0], "SOCKS greeting: {greeting:?}");
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await?;
    ensure!(reply[1] == 0 && reply[3] == 1, "UDP associate: {reply:?}");
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(relay).await?;
    Ok((control, socket))
}

fn datagram(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// One SOCKS UDP reply as (source port, payload); the source must be 127.0.0.1.
async fn reply(socket: &UdpSocket) -> Result<(u16, Vec<u8>)> {
    let mut buf = vec![0; 65536];
    let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await
        .context("no UDP reply within 5s")??;
    ensure!(
        n >= 10 && buf[..8] == [0, 0, 0, 1, 127, 0, 0, 1],
        "SOCKS UDP reply header: {:?}",
        &buf[..n.min(10)]
    );
    Ok((u16::from_be_bytes([buf[8], buf[9]]), buf[10..n].to_vec()))
}

fn echo(socket: Arc<UdpSocket>, also: Option<Arc<UdpSocket>>) {
    tokio::spawn(async move {
        let mut buf = vec![0; 65536];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
            if let Some(other) = &also {
                let _ = other.send_to(b"cone", from).await;
            }
        }
    });
}

/// Echo, an unsolicited reply from another address (full cone, tagged with its source),
/// a second destination on the same association and a large datagram.
#[allow(dead_code)]
pub async fn xudp_checks(socks: u16) -> Result<()> {
    let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let (a_port, b_port) = (a.local_addr()?.port(), b.local_addr()?.port());
    echo(a, Some(b.clone()));
    echo(b, None);
    let (_control, udp) = udp_associate(socks).await?;
    udp.send(&datagram(a_port, b"first")).await?;
    let replies: HashSet<_> = [reply(&udp).await?, reply(&udp).await?].into();
    let expected = HashSet::from([(a_port, b"first".to_vec()), (b_port, b"cone".to_vec())]);
    ensure!(replies == expected, "replies {replies:?}");
    let big = vec![0x5a; 4000];
    udp.send(&datagram(b_port, &big)).await?;
    ensure!(reply(&udp).await? == (b_port, big), "large datagram");
    for i in 0..20u8 {
        udp.send(&datagram(a_port, &[i; 100])).await?;
        let (port, data) = reply(&udp).await?;
        ensure!(port == a_port && data == [i; 100], "echo {i}");
        ensure!(reply(&udp).await?.1 == b"cone", "cone {i}");
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn socks_connect(socks: u16, target: u16) -> Result<TcpStream> {
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

/// TCP echo through SOCKS: several round trips, then 4 MB both ways at once. The write half
/// stays open until the echo is read back (mux.cool has no half-close).
#[allow(dead_code)]
pub async fn tcp_checks(socks: u16) -> Result<()> {
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = echo.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while let Ok(n) = s.read(&mut buf).await
                    && n > 0
                {
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let mut s = socks_connect(socks, port).await?;
    for message in [&b"ping"[..], b"second message", &[7u8; 3000]] {
        s.write_all(message).await?;
        let mut back = vec![0u8; message.len()];
        tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut back))
            .await
            .context("echo timeout")??;
        ensure!(back == message, "echo mismatch");
    }
    let big: Vec<u8> = (0..4_000_000u32).map(|i| (i % 251) as u8).collect();
    let (mut r, mut w) = s.into_split();
    let sent = big.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&sent).await?;
        anyhow::Ok(w)
    });
    let mut got = vec![0u8; big.len()];
    tokio::time::timeout(Duration::from_secs(30), r.read_exact(&mut got))
        .await
        .context("large transfer timeout")??;
    writer.await??;
    ensure!(got == big, "large transfer corrupted");
    Ok(())
}

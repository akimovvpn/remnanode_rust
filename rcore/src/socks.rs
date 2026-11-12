//! SOCKS5 outbound wire protocol, following Xray's proxy/socks client.
use crate::vless::Address;
use anyhow::{Result, bail, ensure};
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct Server {
    pub address: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
}

pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    server: &Server,
    dest: &Address,
    port: u16,
    udp: bool,
) -> Result<(Address, u16)> {
    if let Some((user, pass)) = &server.auth {
        ensure!(
            (1..=255).contains(&user.len()) && (1..=255).contains(&pass.len()),
            "invalid SOCKS credential length"
        );
    }
    let mut request = vec![5, if udp { 3 } else { 1 }, 0];
    if udp {
        // RFC 1928: the client does not yet know its UDP source address or port.
        request.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0]);
    } else {
        encode_address(&mut request, dest, port)?;
    }
    let method = if server.auth.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await?;
    ensure!(reply[0] == 5, "invalid SOCKS server version");
    ensure!(
        reply[1] == method,
        "SOCKS server selected an unoffered authentication method"
    );
    if let Some((user, pass)) = &server.auth {
        let mut auth = vec![1, user.len() as u8];
        auth.extend_from_slice(user.as_bytes());
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass.as_bytes());
        stream.write_all(&auth).await?;
        stream.read_exact(&mut reply).await?;
        ensure!(
            reply[0] == 1 && reply[1] == 0,
            "SOCKS authentication rejected"
        );
    }
    stream.write_all(&request).await?;
    let mut response = [0; 4];
    stream.read_exact(&mut response).await?;
    ensure!(
        response[0] == 5 && response[2] == 0,
        "invalid SOCKS response header"
    );
    ensure!(
        response[1] == 0,
        "SOCKS request rejected with status {}",
        response[1]
    );
    let mut address = vec![response[3]];
    let len = match response[3] {
        1 => 4,
        4 => 16,
        3 => {
            let len = stream.read_u8().await?;
            address.push(len);
            len as usize
        }
        _ => bail!("invalid SOCKS address type"),
    };
    let start = address.len();
    address.resize(start + len + 2, 0);
    stream.read_exact(&mut address[start..]).await?;
    let (bound, port, _) = decode_address(&address)?;
    Ok((bound, port))
}

fn encode_address(out: &mut Vec<u8>, dest: &Address, port: u16) -> Result<()> {
    match dest {
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            ensure!(
                (1..=255).contains(&domain.len()),
                "invalid SOCKS domain length"
            );
            out.extend_from_slice(&[3, domain.len() as u8]);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

fn decode_address(packet: &[u8]) -> Result<(Address, u16, usize)> {
    let (start, len) = match packet.first() {
        Some(1) => (1, 4),
        Some(4) => (1, 16),
        Some(3) => {
            let len = *packet
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("truncated SOCKS address"))?
                as usize;
            ensure!(len > 0, "empty SOCKS domain");
            (2, len)
        }
        _ => bail!("invalid SOCKS address type"),
    };
    let end = start + len;
    ensure!(packet.len() >= end + 2, "truncated SOCKS address");
    let raw = &packet[start..end];
    let address = match packet[0] {
        1 => Address::Ip(IpAddr::from(<[u8; 4]>::try_from(raw)?)),
        4 => Address::Ip(IpAddr::from(<[u8; 16]>::try_from(raw)?)),
        _ => Address::Domain(std::str::from_utf8(raw)?.to_owned()),
    };
    Ok((
        address,
        u16::from_be_bytes([packet[end], packet[end + 1]]),
        end + 2,
    ))
}

pub fn udp_encode(dest: &Address, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    encode_address(&mut packet, dest, port)?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub fn udp_decode(packet: &[u8]) -> Result<&[u8]> {
    ensure!(packet.len() >= 4, "truncated SOCKS UDP header");
    ensure!(packet[..2] == [0, 0], "invalid SOCKS UDP reserved bytes");
    ensure!(
        packet[2] == 0,
        "fragmented SOCKS UDP packets are unsupported"
    );
    let (_, _, len) = decode_address(&packet[3..])?;
    Ok(&packet[3 + len..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    async fn exchange(
        dest: Address,
        udp: bool,
        auth: Option<(String, String)>,
        steps: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(Address, u16)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for (expected, response) in steps {
                let mut received = vec![0; expected.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, expected);
                stream.write_all(&response).await.unwrap();
            }
        });
        let mut stream = TcpStream::connect(addr).await?;
        let server = Server {
            address: addr.ip().to_string(),
            port: addr.port(),
            auth,
        };
        let result = timeout(
            Duration::from_secs(2),
            handshake(&mut stream, &server, &dest, 443, udp),
        )
        .await?;
        drop(stream);
        peer.await.expect("SOCKS mock protocol peer failed");
        result
    }

    #[tokio::test]
    async fn connect_preserves_ipv4_ipv6_and_remote_domain() {
        for (dest, encoded) in [
            (
                Address::Ip("192.0.2.1".parse().unwrap()),
                vec![1, 192, 0, 2, 1],
            ),
            (
                Address::Ip("2001:db8::1".parse().unwrap()),
                vec![4, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
            (
                Address::Domain("example.com".into()),
                b"\x03\x0bexample.com".to_vec(),
            ),
        ] {
            let mut request = vec![5, 1, 0];
            request.extend_from_slice(&encoded);
            request.extend_from_slice(&443u16.to_be_bytes());
            let mut response = vec![5, 0, 0];
            response.extend_from_slice(&encoded);
            response.extend_from_slice(&1080u16.to_be_bytes());
            let bound = exchange(
                dest.clone(),
                false,
                None,
                vec![(vec![5, 1, 0], vec![5, 0]), (request, response)],
            )
            .await
            .unwrap();
            assert_eq!(bound, (dest, 1080));
        }
    }

    #[tokio::test]
    async fn udp_associate_requests_unspecified_client_address() {
        let bound = exchange(
            Address::Domain("example.com".into()),
            true,
            None,
            vec![
                (vec![5, 1, 0], vec![5, 0]),
                (
                    vec![5, 3, 0, 1, 0, 0, 0, 0, 0, 0],
                    vec![5, 0, 0, 1, 0, 0, 0, 0, 0x04, 0x38],
                ),
            ],
        )
        .await
        .unwrap();
        assert_eq!(bound, (Address::Ip("0.0.0.0".parse().unwrap()), 1080));
    }

    #[tokio::test]
    async fn authenticates_without_offering_noauth() {
        let bound = exchange(
            Address::Ip("192.0.2.1".parse().unwrap()),
            false,
            Some(("alice".into(), "secret".into())),
            vec![
                (vec![5, 1, 2], vec![5, 2]),
                (b"\x01\x05alice\x06secret".to_vec(), vec![1, 0]),
                (
                    vec![5, 1, 0, 1, 192, 0, 2, 1, 1, 0xbb],
                    vec![5, 0, 0, 1, 127, 0, 0, 1, 4, 0x38],
                ),
            ],
        )
        .await
        .unwrap();
        assert_eq!(bound.1, 1080);
    }

    #[tokio::test]
    async fn rejects_unoffered_auth_and_malformed_auth_replies() {
        for (auth, greeting, reply, auth_reply) in [
            (None, vec![5, 1, 0], vec![5, 2], None),
            (None, vec![5, 1, 0], vec![4, 0], None),
            (None, vec![5, 1, 0], vec![5, 0xff], None),
            (
                Some(("a".into(), "b".into())),
                vec![5, 1, 2],
                vec![5, 0],
                None,
            ),
            (
                Some(("a".into(), "b".into())),
                vec![5, 1, 2],
                vec![5, 2],
                Some(vec![1, 1]),
            ),
            (
                Some(("a".into(), "b".into())),
                vec![5, 1, 2],
                vec![5, 2],
                Some(vec![5, 0]),
            ),
        ] {
            let mut steps = vec![(greeting, reply)];
            if let Some(reply) = auth_reply {
                steps.push((b"\x01\x01a\x01b".to_vec(), reply));
            }
            exchange(Address::Domain("example.com".into()), false, auth, steps)
                .await
                .unwrap_err();
        }
    }

    #[tokio::test]
    async fn rejects_invalid_connect_replies() {
        for reply in [
            vec![4, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            vec![5, 1, 0, 1, 0, 0, 0, 0, 0, 0],
            vec![5, 0, 1, 1, 0, 0, 0, 0, 0, 0],
            vec![5, 0, 0, 9],
            vec![5, 0, 0, 3, 0, 0, 0],
            vec![5, 0, 0, 3, 1, 0xff, 0, 0],
            vec![5, 0, 0, 1, 127],
        ] {
            assert!(
                exchange(
                    Address::Ip("192.0.2.1".parse().unwrap()),
                    false,
                    None,
                    vec![
                        (vec![5, 1, 0], vec![5, 0]),
                        (vec![5, 1, 0, 1, 192, 0, 2, 1, 1, 0xbb], reply),
                    ]
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn rejects_credentials_outside_wire_length_without_sending_them() {
        for auth in [
            ("".into(), "b".into()),
            ("a".into(), "".into()),
            ("a".repeat(256), "b".into()),
            ("a".into(), "b".repeat(256)),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut stream = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let server = Server {
                address: "127.0.0.1".into(),
                port: 1080,
                auth: Some(auth),
            };
            assert!(
                handshake(
                    &mut stream,
                    &server,
                    &Address::Domain("example.com".into()),
                    443,
                    false
                )
                .await
                .is_err()
            );
            drop(stream);
            assert_eq!(peer.read(&mut [0; 512]).await.unwrap(), 0);
        }
    }

    #[test]
    fn udp_packets_preserve_addresses_and_payload() {
        for (dest, expected) in [
            (
                Address::Ip("192.0.2.1".parse().unwrap()),
                b"\0\0\0\x01\xc0\0\x02\x01\x01\xbbhello".to_vec(),
            ),
            (
                Address::Ip("::1".parse().unwrap()),
                b"\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\x01\xbbhello".to_vec(),
            ),
            (
                Address::Domain("example.com".into()),
                b"\0\0\0\x03\x0bexample.com\x01\xbbhello".to_vec(),
            ),
        ] {
            assert_eq!(udp_encode(&dest, 443, b"hello").unwrap(), expected);
            assert_eq!(udp_decode(&expected).unwrap(), b"hello");
            let header_len = expected.len() - 5;
            assert_eq!(udp_decode(&expected[..header_len]).unwrap(), b"");
            for end in 0..header_len {
                assert!(
                    udp_decode(&expected[..end]).is_err(),
                    "accepted truncated UDP header at {end}"
                );
            }
        }
    }

    #[test]
    fn rejects_malformed_udp_headers_and_fragmentation() {
        for packet in [
            b"\0\0\x01\x01\x7f\0\0\x01\0\x35".as_slice(),
            b"\0\x01\0\x01\x7f\0\0\x01\0\x35",
            b"\0\0\0\x05\x7f\0\0\x01\0\x35",
            b"\0\0\0\x03\0\0\x35",
            b"\0\0\0\x03\x01\xff\0\x35",
        ] {
            assert!(udp_decode(packet).is_err());
        }
        assert!(udp_encode(&Address::Domain("".into()), 53, b"").is_err());
        assert!(udp_encode(&Address::Domain("a".repeat(256)), 53, b"").is_err());
    }
}

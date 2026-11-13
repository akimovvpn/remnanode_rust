//! Port of xray-core proxy/vless: validator, request header decoding and flow checks.
use crate::config::User;
use anyhow::{Result, bail, ensure};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const XRV: &str = "xtls-rprx-vision";

/// MemoryValidator: users keyed by ProcessUUID (bytes 6-7 carry vlessRoute) and lowercase email.
#[derive(Default)]
pub struct Users {
    by_id: RwLock<HashMap<[u8; 16], Arc<User>>>,
    by_email: RwLock<HashMap<String, Arc<User>>>,
}

fn process_uuid(mut id: [u8; 16]) -> [u8; 16] {
    id[6] = 0;
    id[7] = 0;
    id
}

impl Users {
    pub fn add(&self, user: User) -> Result<()> {
        let user = Arc::new(user);
        if !user.email.is_empty() {
            let mut emails = self.by_email.write().unwrap();
            let key = user.email.to_lowercase();
            ensure!(
                !emails.contains_key(&key),
                "User {} already exists.",
                user.email
            );
            emails.insert(key, user.clone());
        }
        self.by_id
            .write()
            .unwrap()
            .insert(process_uuid(user.id), user);
        Ok(())
    }
    pub fn remove(&self, email: &str) -> Result<()> {
        ensure!(!email.is_empty(), "Email must not be empty.");
        let Some(user) = self.by_email.write().unwrap().remove(&email.to_lowercase()) else {
            bail!("User {email} not found.");
        };
        self.by_id.write().unwrap().remove(&process_uuid(user.id));
        Ok(())
    }
    pub fn get(&self, id: [u8; 16]) -> Option<Arc<User>> {
        self.by_id.read().unwrap().get(&process_uuid(id)).cloned()
    }
    pub fn by_email(&self, email: &str) -> Option<Arc<User>> {
        self.by_email
            .read()
            .unwrap()
            .get(&email.to_lowercase())
            .cloned()
    }
    pub fn all(&self) -> Vec<Arc<User>> {
        self.by_id.read().unwrap().values().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Address {
    Ip(IpAddr),
    Domain(String),
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Address::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
            Address::Ip(ip) => write!(f, "{ip}"),
            Address::Domain(d) => f.write_str(d),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
    Rvs,
}

pub struct Request {
    pub user: Arc<User>,
    pub sent_id: [u8; 16],
    pub flow: String,
    pub command: Command,
    pub address: Address,
    pub port: u16,
}

/// Reads exactly `n` more bytes into `buf`, reading from `r` as needed.
async fn need<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    pos: usize,
    n: usize,
) -> Result<()> {
    while buf.len() < pos + n {
        let mut chunk = [0u8; 8192];
        let read = r.read(&mut chunk).await?;
        ensure!(read > 0, "EOF");
        buf.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

/// Decodes a VLESS request header (encoding.DecodeRequestHeader). Returns the request and any payload read past it.
pub async fn read_request<R: AsyncRead + Unpin>(
    r: &mut R,
    users: &Users,
) -> Result<(Request, Vec<u8>)> {
    let mut buf = Vec::with_capacity(8192);
    let mut pos = 0;
    need(r, &mut buf, pos, 1)
        .await
        .map_err(|e| e.context("failed to read request version"))?;
    ensure!(buf[0] == 0, "invalid request version");
    pos += 1;
    need(r, &mut buf, pos, 16)
        .await
        .map_err(|e| e.context("failed to read request user id"))?;
    let id: [u8; 16] = buf[pos..pos + 16].try_into()?;
    pos += 16;
    let Some(user) = users.get(id) else {
        bail!("invalid request user id: {}", uuid_string(id));
    };
    need(r, &mut buf, pos, 1).await?;
    let addons_len = buf[pos] as usize;
    pos += 1;
    need(r, &mut buf, pos, addons_len).await?;
    let flow = if addons_len == 0 {
        String::new()
    } else {
        decode_flow(&buf[pos..pos + addons_len])?
    };
    pos += addons_len;
    need(r, &mut buf, pos, 1)
        .await
        .map_err(|e| e.context("failed to read request command"))?;
    let command = match buf[pos] {
        1 => Command::Tcp,
        2 => Command::Udp,
        3 => Command::Mux,
        4 => Command::Rvs,
        _ => bail!("invalid request address"),
    };
    pos += 1;
    let (address, port) = match command {
        Command::Mux => (Address::Domain("v1.mux.cool".into()), 0),
        Command::Rvs => (Address::Domain("v1.rvs.cool".into()), 0),
        Command::Tcp | Command::Udp => {
            // protocol.PortThenAddress
            need(r, &mut buf, pos, 3)
                .await
                .map_err(|_| anyhow::anyhow!("invalid request address"))?;
            let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let kind = buf[pos + 2];
            pos += 3;
            let address = match kind {
                1 => {
                    need(r, &mut buf, pos, 4).await?;
                    let ip: [u8; 4] = buf[pos..pos + 4].try_into()?;
                    pos += 4;
                    Address::Ip(ip.into())
                }
                3 => {
                    need(r, &mut buf, pos, 16).await?;
                    let ip: [u8; 16] = buf[pos..pos + 16].try_into()?;
                    pos += 16;
                    Address::Ip(IpAddr::from(ip).to_canonical())
                }
                2 => {
                    need(r, &mut buf, pos, 1).await?;
                    let len = buf[pos] as usize;
                    pos += 1;
                    need(r, &mut buf, pos, len).await?;
                    let domain = String::from_utf8_lossy(&buf[pos..pos + len]).into_owned();
                    pos += len;
                    // net.ParseAddress turns IP literals sent as domains into IPs.
                    match domain
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .parse::<IpAddr>()
                    {
                        Ok(ip) => Address::Ip(ip.to_canonical()),
                        Err(_) => Address::Domain(domain),
                    }
                }
                _ => bail!("invalid request address"),
            };
            (address, port)
        }
    };
    let rest = buf.split_off(pos);
    Ok((
        Request {
            user,
            sent_id: id,
            flow,
            command,
            address,
            port,
        },
        rest,
    ))
}

/// Addons protobuf: field 1 Flow (string), field 2 Seed (bytes, ignored).
fn decode_flow(mut b: &[u8]) -> Result<String> {
    let mut flow = String::new();
    while !b.is_empty() {
        let key = b[0];
        ensure!(
            key & 0x80 == 0 && key & 0x07 == 2,
            "failed to unmarshal addons protobuf value"
        );
        ensure!(
            b.len() >= 2 && b[1] & 0x80 == 0,
            "failed to unmarshal addons protobuf value"
        );
        let len = b[1] as usize;
        ensure!(
            b.len() >= 2 + len,
            "failed to unmarshal addons protobuf value"
        );
        if key >> 3 == 1 {
            flow = String::from_utf8_lossy(&b[2..2 + len]).into_owned();
        }
        b = &b[2 + len..];
    }
    Ok(flow)
}

pub fn uuid_string(id: [u8; 16]) -> String {
    let h: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// isMuxAndNotXUDP: `first` is the payload that arrived with the request header.
fn is_mux_and_not_xudp(request: &Request, first: &[u8]) -> bool {
    request.command == Command::Mux
        && (first.len() < 7 || !(first[2] == 0 && first[3] == 0 && first[6] == 2))
}

/// Inbound flow checks (inbound.go Process). `outer_tls` is true behind TLS 1.3 / REALITY.
pub fn check_flow(request: &Request, outer_tls: bool, first: &[u8]) -> Result<()> {
    let account = uuid_string(request.user.id);
    match request.flow.as_str() {
        XRV if request.user.flow == XRV => {
            ensure!(request.command != Command::Udp, "{XRV} doesn't support UDP");
            ensure!(outer_tls, "failed to use {XRV}, found outer tls version 0");
            Ok(())
        }
        XRV => bail!("account {account} is not able to use the flow {XRV}"),
        "" => {
            ensure!(
                !(request.user.flow == XRV
                    && (request.command == Command::Tcp || is_mux_and_not_xudp(request, first))),
                "account {account} is rejected since the client flow is empty. Note that the pure TLS proxy has certain TLS in TLS characters."
            );
            Ok(())
        }
        other => bail!("unknown request flow {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn user(email: &str, id: u8, flow: &str) -> User {
        User {
            email: email.into(),
            level: 0,
            id: [id; 16],
            flow: flow.into(),
        }
    }
    #[test]
    fn validator_matches_go_semantics() {
        let users = Users::default();
        users.add(user("Alice", 1, "")).unwrap();
        assert!(
            users
                .add(user("alice", 2, ""))
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        let mut routed = [1u8; 16];
        routed[6] = 9;
        routed[7] = 9;
        assert!(
            users.get(routed).is_some(),
            "bytes 6-7 are vlessRoute, not identity"
        );
        assert_eq!(
            users.remove("nobody").unwrap_err().to_string(),
            "User nobody not found."
        );
        users.remove("ALICE").unwrap();
        assert!(users.get([1; 16]).is_none());
    }
    #[tokio::test]
    async fn decodes_request_header_and_payload() {
        let users = Users::default();
        users.add(user("a", 7, "")).unwrap();
        let mut wire = vec![0];
        wire.extend_from_slice(&[7; 16]);
        wire.extend_from_slice(&[0, 1, 0x01, 0xbb, 2, 11]);
        wire.extend_from_slice(b"example.com");
        wire.extend_from_slice(b"hello");
        let (req, rest) = read_request(&mut wire.as_slice(), &users).await.unwrap();
        assert_eq!(
            (req.command, req.port, req.address.clone()),
            (Command::Tcp, 443, Address::Domain("example.com".into()))
        );
        assert_eq!(rest, b"hello");
        check_flow(&req, false, &rest).unwrap();
        let mut bad = vec![0];
        bad.extend_from_slice(&[8; 16]);
        let error = read_request(&mut bad.as_slice(), &users)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("invalid request user id"), "{error}");
    }

    #[test]
    fn vision_accounts_without_flow_only_get_xudp_mux() {
        let request = |command| Request {
            user: Arc::new(user("v", 1, XRV)),
            sent_id: [1; 16],
            flow: String::new(),
            command,
            address: Address::Domain("v1.mux.cool".into()),
            port: 0,
        };
        // XUDP: session 0, New, network UDP.
        let xudp = [0, 12, 0, 0, 1, 1, 2];
        check_flow(&request(Command::Mux), true, &xudp).unwrap();
        for first in [
            &[0, 12, 0, 1, 1, 1, 2][..],
            &[0, 12, 0, 0, 1, 1, 1],
            &xudp[..6],
        ] {
            assert!(check_flow(&request(Command::Mux), true, first).is_err());
        }
        assert!(check_flow(&request(Command::Tcp), true, b"").is_err());
        check_flow(&request(Command::Udp), true, b"").unwrap();
    }
}

//! Port of xray-core proxy/dns: the `dns` outbound that hijacks A/AAAA queries into the DNS
//! module and passes, rejects or drops the rest by its rules.
use crate::app::{Activity, Instance, Sid};
use crate::config::{Outbound, keys, port_list, string_list};
use crate::dns::{IpOption, TYPE_A, TYPE_AAAA, parse_address, put_name, read_name, type_name};
use crate::geodata::{DomainMatcher, Kind, Loader};
use crate::vless::Address;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, mpsc},
};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Action {
    Direct,
    Drop,
    Return,
    Hijack,
}

pub struct Rule {
    action: Action,
    qtypes: Vec<u16>,
    domains: Option<DomainMatcher>,
    rcode: u16,
}

pub struct DnsOutbound {
    /// rewriteServer: network (true = TCP), address and port; unset parts keep the target's.
    network: Option<bool>,
    address: Option<Address>,
    port: u16,
    pub user_level: u32,
    rules: Vec<Rule>,
}

impl DnsOutbound {
    /// infra/conf DNSOutboundConfig.Build.
    pub fn parse(
        settings: &Value,
        path: &str,
        loader: &mut Loader,
        warnings: &mut Vec<String>,
    ) -> Result<Self> {
        keys(
            settings,
            &[
                "rewriteNetwork",
                "rewriteAddress",
                "rewritePort",
                "network",
                "address",
                "port",
                "userLevel",
                "rules",
                "nonIPQuery",
                "blockTypes",
            ],
            path,
        )?;
        let text = |k: &str| -> Result<Option<&str>> {
            match &settings[k] {
                Value::Null => Ok(None),
                Value::String(s) => Ok(Some(s)),
                _ => bail!("{path}.{k} must be a string"),
            }
        };
        let number = |k: &str, max: u64| -> Result<u64> {
            match &settings[k] {
                Value::Null => Ok(0),
                v => v
                    .as_u64()
                    .filter(|n| *n <= max)
                    .with_context(|| format!("{path}.{k} must be an integer up to {max}")),
            }
        };
        let network = text("network")?
            .filter(|n| !n.is_empty())
            .or(text("rewriteNetwork")?)
            .and_then(|n| match n.to_lowercase().as_str() {
                "tcp" => Some(true),
                "udp" => Some(false),
                _ => None,
            });
        let address = text("address")?
            .or(text("rewriteAddress")?)
            .map(parse_address);
        let port = match number("port", 65535)? {
            0 => number("rewritePort", 65535)?,
            p => p,
        } as u16;
        let user_level = number("userLevel", u32::MAX as u64)? as u32;
        let legacy = !settings["nonIPQuery"].is_null() || !settings["blockTypes"].is_null();
        let rules = if legacy {
            if !settings["rules"].is_null() {
                bail!("legacy nonIPQuery and blockTypes cannot be mixed with rules");
            }
            warnings.push("common/errors: This feature \"nonIPQuery\" and \"blockTypes\" is deprecated, will be removed soon and being migrated to \"rules\". Please update your config(s) according to release note and documentation before removal.".into());
            let mode = text("nonIPQuery")?
                .filter(|m| !m.is_empty())
                .unwrap_or("reject");
            if !matches!(mode, "reject" | "drop" | "skip") {
                bail!("unknown nonIPQuery: {mode}");
            }
            let mut rules = Vec::new();
            let blocked: Vec<u16> = match &settings["blockTypes"] {
                Value::Null => Vec::new(),
                Value::Array(items) => items
                    .iter()
                    .map(|v| {
                        v.as_i64()
                            .filter(|t| (0..=65535).contains(t))
                            .map(|t| t as u16)
                            .with_context(|| format!("legacy blockTypes qType out of range: {v}"))
                    })
                    .collect::<Result<_>>()?,
                _ => bail!("{path}.blockTypes must be an array"),
            };
            if !blocked.is_empty() {
                let reject = mode == "reject";
                rules.push(Rule {
                    action: if reject { Action::Return } else { Action::Drop },
                    qtypes: blocked,
                    domains: None,
                    rcode: if reject { 5 } else { 0 },
                });
            }
            rules.push(Rule {
                action: Action::Hijack,
                qtypes: vec![TYPE_A, TYPE_AAAA],
                domains: None,
                rcode: 0,
            });
            rules.push(Rule {
                action: match mode {
                    "drop" => Action::Drop,
                    "skip" => Action::Direct,
                    _ => Action::Return,
                },
                qtypes: Vec::new(),
                domains: None,
                rcode: if mode == "reject" { 5 } else { 0 },
            });
            rules
        } else {
            let mut rules = Vec::new();
            for (i, r) in settings["rules"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
            {
                let p = format!("{path}.rules[{i}]");
                keys(r, &["action", "qType", "domain", "rCode"], &p)?;
                let action = match r["action"]
                    .as_str()
                    .unwrap_or_default()
                    .to_lowercase()
                    .as_str()
                {
                    "direct" => Action::Direct,
                    "drop" => Action::Drop,
                    "return" => Action::Return,
                    "hijack" => Action::Hijack,
                    _ => bail!(
                        "unknown action: {}",
                        r["action"].as_str().unwrap_or_default()
                    ),
                };
                let mut qtypes = Vec::new();
                for (a, b) in port_list(&r["qType"], &format!("{p}.qType"))? {
                    qtypes.extend(a..=b);
                }
                let domains = string_list(&r["domain"], &format!("{p}.domain"))?;
                let rcode = match &r["rCode"] {
                    Value::Null => 0,
                    v => {
                        let c = v
                            .as_u64()
                            .with_context(|| format!("{p}.rCode must be a number"))?;
                        if c > 65535 {
                            bail!("rCode out of range: {c}");
                        }
                        c as u16
                    }
                };
                rules.push(Rule {
                    action,
                    qtypes,
                    domains: if r["domain"].is_null() {
                        None
                    } else {
                        Some(DomainMatcher::parse(&domains, Kind::Substr, loader)?)
                    },
                    rcode,
                });
            }
            rules
        };
        Ok(Self {
            network,
            address,
            port,
            user_level,
            rules,
        })
    }

    /// applyRules: the first matching rule, else hijack A/AAAA and return everything else.
    fn apply(&self, qtype: u16, domain: &str) -> (Action, u16) {
        let name = domain.to_lowercase();
        let name = name.strip_suffix('.').unwrap_or(&name);
        for r in &self.rules {
            if (r.qtypes.is_empty() || r.qtypes.contains(&qtype))
                && r.domains.as_ref().is_none_or(|m| m.matches(name))
            {
                return (r.action, r.rcode);
            }
        }
        if qtype == TYPE_A || qtype == TYPE_AAAA {
            (Action::Hijack, 0)
        } else {
            (Action::Return, 0)
        }
    }
}

/// parseQuery: the ID, the first question's type and its name (with the trailing dot).
fn parse_query(b: &[u8]) -> Option<(u16, u16, String)> {
    if b.len() < 12 {
        tracing::info!("proxy/dns: parser start > insufficient data for base length type");
        return None;
    }
    let id = u16::from_be_bytes([b[0], b[1]]);
    let question = (|| -> Result<(u16, String)> {
        anyhow::ensure!(u16::from_be_bytes([b[4], b[5]]) > 0, "section done");
        let (name, off) = read_name(b, 12)?;
        let t = b
            .get(off..off + 4)
            .context("insufficient data for base length type")?;
        Ok((u16::from_be_bytes([t[0], t[1]]), name))
    })();
    match question {
        Ok((qtype, name)) => Some((id, qtype, name)),
        Err(e) => {
            tracing::info!("proxy/dns: question > {e}");
            None
        }
    }
}

/// A response with the question and, for a hijack, the answers (names compressed to the
/// question, as dnsmessage.Builder with compression writes them).
fn build_response(
    id: u16,
    rcode: u16,
    qtype: u16,
    domain: &str,
    answers: &[Vec<u8>],
    ttl: u32,
) -> Result<Vec<u8>> {
    let mut m = Vec::with_capacity(64);
    m.extend_from_slice(&id.to_be_bytes());
    // Response, Authoritative, RecursionDesired, RecursionAvailable; RCode ORed in unmasked.
    m.extend_from_slice(&(0x8000u16 | 0x0400 | 0x0100 | 0x0080 | rcode).to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    put_name(&mut m, domain)?;
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    for data in answers {
        if domain == "." {
            m.push(0);
        } else {
            m.extend_from_slice(&[0xc0, 12]);
        }
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&(data.len() as u16).to_be_bytes());
        m.extend_from_slice(data);
    }
    Ok(m)
}

/// handleIPQuery: answers from the DNS module; no reply when the lookup failed without an rcode.
async fn handle_ip_query(
    inst: Arc<Instance>,
    id: u16,
    qtype: u16,
    domain: String,
    down: mpsc::Sender<Vec<u8>>,
    kill: Arc<Notify>,
) {
    let option = IpOption {
        v4: qtype == TYPE_A,
        v6: qtype == TYPE_AAAA,
    };
    let (ips, ttl, err) = match inst.config.dns.lookup_ip(&inst, &domain, option).await {
        Ok((ips, ttl)) => (ips, ttl, None),
        Err(e) => (Vec::new(), 0, Some(e)),
    };
    let rcode = err.as_ref().map_or(0, |e| e.rcode());
    if rcode == 0
        && ips.is_empty()
        && !err
            .as_ref()
            .is_some_and(|e| e.is(&crate::dns::DnsError::Empty))
    {
        match err {
            Some(e) => tracing::info!("proxy/dns: ip query > {e}"),
            None => tracing::info!("proxy/dns: ip query"),
        }
        return;
    }
    let answers: Vec<Vec<u8>> = ips
        .iter()
        .filter_map(|ip| match (qtype, ip) {
            (TYPE_A, std::net::IpAddr::V4(v4)) => Some(v4.octets().to_vec()),
            (TYPE_AAAA, std::net::IpAddr::V4(v4)) => Some(v4.to_ipv6_mapped().octets().to_vec()),
            (TYPE_AAAA, std::net::IpAddr::V6(v6)) => Some(v6.octets().to_vec()),
            _ => None,
        })
        .collect();
    let message = match build_response(id, rcode, qtype, &domain, &answers, ttl) {
        Ok(m) => m,
        Err(e) => {
            tracing::info!("proxy/dns: pack message > {e:#}");
            kill.notify_one();
            return;
        }
    };
    if message.len() > 8192 {
        kill.notify_one();
        tracing::error!("proxy/dns: DNS response message too large");
        return;
    }
    if down.send(message).await.is_err() {
        tracing::info!("proxy/dns: write IP answer > io: read/write on closed pipe");
        kill.notify_one();
    }
}

/// The lazily dialed connection to the (rewritten) DNS server.
enum Upstream {
    Tcp(tokio::net::tcp::OwnedWriteHalf),
    Udp(Arc<tokio::net::UdpSocket>),
}

/// Handler.Process: client messages arrive on `up`, answers go out on `down`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn process(
    inst: &Arc<Instance>,
    outbound: &Outbound,
    cfg: &DnsOutbound,
    sid: Sid,
    own_link: bool,
    src_udp: bool,
    dest: &Address,
    port: u16,
    mut up: mpsc::Receiver<Vec<u8>>,
    down: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let tcp = cfg.network.unwrap_or(!src_udp);
    let address = cfg.address.clone().unwrap_or_else(|| dest.clone());
    let port = if cfg.port != 0 { cfg.port } else { port };
    let net = if tcp { "tcp" } else { "udp" };
    tracing::info!("{sid}proxy/dns: handling DNS traffic to {net}:{address}:{port}");
    let activity = Activity::new(inst.config.policy.level(cfg.user_level).conn_idle);
    let kill = Arc::new(Notify::new());
    let (resp_tx, mut resp_rx) = mpsc::channel::<Vec<u8>>(16);
    let mut upstream: Option<Upstream> = None;
    let request = async {
        while let Some(msg) = up.recv().await {
            activity.touch();
            let direct = if own_link {
                true
            } else {
                let Some((id, qtype, domain)) = parse_query(&msg) else {
                    continue;
                };
                let (action, rcode) = cfg.apply(qtype, &domain);
                match action {
                    Action::Drop => {
                        tracing::info!(
                            "{sid}proxy/dns: blocked type {} query for domain {domain}",
                            type_name(qtype)
                        );
                        false
                    }
                    Action::Return => {
                        tracing::info!(
                            "{sid}proxy/dns: rejected type {} query for domain {domain}",
                            type_name(qtype)
                        );
                        reject(id, qtype, &domain, rcode, &down).await?;
                        false
                    }
                    Action::Hijack if qtype != TYPE_A && qtype != TYPE_AAAA => {
                        tracing::error!("{sid}proxy/dns: can only hijack A/AAAA records");
                        reject(id, qtype, &domain, rcode, &down).await?;
                        false
                    }
                    Action::Hijack => {
                        tokio::spawn(handle_ip_query(
                            inst.clone(),
                            id,
                            qtype,
                            domain,
                            down.clone(),
                            kill.clone(),
                        ));
                        false
                    }
                    Action::Direct => true,
                }
            };
            if !direct {
                continue;
            }
            if upstream.is_none() {
                let dialed = dial(&address, port, tcp, outbound, sid, resp_tx.clone()).await;
                match dialed {
                    Ok(conn) => upstream = Some(conn),
                    Err(e) => {
                        tracing::warn!("proxy/dns: failed to dial outbound connection > {e:#}");
                        return Err(e);
                    }
                }
            }
            match upstream.as_mut().unwrap() {
                Upstream::Tcp(w) => {
                    let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&msg);
                    w.write_all(&framed).await?;
                }
                Upstream::Udp(s) => {
                    s.send(&msg).await?;
                }
            }
        }
        Ok(())
    };
    let response = async {
        while let Some(msg) = resp_rx.recv().await {
            activity.touch();
            if down.send(msg).await.is_err() {
                bail!("io: read/write on closed pipe");
            }
        }
        Ok(())
    };
    let result = tokio::select! {
        result = request => result,
        result = response => result,
        _ = activity.expired() => Ok(()),
        _ = kill.notified() => Ok(()),
    };
    result.context("proxy/dns: connection ends")
}

async fn reject(
    id: u16,
    qtype: u16,
    domain: &str,
    rcode: u16,
    down: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    if domain.trim_end_matches('.').is_empty() {
        bail!("proxy/dns: empty domain name");
    }
    let message = build_response(id, rcode, qtype, domain, &[], 0).map_err(|e| {
        tracing::info!("proxy/dns: unexpected domain {domain} when building reject message: {e}");
        e
    })?;
    if down.send(message).await.is_err() {
        tracing::info!("proxy/dns: write reject answer > io: read/write on closed pipe");
        bail!("io: read/write on closed pipe");
    }
    Ok(())
}

/// The outbound's dialer for the DNS server, with a task forwarding its answers.
async fn dial(
    address: &Address,
    port: u16,
    tcp: bool,
    outbound: &Outbound,
    sid: Sid,
    answers: mpsc::Sender<Vec<u8>>,
) -> Result<Upstream> {
    let addrs = crate::app::resolve(address, port).await?;
    if tcp {
        tracing::info!("{sid}transport/internet/tcp: dialing TCP to tcp:{address}:{port}");
        tracing::debug!("{sid}transport/internet: dialing to tcp:{address}:{port}");
        let stream = crate::app::connect_once(&addrs, &outbound.socket).await?;
        let (mut r, w) = stream.into_split();
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 2];
                if r.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
                if r.read_exact(&mut msg).await.is_err() || answers.send(msg).await.is_err() {
                    return;
                }
            }
        });
        Ok(Upstream::Tcp(w))
    } else {
        tracing::debug!("{sid}transport/internet: dialing to udp:{address}:{port}");
        let addr = *addrs.first().context("failed to resolve destination")?;
        let socket = Arc::new(crate::app::udp_connect(addr, &outbound.socket).await?);
        let reader = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok(n) = reader.recv(&mut buf).await {
                if answers.send(buf[..n].to_vec()).await.is_err() {
                    return;
                }
            }
        });
        Ok(Upstream::Udp(socket))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_and_legacy_policy_match_go() {
        let mut loader = Loader::default();
        let cfg = DnsOutbound::parse(
            &serde_json::json!({"rules": [
                {"action": "drop", "qType": 65},
                {"action": "return", "domain": ["domain:ads.example"], "rCode": 3},
                {"action": "direct", "qType": "16,33"}
            ]}),
            "o",
            &mut loader,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(cfg.apply(65, "x.com."), (Action::Drop, 0));
        assert_eq!(cfg.apply(1, "Tracker.ADS.example."), (Action::Return, 3));
        assert_eq!(cfg.apply(16, "x.com."), (Action::Direct, 0));
        assert_eq!(cfg.apply(28, "x.com."), (Action::Hijack, 0));
        assert_eq!(cfg.apply(15, "x.com."), (Action::Return, 0));
        let legacy = DnsOutbound::parse(
            &serde_json::json!({"nonIPQuery": "skip", "blockTypes": [65]}),
            "o",
            &mut loader,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(legacy.apply(65, "x."), (Action::Drop, 0));
        assert_eq!(legacy.apply(1, "x."), (Action::Hijack, 0));
        assert_eq!(legacy.apply(16, "x."), (Action::Direct, 0));
        let reject = DnsOutbound::parse(
            &serde_json::json!({"nonIPQuery": "reject"}),
            "o",
            &mut loader,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(reject.apply(16, "x."), (Action::Return, 5));
        assert!(
            DnsOutbound::parse(
                &serde_json::json!({"nonIPQuery": "drop", "rules": []}),
                "o",
                &mut loader,
                &mut Vec::new()
            )
            .is_err()
        );
    }

    #[test]
    fn hijack_answer_layout() {
        let m =
            build_response(0x1234, 0, TYPE_A, "Example.com.", &[vec![192, 0, 2, 1]], 60).unwrap();
        assert_eq!(&m[..12], &[0x12, 0x34, 0x85, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        let (name, off) = read_name(&m, 12).unwrap();
        assert_eq!(name, "Example.com.");
        assert_eq!(
            &m[off + 4..],
            &[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]
        );
        let q = parse_query(&m).unwrap();
        assert_eq!(q, (0x1234, TYPE_A, "Example.com.".into()));
    }
}

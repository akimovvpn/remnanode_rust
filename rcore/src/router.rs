//! Port of xray-core app/router: first-match field rules, domain strategies and routing webhooks.
use crate::config::{keys, port_list, string_list, unsupported};
use crate::geodata::{DomainMatcher, IpMatcher, Kind, Loader};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, PartialEq)]
pub enum Strategy {
    AsIs,
    IpIfNonMatch,
    IpOnDemand,
}

/// Routing context for one connection (routing.Context).
pub struct Ctx {
    pub inbound_tag: String,
    pub inbound_name: &'static str,
    pub udp: bool,
    pub source: SocketAddr,
    pub local: SocketAddr,
    pub domain: Option<String>,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub protocol: String,
    pub user: String,
    pub level: u32,
    pub vless_route: u16,
}

fn in_ports(ports: &[(u16, u16)], port: u16) -> bool {
    ports.iter().any(|(a, b)| (*a..=*b).contains(&port))
}

enum UserMatch {
    Exact(String),
    Regex(regex::Regex),
}

#[derive(Default)]
struct Conditions {
    domain: Option<DomainMatcher>,
    ip: Option<IpMatcher>,
    port: Vec<(u16, u16)>,
    network: Option<(bool, bool)>,
    source: Option<IpMatcher>,
    source_port: Vec<(u16, u16)>,
    user: Vec<UserMatch>,
    inbound_tag: Vec<String>,
    protocol: Vec<String>,
    local_ip: Option<IpMatcher>,
    local_port: Vec<(u16, u16)>,
    vless_route: Vec<(u16, u16)>,
}

pub struct Webhook {
    url: String,
    dedup: Duration,
    headers: Vec<(String, String)>,
    seen: Mutex<HashMap<String, Instant>>,
}

pub struct Rule {
    pub outbound: String,
    pub tag: String,
    cond: Conditions,
    webhook: Option<Arc<Webhook>>,
}

pub struct Router {
    strategy: Strategy,
    rules: Vec<Rule>,
}

impl Rule {
    fn applies(&self, ctx: &Ctx, ips: &[IpAddr]) -> bool {
        let c = &self.cond;
        if !c.inbound_tag.is_empty() && !c.inbound_tag.contains(&ctx.inbound_tag) {
            return false;
        }
        if let Some(d) = &c.domain
            && !ctx
                .domain
                .as_deref()
                .is_some_and(|domain| d.matches(domain))
        {
            return false;
        }
        if let Some(m) = &c.ip
            && !ips.iter().any(|ip| m.matches(*ip))
        {
            return false;
        }
        if !c.port.is_empty() && !in_ports(&c.port, ctx.port) {
            return false;
        }
        if let Some((tcp, udp)) = c.network
            && !(if ctx.udp { udp } else { tcp })
        {
            return false;
        }
        if let Some(m) = &c.source
            && !m.matches(ctx.source.ip())
        {
            return false;
        }
        if !c.source_port.is_empty() && !in_ports(&c.source_port, ctx.source.port()) {
            return false;
        }
        if !c.user.is_empty()
            && !c.user.iter().any(|u| match u {
                UserMatch::Exact(e) => *e == ctx.user,
                UserMatch::Regex(r) => r.is_match(&ctx.user),
            })
        {
            return false;
        }
        if !c.protocol.is_empty()
            && !c
                .protocol
                .iter()
                .any(|p| ctx.protocol.starts_with(p.as_str()))
        {
            return false;
        }
        if let Some(m) = &c.local_ip
            && !m.matches(ctx.local.ip())
        {
            return false;
        }
        if !c.local_port.is_empty() && !in_ports(&c.local_port, ctx.local.port()) {
            return false;
        }
        if !c.vless_route.is_empty() && !in_ports(&c.vless_route, ctx.vless_route) {
            return false;
        }
        true
    }
}

impl Router {
    pub fn parse(value: &Value, loader: &mut Loader) -> Result<Self> {
        keys(value, &["domainStrategy", "rules"], "routing")?;
        let strategy = match value["domainStrategy"].as_str().unwrap_or("AsIs") {
            "AsIs" | "" => Strategy::AsIs,
            "IPIfNonMatch" => Strategy::IpIfNonMatch,
            "IPOnDemand" => Strategy::IpOnDemand,
            other => bail!("routing.domainStrategy: unknown {other}"),
        };
        let mut rules = Vec::new();
        for (i, r) in value["rules"].as_array().into_iter().flatten().enumerate() {
            let p = format!("routing.rules[{i}]");
            keys(
                r,
                &[
                    "type",
                    "outboundTag",
                    "ruleTag",
                    "domain",
                    "domains",
                    "ip",
                    "port",
                    "network",
                    "source",
                    "sourceIP",
                    "sourcePort",
                    "user",
                    "inboundTag",
                    "protocol",
                    "localIP",
                    "localPort",
                    "vlessRoute",
                    "webhook",
                ],
                &p,
            )?;
            ensure!(
                r["type"].as_str().is_none_or(|t| t == "field"),
                "{p}.type must be field"
            );
            let list = |k: &str| string_list(&r[k], &format!("{p}.{k}"));
            let mut domains = list("domain")?;
            domains.extend(list("domains")?);
            let ips = list("ip")?;
            let mut sources = list("source")?;
            sources.extend(list("sourceIP")?);
            let local_ips = list("localIP")?;
            let networks = list("network")?;
            for n in &networks {
                ensure!(
                    matches!(n.as_str(), "tcp" | "udp"),
                    "{p}.network: unknown {n}"
                );
            }
            let cond = Conditions {
                domain: if domains.is_empty() {
                    None
                } else {
                    Some(DomainMatcher::parse(&domains, Kind::Substr, loader)?)
                },
                ip: if ips.is_empty() {
                    None
                } else {
                    Some(IpMatcher::parse(&ips, loader)?)
                },
                port: port_list(&r["port"], &format!("{p}.port"))?,
                network: if networks.is_empty() {
                    None
                } else {
                    Some((
                        networks.iter().any(|n| n == "tcp"),
                        networks.iter().any(|n| n == "udp"),
                    ))
                },
                source: if sources.is_empty() {
                    None
                } else {
                    Some(IpMatcher::parse(&sources, loader)?)
                },
                source_port: port_list(&r["sourcePort"], &format!("{p}.sourcePort"))?,
                user: list("user")?
                    .into_iter()
                    .map(|u| match u.strip_prefix("regexp:") {
                        Some(re) => regex::Regex::new(re)
                            .map(UserMatch::Regex)
                            .context("invalid user regexp"),
                        None => Ok(UserMatch::Exact(u)),
                    })
                    .collect::<Result<_>>()?,
                inbound_tag: list("inboundTag")?,
                protocol: list("protocol")?,
                local_ip: if local_ips.is_empty() {
                    None
                } else {
                    Some(IpMatcher::parse(&local_ips, loader)?)
                },
                local_port: port_list(&r["localPort"], &format!("{p}.localPort"))?,
                vless_route: port_list(&r["vlessRoute"], &format!("{p}.vlessRoute"))?,
            };
            let webhook = match &r["webhook"] {
                Value::Null => None,
                w => {
                    keys(
                        w,
                        &["url", "deduplication", "headers"],
                        &format!("{p}.webhook"),
                    )?;
                    let url = w["url"]
                        .as_str()
                        .context("webhook.url is required")?
                        .to_owned();
                    ensure!(
                        url.starts_with('/') || url.starts_with("http://"),
                        "{}",
                        unsupported(&format!(
                            "{p}.webhook.url {url} (only unix sockets and http://)"
                        ))
                    );
                    Some(Arc::new(Webhook {
                        url,
                        dedup: Duration::from_secs(w["deduplication"].as_u64().unwrap_or(0)),
                        headers: w["headers"]
                            .as_object()
                            .into_iter()
                            .flatten()
                            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
                            .collect(),
                        seen: Mutex::default(),
                    }))
                }
            };
            rules.push(Rule {
                outbound: r["outboundTag"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| unsupported(&format!("{p} without outboundTag (balancers)")))?,
                tag: r["ruleTag"].as_str().unwrap_or_default().to_owned(),
                cond,
                webhook,
            });
        }
        Ok(Self { strategy, rules })
    }

    /// True when a rule sends all of `inbound`'s traffic to `outbound` (the API pattern).
    pub fn routes_inbound_to(&self, inbound: &str, outbound: &str) -> bool {
        self.rules
            .iter()
            .any(|r| r.outbound == outbound && r.cond.inbound_tag.iter().any(|t| t == inbound))
    }

    async fn resolve(domain: &str, port: u16) -> Vec<IpAddr> {
        tokio::net::lookup_host((domain, port))
            .await
            .map(|a| a.map(|s| s.ip()).collect())
            .unwrap_or_default()
    }

    /// PickRoute: returns the outbound tag of the first matching rule, firing its webhook.
    pub async fn pick(&self, ctx: &Ctx) -> Option<&Rule> {
        let mut ips: Vec<IpAddr> = ctx.ip.into_iter().collect();
        if ips.is_empty()
            && self.strategy == Strategy::IpOnDemand
            && let Some(d) = &ctx.domain
        {
            ips = Self::resolve(d, ctx.port).await;
        }
        let mut hit = self.rules.iter().find(|r| r.applies(ctx, &ips));
        if hit.is_none()
            && self.strategy == Strategy::IpIfNonMatch
            && ctx.ip.is_none()
            && let Some(d) = &ctx.domain
        {
            ips = Self::resolve(d, ctx.port).await;
            hit = self.rules.iter().find(|r| r.applies(ctx, &ips));
        }
        if let Some(rule) = hit
            && let Some(hook) = &rule.webhook
        {
            hook.fire(ctx, &rule.outbound);
        }
        hit
    }
}

impl Webhook {
    fn fire(self: &Arc<Self>, ctx: &Ctx, outbound: &str) {
        {
            let mut seen = self.seen.lock().unwrap();
            let now = Instant::now();
            if self.dedup > Duration::ZERO {
                seen.retain(|_, at| now.duration_since(*at) < self.dedup);
                if seen.contains_key(&ctx.user) {
                    return;
                }
                seen.insert(ctx.user.clone(), now);
            }
        }
        let host = |ip: IpAddr, port: u16| SocketAddr::new(ip, port).to_string();
        let destination = match (&ctx.domain, ctx.ip) {
            (Some(d), _) => Some(format!("{d}:{}", ctx.port)),
            (None, Some(ip)) => Some(host(ip, ctx.port)),
            _ => None,
        };
        let event = json!({
            "email": (!ctx.user.is_empty()).then(|| ctx.user.clone()),
            "level": (!ctx.user.is_empty()).then_some(ctx.level),
            "protocol": ctx.protocol,
            "network": if ctx.udp { "udp" } else { "tcp" },
            "source": host(ctx.source.ip().to_canonical(), ctx.source.port()),
            "destination": destination,
            "originalTarget": null,
            "routeTarget": null,
            "inboundTag": ctx.inbound_tag,
            "inboundName": ctx.inbound_name,
            "inboundLocal": host(ctx.local.ip().to_canonical(), ctx.local.port()),
            "outboundTag": outbound,
            "ts": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default(),
        });
        let hook = self.clone();
        tokio::spawn(async move {
            if let Err(error) = hook.post(event.to_string()).await {
                tracing::warn!(%error, "routing webhook failed");
            }
        });
    }

    async fn post(&self, body: String) -> Result<()> {
        use http_body_util::Full;
        use hyper_util::rt::TokioIo;
        // utils.SplitHTTPUnixURL: "/path/to.sock:/http/path" or a plain http:// URL.
        let (authority, path, socket) = if let Some(rest) = self.url.strip_prefix("http://") {
            let (authority, path) = rest
                .split_once('/')
                .map(|(a, p)| (a, format!("/{p}")))
                .unwrap_or((rest, "/".into()));
            (authority.to_owned(), path, None)
        } else {
            let (socket, path) = self
                .url
                .split_once(":/")
                .map(|(s, p)| (s, format!("/{p}")))
                .unwrap_or((self.url.as_str(), "/".into()));
            ("localhost".to_owned(), path, Some(socket.to_owned()))
        };
        let mut request = http::Request::post(path)
            .header("host", &authority)
            .header("content-type", "application/json");
        for (k, v) in &self.headers {
            request = request.header(k, v);
        }
        let request = request.body(Full::new(bytes_of(body)))?;
        let send = async {
            let response = match socket {
                Some(socket) => {
                    let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(
                        tokio::net::UnixStream::connect(socket).await?,
                    ))
                    .await?;
                    tokio::spawn(conn);
                    tx.send_request(request).await?
                }
                None => {
                    let addr = if authority.contains(':') {
                        authority.clone()
                    } else {
                        format!("{authority}:80")
                    };
                    let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(
                        tokio::net::TcpStream::connect(addr).await?,
                    ))
                    .await?;
                    tokio::spawn(conn);
                    tx.send_request(request).await?
                }
            };
            ensure!(
                response.status().is_success(),
                "webhook returned {}",
                response.status()
            );
            anyhow::Ok(())
        };
        tokio::time::timeout(Duration::from_secs(5), send)
            .await
            .context("webhook timed out")?
    }
}

fn bytes_of(body: String) -> hyper::body::Bytes {
    hyper::body::Bytes::from(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ctx(domain: Option<&str>, ip: Option<&str>, protocol: &str) -> Ctx {
        Ctx {
            inbound_tag: "in".into(),
            inbound_name: "vless",
            udp: false,
            source: "1.2.3.4:5000".parse().unwrap(),
            local: "10.0.0.1:443".parse().unwrap(),
            domain: domain.map(str::to_owned),
            ip: ip.map(|i| i.parse().unwrap()),
            port: 443,
            protocol: protocol.into(),
            user: "alice".into(),
            level: 0,
            vless_route: 0,
        }
    }
    #[tokio::test]
    async fn first_matching_rule_wins() {
        let router = Router::parse(
            &json!({"rules":[
                {"protocol":["bittorrent"],"outboundTag":"block"},
                {"domain":["domain:example.com"],"port":"443","outboundTag":"a"},
                {"ip":["10.0.0.0/8"],"user":["regexp:^al"],"outboundTag":"b"},
                {"inboundTag":["in"],"network":"udp","outboundTag":"c"}
            ]}),
            &mut Loader::default(),
        )
        .unwrap();
        let router = &router;
        let pick = |c: Ctx| async move { router.pick(&c).await.map(|r| r.outbound.clone()) };
        assert_eq!(
            pick(ctx(None, Some("8.8.8.8"), "bittorrent"))
                .await
                .as_deref(),
            Some("block")
        );
        assert_eq!(
            pick(ctx(Some("www.example.com"), None, "tls"))
                .await
                .as_deref(),
            Some("a")
        );
        assert_eq!(
            pick(ctx(None, Some("10.1.1.1"), "")).await.as_deref(),
            Some("b")
        );
        assert_eq!(pick(ctx(None, Some("8.8.8.8"), "")).await, None);
        assert!(
            Router::parse(
                &json!({"rules":[{"balancerTag":"x"}]}),
                &mut Loader::default()
            )
            .is_err()
        );
    }
}

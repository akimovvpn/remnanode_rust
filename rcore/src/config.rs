//! Xray JSON config subset (infra/conf). Anything not ported fails validation by name.
use crate::geodata::{IpMatcher, Kind, Loader};
use crate::router::Router;
use crate::transport::Transport;
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{collections::HashMap, net::IpAddr, time::Duration};

pub const VERSION: &str = "26.11.9";

pub fn unsupported(path: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "rcore does not support `{path}` yet (Xray-core v{VERSION} subset); use the Go Xray binary for this config"
    )
}

/// Rejects keys outside `allowed` so unported features never run silently.
pub fn keys(value: &Value, allowed: &[&str], path: &str) -> Result<()> {
    let Some(object) = value.as_object() else {
        ensure!(value.is_null(), "{path} must be an object");
        return Ok(());
    };
    for (key, v) in object {
        if !allowed.contains(&key.as_str()) && !v.is_null() {
            return Err(unsupported(&format!("{path}.{key}")));
        }
    }
    Ok(())
}

/// Xray StringList: an array of strings or one comma-separated string.
pub fn string_list(value: &Value, path: &str) -> Result<Vec<String>> {
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(s) => Ok(s
            .split(',')
            .map(|x| x.trim().to_owned())
            .filter(|x| !x.is_empty())
            .collect()),
        Value::Array(items) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .with_context(|| format!("{path} must contain strings"))
            })
            .collect(),
        _ => bail!("{path} must be a string or an array"),
    }
}

/// Xray PortList: number, "a-b,c" string, or array of those. Returns inclusive ranges.
pub fn port_list(value: &Value, path: &str) -> Result<Vec<(u16, u16)>> {
    let one = |s: &str| -> Result<(u16, u16)> {
        let s = s.trim();
        let (a, b) = s.split_once('-').unwrap_or((s, s));
        let (a, b): (u16, u16) = (
            a.trim()
                .parse()
                .with_context(|| format!("invalid port in {path}"))?,
            b.trim()
                .parse()
                .with_context(|| format!("invalid port in {path}"))?,
        );
        ensure!(a <= b, "invalid port range in {path}");
        Ok((a, b))
    };
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Number(n) => {
            let p = n
                .as_u64()
                .filter(|p| *p <= 65535)
                .with_context(|| format!("invalid port in {path}"))? as u16;
            Ok(vec![(p, p)])
        }
        Value::String(s) => s
            .split(',')
            .filter(|x| !x.trim().is_empty())
            .map(one)
            .collect(),
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                out.extend(port_list(item, path)?);
            }
            Ok(out)
        }
        _ => bail!("{path} must be a port list"),
    }
}

fn seconds(value: &Value, default: u64) -> Result<Duration> {
    Ok(Duration::from_secs(match value {
        Value::Null => default,
        v => v
            .as_u64()
            .context("policy timeouts must be whole seconds")?,
    }))
}

#[derive(Clone)]
pub struct LevelPolicy {
    pub handshake: Duration,
    pub conn_idle: Duration,
    pub uplink_only: Duration,
    pub downlink_only: Duration,
    pub user_uplink: bool,
    pub user_downlink: bool,
    pub user_online: bool,
}

impl Default for LevelPolicy {
    // features/policy SessionDefault
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(60),
            conn_idle: Duration::from_secs(300),
            uplink_only: Duration::from_secs(1),
            downlink_only: Duration::from_secs(1),
            user_uplink: false,
            user_downlink: false,
            user_online: false,
        }
    }
}

#[derive(Default)]
pub struct Policy {
    levels: HashMap<u32, LevelPolicy>,
    pub inbound_uplink: bool,
    pub inbound_downlink: bool,
    pub outbound_uplink: bool,
    pub outbound_downlink: bool,
}

impl Policy {
    pub fn level(&self, level: u32) -> LevelPolicy {
        self.levels.get(&level).cloned().unwrap_or_default()
    }
    fn parse(value: &Value) -> Result<Self> {
        keys(value, &["levels", "system"], "policy")?;
        let mut policy = Self::default();
        if let Some(levels) = value.get("levels").and_then(Value::as_object) {
            for (level, v) in levels {
                let p = format!("policy.levels.{level}");
                keys(
                    v,
                    &[
                        "handshake",
                        "connIdle",
                        "uplinkOnly",
                        "downlinkOnly",
                        "statsUserUplink",
                        "statsUserDownlink",
                        "statsUserOnline",
                        "bufferSize",
                    ],
                    &p,
                )?;
                let d = LevelPolicy::default();
                let flag = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
                policy.levels.insert(
                    level
                        .parse()
                        .with_context(|| format!("{p}: level must be a number"))?,
                    LevelPolicy {
                        handshake: seconds(&v["handshake"], d.handshake.as_secs())?,
                        conn_idle: seconds(&v["connIdle"], d.conn_idle.as_secs())?,
                        uplink_only: seconds(&v["uplinkOnly"], d.uplink_only.as_secs())?,
                        downlink_only: seconds(&v["downlinkOnly"], d.downlink_only.as_secs())?,
                        user_uplink: flag("statsUserUplink"),
                        user_downlink: flag("statsUserDownlink"),
                        user_online: flag("statsUserOnline"),
                    },
                );
            }
        }
        let system = &value["system"];
        keys(
            system,
            &[
                "statsInboundUplink",
                "statsInboundDownlink",
                "statsOutboundUplink",
                "statsOutboundDownlink",
            ],
            "policy.system",
        )?;
        let flag = |k: &str| system.get(k).and_then(Value::as_bool).unwrap_or(false);
        policy.inbound_uplink = flag("statsInboundUplink");
        policy.inbound_downlink = flag("statsInboundDownlink");
        policy.outbound_uplink = flag("statsOutboundUplink");
        policy.outbound_downlink = flag("statsOutboundDownlink");
        Ok(policy)
    }
}

#[derive(Clone)]
pub struct User {
    pub email: String,
    pub level: u32,
    pub id: [u8; 16],
    pub flow: String,
}

/// common/uuid ParseString: canonical UUIDs, or 1-30 char strings mapped through UUIDv5(SHA-1).
pub fn parse_uuid(text: &str) -> Result<[u8; 16]> {
    let mut id = [0u8; 16];
    if !(32..=36).contains(&text.len()) {
        ensure!(!text.is_empty() && text.len() <= 30, "invalid UUID: {text}");
        use sha1::Digest;
        let hash = sha1::Sha1::new()
            .chain_update([0u8; 16])
            .chain_update(text.as_bytes())
            .finalize();
        id.copy_from_slice(&hash[..16]);
        id[6] = (id[6] & 0x0f) | (5 << 4);
        id[8] = (id[8] & (0xff >> 2)) | (0x02 << 6);
        return Ok(id);
    }
    let mut rest = text.as_bytes();
    let mut at = 0;
    for group in [4usize, 2, 2, 2, 6] {
        if rest.first() == Some(&b'-') {
            rest = &rest[1..];
        }
        ensure!(rest.len() >= group * 2, "invalid UUID: {text}");
        for i in 0..group {
            let hex = std::str::from_utf8(&rest[i * 2..i * 2 + 2]).ok();
            id[at] = hex
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .with_context(|| format!("invalid UUID: {text}"))?;
            at += 1;
        }
        rest = &rest[group * 2..];
    }
    ensure!(rest.is_empty(), "invalid UUID: {text}");
    Ok(id)
}

fn parse_flow<'a>(value: &'a Value, path: &str) -> Result<&'a str> {
    let flow = match value {
        Value::Null => "",
        Value::String(flow) => flow,
        _ => bail!("{path} must be a string"),
    };
    ensure!(
        flow.is_empty() || flow == "xtls-rprx-vision",
        "{path}: unknown flow {flow}"
    );
    Ok(flow)
}

pub fn parse_user(v: &Value, path: &str) -> Result<User> {
    keys(v, &["id", "email", "level", "flow", "encryption"], path)?;
    let flow = parse_flow(&v["flow"], &format!("{path}.flow"))?.to_owned();
    Ok(User {
        email: v["email"].as_str().unwrap_or_default().to_owned(),
        level: v["level"].as_u64().unwrap_or(0) as u32,
        id: parse_uuid(
            v["id"]
                .as_str()
                .with_context(|| format!("{path}.id is required"))?,
        )?,
        flow,
    })
}

pub struct Sniffing {
    pub enabled: bool,
    pub dest_override: Vec<String>,
    pub domains_excluded: crate::geodata::DomainMatcher,
    pub metadata_only: bool,
    pub route_only: bool,
}

pub enum InboundKind {
    Vless(Vec<User>),
    /// dokodemo-door routed to the api tag: served as the gRPC API listener.
    Api,
}

pub struct Inbound {
    pub tag: String,
    pub listen: IpAddr,
    pub port: u16,
    pub kind: InboundKind,
    pub sniffing: Sniffing,
    pub transport: Transport,
    /// sockopt.trustedXForwardedFor header names.
    pub trusted_xff: Vec<String>,
    pub reality: Option<std::sync::Arc<crate::reality::Config>>,
}

/// REALITYConfig.Build (infra/conf/transport_internet.go), server side.
fn parse_reality(v: &Value, path: &str) -> Result<crate::reality::Config> {
    keys(
        v,
        &[
            "show",
            "target",
            "dest",
            "type",
            "xver",
            "serverNames",
            "privateKey",
            "minClientVer",
            "maxClientVer",
            "maxTimeDiff",
            "shortIds",
            "mldsa65Seed",
            "limitFallbackUpload",
            "limitFallbackDownload",
            "masterKeyLog",
            // Client-side fields are ignored by a server, as in Xray.
            "fingerprint",
            "serverName",
            "password",
            "publicKey",
            "shortId",
            "mldsa65Verify",
            "spiderX",
        ],
        path,
    )?;
    ensure!(
        v.get("show").is_none_or(|x| x.is_null() || x.is_boolean()),
        "{path}.show must be a boolean"
    );
    for field in ["xver", "maxTimeDiff"] {
        ensure!(
            v.get(field)
                .is_none_or(|x| x.is_null() || x.as_u64().is_some()),
            "{path}.{field} must be an unsigned integer"
        );
    }
    for field in [
        "type",
        "minClientVer",
        "maxClientVer",
        "mldsa65Seed",
        "masterKeyLog",
    ] {
        ensure!(
            v.get(field).is_none_or(|x| x.is_null() || x.is_string()),
            "{path}.{field} must be a string"
        );
    }
    let dest = match v
        .get("target")
        .filter(|t| !t.is_null())
        .or_else(|| v.get("dest"))
    {
        Some(Value::Number(n)) if n.as_u64().is_some_and(|p| p > 0 && p <= 65535) => {
            format!("localhost:{n}")
        }
        Some(Value::String(s)) if s.starts_with('/') || s.starts_with('@') => {
            return Err(unsupported(&format!("{path}.target unix socket")));
        }
        Some(Value::String(s)) if s.parse::<u16>().is_ok() => format!("localhost:{s}"),
        Some(Value::String(s))
            if s.rsplit_once(':')
                .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok()) =>
        {
            s.clone()
        }
        _ => bail!("{path}: please fill in a valid value for \"target\""),
    };
    ensure!(
        v["type"]
            .as_str()
            .is_none_or(|t| t.is_empty() || t == "tcp"),
        "{}",
        unsupported(&format!("{path}.type"))
    );
    let xver = v["xver"].as_u64().unwrap_or(0);
    ensure!(
        xver <= 2,
        "{path}: invalid PROXY protocol version, \"xver\" only accepts 0, 1, 2"
    );
    ensure!(
        xver == 0,
        "{}",
        unsupported(&format!("{path}.xver (PROXY protocol to the target)"))
    );
    let server_names: Vec<String> = string_list(&v["serverNames"], &format!("{path}.serverNames"))?;
    ensure!(!server_names.is_empty(), "{path}: empty \"serverNames\"");
    let key = v["privateKey"].as_str().unwrap_or_default();
    ensure!(!key.is_empty(), "{path}: empty \"privateKey\"");
    use base64::Engine;
    let private_key: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key)
        .ok()
        .and_then(|k| k.try_into().ok())
        .with_context(|| format!("{path}: invalid \"privateKey\""))?;
    let version = |field: &str| -> Result<Option<[u8; 3]>> {
        let Some(text) = v[field].as_str().filter(|t| !t.is_empty()) else {
            return Ok(None);
        };
        let mut out = [0u8; 3];
        for (i, part) in text.split('.').enumerate() {
            ensure!(i < 3, "{path}: invalid \"{field}\": {text}");
            out[i] = part
                .parse()
                .with_context(|| format!("{path}: \"{field}[{i}]\" should be less than 256"))?;
        }
        Ok(Some(out))
    };
    let short_ids = string_list(&v["shortIds"], &format!("{path}.shortIds"))?;
    ensure!(
        !short_ids.is_empty() || v["shortIds"].as_array().is_some_and(|a| !a.is_empty()),
        "{path}: empty \"shortIds\""
    );
    let raw_ids: Vec<String> = match &v["shortIds"] {
        Value::Array(items) => items
            .iter()
            .map(|i| i.as_str().unwrap_or_default().to_owned())
            .collect(),
        _ => short_ids,
    };
    let mut ids = std::collections::HashSet::new();
    for (i, id) in raw_ids.iter().enumerate() {
        ensure!(id.len() <= 16, "{path}: too long \"shortIds[{i}]\": {id}");
        ensure!(
            id.len() % 2 == 0 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "{path}: invalid \"shortIds[{i}]\": {id}"
        );
        let mut out = [0u8; 8];
        for (j, chunk) in id.as_bytes().chunks(2).enumerate() {
            out[j] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
        }
        ids.insert(out);
    }
    ensure!(
        v["mldsa65Seed"].as_str().unwrap_or_default().is_empty(),
        "{}",
        unsupported(&format!("{path}.mldsa65Seed"))
    );
    ensure!(
        v["masterKeyLog"].as_str().unwrap_or_default().is_empty(),
        "{}",
        unsupported(&format!("{path}.masterKeyLog"))
    );
    for limit in ["limitFallbackUpload", "limitFallbackDownload"] {
        keys(
            &v[limit],
            &["afterBytes", "bytesPerSec", "burstBytesPerSec"],
            &format!("{path}.{limit}"),
        )?;
        if let Some(values) = v[limit].as_object() {
            ensure!(
                values.values().all(|x| x.as_u64().is_some()),
                "{path}.{limit} values must be unsigned integers"
            );
        }
        let active = v[limit]
            .as_object()
            .is_some_and(|o| o.values().any(|x| x.as_u64().unwrap_or(0) != 0));
        ensure!(!active, "{}", unsupported(&format!("{path}.{limit}")));
    }
    Ok(crate::reality::Config {
        dest,
        server_names: server_names.into_iter().collect(),
        private_key,
        short_ids: ids,
        min_client_ver: version("minClientVer")?,
        max_client_ver: version("maxClientVer")?,
        max_time_diff: std::time::Duration::from_millis(v["maxTimeDiff"].as_u64().unwrap_or(0)),
        show: v["show"] == true,
        profiles: Default::default(),
    })
}

/// wsSettings / httpupgradeSettings (infra/conf transport_method.go).
fn http_transport(settings: &Value, websocket: bool, path: &str) -> Result<(String, String)> {
    let allowed: &[&str] = if websocket {
        &[
            "path",
            "host",
            "headers",
            "acceptProxyProtocol",
            "heartbeatPeriod",
        ]
    } else {
        &["path", "host", "headers", "acceptProxyProtocol"]
    };
    keys(settings, allowed, path)?;
    ensure!(
        settings["acceptProxyProtocol"] != true,
        "{}",
        unsupported(&format!("{path}.acceptProxyProtocol"))
    );
    let mut host = settings["host"].as_str().unwrap_or_default().to_owned();
    for (k, v) in settings["headers"].as_object().into_iter().flatten() {
        if k.eq_ignore_ascii_case("host") {
            ensure!(websocket, "{path}: \"headers\" can't contain \"host\"");
            if host.is_empty() {
                host = v.as_str().unwrap_or_default().to_owned();
            }
        }
    }
    Ok((
        crate::transport::normalize_path(settings["path"].as_str().unwrap_or_default()),
        host,
    ))
}

pub struct FinalRule {
    pub block: bool,
    pub tcp: bool,
    pub udp: bool,
    pub ports: Vec<(u16, u16)>,
    pub ips: Option<IpMatcher>,
    pub delay: (u64, u64),
}

pub enum OutboundKind {
    Freedom {
        final_rules: Vec<FinalRule>,
        strategy: String,
    },
    Blackhole {
        http: bool,
    },
    Socks(crate::socks::Server),
}

pub struct Outbound {
    pub tag: String,
    pub kind: OutboundKind,
    pub socket: crate::socket::Options,
}

pub struct Config {
    pub stats: bool,
    pub policy: Policy,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub router: Router,
    pub log_level: String,
    pub access_log: Option<String>,
    pub error_log: Option<String>,
}

fn port(value: &Value, path: &str) -> Result<u16> {
    match port_list(value, path)?.as_slice() {
        [(a, b)] if a == b && *a != 0 => Ok(*a),
        _ => Err(unsupported(&format!("{path} (port ranges/zero)"))),
    }
}

fn parse_final_rule(v: &Value, i: usize, loader: &mut Loader) -> Result<FinalRule> {
    let p = format!("outbounds[].settings.finalRules[{i}]");
    keys(
        v,
        &[
            "action",
            "network",
            "port",
            "ip",
            "delay",
            "blockDelay",
            "logLevel",
        ],
        &p,
    )?;
    let block = match v["action"].as_str() {
        Some("allow") => false,
        Some("block") => true,
        other => bail!("{p}.action must be allow or block, got {other:?}"),
    };
    let networks = string_list(&v["network"], &format!("{p}.network"))?;
    let delay = match &v
        .get("blockDelay")
        .or_else(|| v.get("delay"))
        .cloned()
        .unwrap_or(Value::Null)
    {
        Value::Null => (30, 90),
        Value::Number(n) => {
            let n = n.as_u64().context("delay must be a whole number")?;
            (n, n)
        }
        Value::String(s) => {
            let (a, b) = s.split_once('-').unwrap_or((s, s));
            (a.trim().parse()?, b.trim().parse()?)
        }
        _ => bail!("{p}.delay must be a number or range"),
    };
    let ips = string_list(&v["ip"], &format!("{p}.ip"))?;
    Ok(FinalRule {
        block,
        tcp: networks.is_empty() || networks.iter().any(|n| n == "tcp"),
        udp: networks.is_empty() || networks.iter().any(|n| n == "udp"),
        ports: port_list(&v["port"], &format!("{p}.port"))?,
        ips: if ips.is_empty() {
            None
        } else {
            Some(IpMatcher::parse(&ips, loader)?)
        },
        delay,
    })
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let root: Value = serde_json::from_str(text).context("invalid JSON config")?;
        keys(
            &root,
            &[
                "log",
                "api",
                "stats",
                "policy",
                "inbounds",
                "outbounds",
                "routing",
            ],
            "",
        )?;
        let log = &root["log"];
        keys(
            log,
            &["loglevel", "access", "error", "dnsLog", "maskAddress"],
            "log",
        )?;
        let mut loader = Loader::default();
        let api = match &root["api"] {
            Value::Null => None,
            api => {
                keys(api, &["tag", "services"], "api")?;
                for service in string_list(&api["services"], "api.services")? {
                    ensure!(
                        matches!(
                            service.as_str(),
                            "HandlerService" | "StatsService" | "RoutingService" | "LoggerService"
                        ),
                        "{}",
                        unsupported(&format!("api.services {service}"))
                    );
                }
                Some(
                    api["tag"]
                        .as_str()
                        .context("api.tag is required")?
                        .to_owned(),
                )
            }
        };
        let router = Router::parse(&root["routing"], &mut loader)?;
        let mut inbounds = Vec::new();
        for (i, v) in root["inbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let p = format!("inbounds[{i}]");
            keys(
                v,
                &[
                    "tag",
                    "listen",
                    "port",
                    "protocol",
                    "settings",
                    "streamSettings",
                    "sniffing",
                ],
                &p,
            )?;
            let tag = v["tag"].as_str().unwrap_or_default().to_owned();
            let listen: IpAddr = match v["listen"].as_str() {
                None | Some("") => "0.0.0.0".parse()?,
                Some(ip) => ip
                    .parse()
                    .map_err(|_| unsupported(&format!("{p}.listen {ip} (unix sockets)")))?,
            };
            let stream = &v["streamSettings"];
            keys(
                stream,
                &[
                    "network",
                    "security",
                    "tcpSettings",
                    "rawSettings",
                    "wsSettings",
                    "httpupgradeSettings",
                    "realitySettings",
                    "sockopt",
                ],
                &format!("{p}.streamSettings"),
            )?;
            let transport = match stream["network"].as_str().unwrap_or("raw") {
                "raw" | "tcp" => Transport::Raw,
                "ws" | "websocket" => {
                    let (path, host) = http_transport(
                        &stream["wsSettings"],
                        true,
                        &format!("{p}.streamSettings.wsSettings"),
                    )?;
                    let heartbeat = stream["wsSettings"]["heartbeatPeriod"]
                        .as_u64()
                        .unwrap_or(0) as u32;
                    Transport::Ws {
                        path,
                        host,
                        heartbeat,
                    }
                }
                "httpupgrade" => {
                    let (path, host) = http_transport(
                        &stream["httpupgradeSettings"],
                        false,
                        &format!("{p}.streamSettings.httpupgradeSettings"),
                    )?;
                    Transport::HttpUpgrade { path, host }
                }
                other => return Err(unsupported(&format!("{p}.streamSettings.network {other}"))),
            };
            let reality = match stream["security"].as_str().unwrap_or("none") {
                "none" | "" => None,
                "reality" => {
                    ensure!(
                        matches!(transport, Transport::Raw),
                        "{}",
                        unsupported(&format!("{p}.streamSettings: REALITY over this network"))
                    );
                    Some(std::sync::Arc::new(parse_reality(
                        &stream["realitySettings"],
                        &format!("{p}.streamSettings.realitySettings"),
                    )?))
                }
                other => return Err(unsupported(&format!("{p}.streamSettings.security {other}"))),
            };
            for raw in ["tcpSettings", "rawSettings"] {
                keys(
                    &stream[raw],
                    &["header", "acceptProxyProtocol"],
                    &format!("{p}.streamSettings.{raw}"),
                )?;
                ensure!(
                    stream[raw]["acceptProxyProtocol"] != true,
                    "{}",
                    unsupported(&format!("{p}.streamSettings.{raw}.acceptProxyProtocol"))
                );
                let header = stream[raw]["header"]["type"].as_str().unwrap_or("none");
                ensure!(
                    header == "none",
                    "{}",
                    unsupported(&format!("{p}.streamSettings.{raw}.header {header}"))
                );
            }
            keys(
                &stream["sockopt"],
                &["trustedXForwardedFor"],
                &format!("{p}.streamSettings.sockopt"),
            )?;
            let trusted_xff = string_list(
                &stream["sockopt"]["trustedXForwardedFor"],
                &format!("{p}.streamSettings.sockopt.trustedXForwardedFor"),
            )?;
            let sniff = &v["sniffing"];
            keys(
                sniff,
                &[
                    "enabled",
                    "destOverride",
                    "domainsExcluded",
                    "metadataOnly",
                    "routeOnly",
                ],
                &format!("{p}.sniffing"),
            )?;
            let dest_override = string_list(&sniff["destOverride"], "sniffing.destOverride")?;
            for d in &dest_override {
                ensure!(
                    matches!(d.as_str(), "http" | "tls" | "quic" | "fakedns"),
                    "{p}.sniffing.destOverride: unknown protocol {d}"
                );
            }
            ensure!(
                !dest_override.iter().any(|d| d == "fakedns"),
                "{}",
                unsupported(&format!("{p}.sniffing.destOverride fakedns"))
            );
            let sniffing = Sniffing {
                enabled: sniff["enabled"] == true,
                dest_override,
                domains_excluded: crate::geodata::DomainMatcher::parse(
                    &string_list(&sniff["domainsExcluded"], "sniffing.domainsExcluded")?,
                    Kind::Substr,
                    &mut loader,
                )?,
                metadata_only: sniff["metadataOnly"] == true,
                route_only: sniff["routeOnly"] == true,
            };
            let settings = &v["settings"];
            let kind = match v["protocol"].as_str() {
                Some("vless") => {
                    keys(
                        settings,
                        &["clients", "decryption", "fallbacks", "flow"],
                        &format!("{p}.settings"),
                    )?;
                    ensure!(
                        settings["decryption"] == "none",
                        "{}",
                        unsupported(&format!("{p}.settings.decryption (only \"none\")"))
                    );
                    ensure!(
                        settings["fallbacks"].as_array().is_none_or(Vec::is_empty),
                        "{}",
                        unsupported(&format!("{p}.settings.fallbacks"))
                    );
                    let default_flow =
                        parse_flow(&settings["flow"], &format!("{p}.settings.flow"))?;
                    let clients = settings["clients"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .enumerate();
                    InboundKind::Vless(
                        clients
                            .map(|(j, c)| {
                                let mut user =
                                    parse_user(c, &format!("{p}.settings.clients[{j}]"))?;
                                if user.flow.is_empty() {
                                    user.flow = default_flow.to_owned();
                                }
                                Ok(user)
                            })
                            .collect::<Result<_>>()?,
                    )
                }
                Some("dokodemo-door" | "tunnel")
                    if api
                        .as_deref()
                        .is_some_and(|api| router.routes_inbound_to(&tag, api)) =>
                {
                    InboundKind::Api
                }
                Some(other) => return Err(unsupported(&format!("{p}.protocol {other}"))),
                None => bail!("{p}.protocol is required"),
            };
            inbounds.push(Inbound {
                tag,
                listen,
                port: port(&v["port"], &format!("{p}.port"))?,
                kind,
                sniffing,
                transport,
                trusted_xff,
                reality,
            });
        }
        let mut outbounds = Vec::new();
        for (i, v) in root["outbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let p = format!("outbounds[{i}]");
            keys(v, &["tag", "protocol", "settings", "streamSettings"], &p)?;
            let stream = &v["streamSettings"];
            keys(
                stream,
                &["network", "security", "sockopt"],
                &format!("{p}.streamSettings"),
            )?;
            for field in ["network", "security"] {
                ensure!(
                    stream[field].is_null() || stream[field].is_string(),
                    "{p}.streamSettings.{field} must be a string"
                );
            }
            ensure!(
                stream["network"]
                    .as_str()
                    .is_none_or(|n| matches!(n, "" | "raw" | "tcp")),
                "{}",
                unsupported(&format!("{p}.streamSettings.network"))
            );
            ensure!(
                stream["security"]
                    .as_str()
                    .is_none_or(|s| matches!(s, "" | "none")),
                "{}",
                unsupported(&format!("{p}.streamSettings.security"))
            );
            let sockopt = &stream["sockopt"];
            let sp = format!("{p}.streamSettings.sockopt");
            keys(sockopt, &["interface", "tcpFastOpen"], &sp)?;
            let interface = match &sockopt["interface"] {
                Value::Null => String::new(),
                Value::String(s) => s.clone(),
                _ => bail!("{sp}.interface must be a string"),
            };
            ensure!(
                !interface.contains('\0') && interface.len() < 16,
                "{sp}.interface must be shorter than 16 bytes without NUL"
            );
            let tcp_fast_open = match &sockopt["tcpFastOpen"] {
                Value::Null => None,
                Value::Bool(b) => Some(*b),
                Value::Number(n) => n
                    .as_i64()
                    .map(|i| if i < 0 { None } else { Some(i > 0) })
                    .with_context(|| format!("{sp}.tcpFastOpen must be an integer"))?,
                _ => bail!("{sp}.tcpFastOpen must be a boolean or integer"),
            };
            let socket = crate::socket::Options {
                interface,
                tcp_fast_open,
            };
            let settings = &v["settings"];
            let kind = match v["protocol"].as_str() {
                Some("freedom") => {
                    keys(
                        settings,
                        &["domainStrategy", "finalRules", "userLevel"],
                        &format!("{p}.settings"),
                    )?;
                    let strategy = settings["domainStrategy"]
                        .as_str()
                        .unwrap_or("AsIs")
                        .to_owned();
                    ensure!(
                        matches!(
                            strategy.as_str(),
                            "AsIs"
                                | "UseIP"
                                | "UseIPv4"
                                | "UseIPv6"
                                | "UseIPv4v6"
                                | "UseIPv6v4"
                                | "ForceIP"
                                | "ForceIPv4"
                                | "ForceIPv6"
                                | "ForceIPv4v6"
                                | "ForceIPv6v4"
                        ),
                        "{p}.settings.domainStrategy: unknown {strategy}"
                    );
                    let rules = settings["finalRules"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .enumerate();
                    OutboundKind::Freedom {
                        final_rules: rules
                            .map(|(j, r)| parse_final_rule(r, j, &mut loader))
                            .collect::<Result<_>>()?,
                        strategy,
                    }
                }
                Some("blackhole") => {
                    keys(settings, &["response"], &format!("{p}.settings"))?;
                    let kind = settings["response"]["type"].as_str().unwrap_or("none");
                    ensure!(
                        matches!(kind, "none" | "http"),
                        "{p}.settings.response.type must be none or http"
                    );
                    OutboundKind::Blackhole {
                        http: kind == "http",
                    }
                }
                Some("socks") => {
                    keys(
                        settings,
                        &["address", "port", "user", "pass"],
                        &format!("{p}.settings"),
                    )?;
                    let address = settings["address"]
                        .as_str()
                        .filter(|a| !a.is_empty())
                        .with_context(|| format!("{p}.settings.address is required"))?
                        .to_owned();
                    let port = settings["port"]
                        .as_u64()
                        .filter(|p| *p > 0 && *p <= 65535)
                        .with_context(|| format!("{p}.settings.port must be between 1 and 65535"))?
                        as u16;
                    let credential = |key: &str| -> Result<&str> {
                        match &settings[key] {
                            Value::Null => Ok(""),
                            Value::String(s) if s.len() <= 255 => Ok(s),
                            _ => bail!("{p}.settings.{key} must be a string of at most 255 bytes"),
                        }
                    };
                    let (user, pass) = (credential("user")?, credential("pass")?);
                    ensure!(
                        user.is_empty() || !pass.is_empty(),
                        "{p}.settings.pass must be nonempty when SOCKS authentication is enabled"
                    );
                    OutboundKind::Socks(crate::socks::Server {
                        address,
                        port,
                        auth: (!user.is_empty()).then(|| (user.to_owned(), pass.to_owned())),
                    })
                }
                Some(other) => return Err(unsupported(&format!("{p}.protocol {other}"))),
                None => bail!("{p}.protocol is required"),
            };
            outbounds.push(Outbound {
                tag: v["tag"].as_str().unwrap_or_default().to_owned(),
                kind,
                socket,
            });
        }
        Ok(Self {
            stats: !root["stats"].is_null(),
            policy: Policy::parse(&root["policy"])?,
            inbounds,
            outbounds,
            router,
            log_level: log["loglevel"].as_str().unwrap_or("warning").to_owned(),
            access_log: log["access"]
                .as_str()
                .filter(|s| !s.is_empty() && *s != "none")
                .map(str::to_owned),
            error_log: log["error"]
                .as_str()
                .filter(|s| !s.is_empty() && *s != "none")
                .map(str::to_owned),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uuid_parsing_matches_xray() {
        assert_eq!(
            parse_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap()[..2],
            [0x55, 0x0e]
        );
        assert_eq!(
            parse_uuid("550e8400e29b41d4a716446655440000").unwrap(),
            parse_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap()
        );
        // Xray maps short strings through UUIDv5 (namespace zero): version 5, RFC variant.
        let mapped = parse_uuid("example").unwrap();
        assert_eq!(mapped[6] >> 4, 5);
        assert_eq!(mapped[8] >> 6, 2);
        assert!(parse_uuid("").is_err());
        assert!(parse_uuid("zz0e8400-e29b-41d4-a716-446655440000").is_err());
    }
    #[test]
    fn unported_features_fail_by_name() {
        let error = Config::parse(r#"{"inbounds":[{"tag":"x","port":443,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"raw","security":"tls"}}]}"#)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("security tls"), "{error}");
        assert!(Config::parse(r#"{"dns":{"servers":["1.1.1.1"]}}"#).is_err());
        assert!(Config::parse(r#"{"outbounds":[{"protocol":"vmess"}]}"#).is_err());
    }
    #[test]
    fn reality_rejects_malformed_security_controls_without_disclosing_key() {
        use base64::Engine;
        let valid = serde_json::json!({"target":"127.0.0.1:443","serverNames":["target.test"],"privateKey":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1;32]),"shortIds":[""]});
        assert!(parse_reality(&valid, "reality").is_ok());
        for (field, value) in [
            ("maxTimeDiff", serde_json::json!(-1)),
            ("maxTimeDiff", serde_json::json!("1000")),
            ("xver", serde_json::json!(-1)),
            ("show", serde_json::json!("true")),
            ("minClientVer", serde_json::json!(12)),
            ("target", serde_json::json!(65536)),
        ] {
            let mut bad = valid.clone();
            bad[field] = value;
            assert!(
                parse_reality(&bad, "reality").is_err(),
                "accepted invalid {field}"
            );
        }
        let mut bad = valid;
        bad["privateKey"] = serde_json::json!("PRIVATE_SECRET");
        let message = parse_reality(&bad, "reality").err().unwrap().to_string();
        assert!(!message.contains("PRIVATE_SECRET"));
    }
    fn vless_config(settings: Value) -> Result<Config> {
        Config::parse(&serde_json::json!({"inbounds":[{"tag":"test","listen":"127.0.0.1","port":12345,"protocol":"vless","settings":settings}]}).to_string())
    }

    #[test]
    fn inbound_flow_is_inherited_by_missing_empty_and_null_client_flows() {
        let parsed=vless_config(serde_json::json!({"decryption":"none","flow":"xtls-rprx-vision","clients":[
            {"id":"first"},{"id":"second","flow":""},{"id":"third","flow":null},{"id":"fourth","flow":"xtls-rprx-vision"}
        ]})).unwrap();
        let InboundKind::Vless(users) = &parsed.inbounds[0].kind else {
            panic!("expected VLESS")
        };
        assert_eq!(users.len(), 4);
        assert!(users.iter().all(|user| user.flow == "xtls-rprx-vision"));
        for default in [Value::Null, serde_json::json!("")] {
            let parsed=vless_config(serde_json::json!({"decryption":"none","flow":default,"clients":[{"id":"first"},{"id":"second","flow":"xtls-rprx-vision"}]})).unwrap();
            let InboundKind::Vless(users) = &parsed.inbounds[0].kind else {
                panic!("expected VLESS")
            };
            assert_eq!(users[0].flow, "");
            assert_eq!(users[1].flow, "xtls-rprx-vision");
        }
    }

    #[test]
    fn invalid_inbound_or_client_flows_are_not_silently_inherited() {
        for invalid in [
            serde_json::json!("xtls-rprx-direct"),
            serde_json::json!(17),
            serde_json::json!(false),
            serde_json::json!([]),
        ] {
            assert!(
                vless_config(serde_json::json!({"decryption":"none","flow":invalid,"clients":[]}))
                    .is_err()
            );
            assert!(vless_config(serde_json::json!({"decryption":"none","flow":"xtls-rprx-vision","clients":[{"id":"first","flow":invalid}]})).is_err());
        }
    }
    #[test]
    fn profile_outbounds_preserve_socket_options_and_socks_proxy() {
        let parsed = Config::parse(&serde_json::json!({"outbounds":[
            {"tag":"DIRECT","protocol":"freedom"},
            {"tag":"BLOCK","protocol":"blackhole"},
            {"tag":"warp-out","protocol":"freedom","settings":{},"streamSettings":{"sockopt":{"interface":"warp","tcpFastOpen":true}}},
            {"tag":"psiphon-out","protocol":"socks","settings":{"address":"172.17.0.1","port":1080}}
        ]}).to_string());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.outbounds[2].socket.interface, "warp");
        assert_eq!(parsed.outbounds[2].socket.tcp_fast_open, Some(true));
        let OutboundKind::Socks(server) = &parsed.outbounds[3].kind else {
            panic!("expected SOCKS")
        };
        assert_eq!(server.address, "172.17.0.1");
        assert_eq!(server.port, 1080);
        assert!(server.auth.is_none());
    }
    #[test]
    fn unported_outbound_transports_and_invalid_socket_options_are_rejected() {
        for stream in [
            serde_json::json!({"network":"ws"}),
            serde_json::json!({"security":"tls"}),
            serde_json::json!({"network":false}),
            serde_json::json!({"security":17}),
            serde_json::json!({"sockopt":{"interface":false}}),
            serde_json::json!({"sockopt":{"interface":"0123456789012345"}}),
            serde_json::json!({"sockopt":{"interface":"lo\u{0}other"}}),
            serde_json::json!({"sockopt":{"tcpFastOpen":"true"}}),
            serde_json::json!({"sockopt":{"tcpFastOpen":1.5}}),
            serde_json::json!({"sockopt":{"mark":2}}),
        ] {
            assert!(Config::parse(&serde_json::json!({"outbounds":[{"protocol":"freedom","streamSettings":stream}]}).to_string()).is_err(), "accepted {stream}");
        }
    }

    #[test]
    fn socks_credentials_and_endpoint_are_validated() {
        for settings in [
            serde_json::json!({}),
            serde_json::json!({"address":"127.0.0.1","port":0}),
            serde_json::json!({"address":"127.0.0.1","port":65536}),
            serde_json::json!({"address":"127.0.0.1","port":1080,"user":false}),
            serde_json::json!({"address":"127.0.0.1","port":1080,"user":"alice"}),
            serde_json::json!({"address":"127.0.0.1","port":1080,"pass":"x".repeat(256)}),
        ] {
            assert!(
                Config::parse(
                    &serde_json::json!({"outbounds":[{"protocol":"socks","settings":settings}]})
                        .to_string()
                )
                .is_err()
            );
        }
    }
}

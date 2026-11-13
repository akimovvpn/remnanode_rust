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

/// cfgcommon/duration: a JSON string in time.ParseDuration syntax, as nanoseconds.
pub fn go_duration_ns(value: &Value, path: &str) -> Result<i64> {
    let text = value
        .as_str()
        .with_context(|| format!("{path}: invalid duration: {value}"))?;
    let (negative, mut rest) = match text.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    ensure!(
        !rest.is_empty(),
        "{path}: time: invalid duration \"{text}\""
    );
    if rest == "0" {
        return Ok(0);
    }
    let mut total = 0f64;
    while !rest.is_empty() {
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .with_context(|| format!("{path}: time: missing unit in duration \"{text}\""))?;
        let number: f64 = rest[..end]
            .parse()
            .with_context(|| format!("{path}: time: invalid duration \"{text}\""))?;
        rest = &rest[end..];
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let scale = match &rest[..unit_end] {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            unit => bail!("{path}: time: unknown unit \"{unit}\" in duration \"{text}\""),
        };
        total += number * scale;
        rest = &rest[unit_end..];
    }
    Ok(if negative {
        -(total as i64)
    } else {
        total as i64
    })
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
    pub tls: Option<std::sync::Arc<crate::tls_server::Server>>,
}

/// REALITYConfig.Build (infra/conf/transport_internet.go), server side.
/// conf.Address: an IP literal or a domain.
fn address(v: &Value, path: &str) -> Result<crate::vless::Address> {
    let text = v
        .as_str()
        .filter(|a| !a.is_empty())
        .with_context(|| format!("{path} is not set"))?;
    Ok(
        match text
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            Ok(ip) => crate::vless::Address::Ip(ip.to_canonical()),
            Err(_) => crate::vless::Address::Domain(text.to_owned()),
        },
    )
}

/// VLessOutboundConfig.Build (one vnext, one user) plus its stream settings.
fn parse_vless_outbound(
    settings: &Value,
    stream: &Value,
    p: &str,
) -> Result<crate::vless_out::Server> {
    keys(
        settings,
        &[
            "address",
            "port",
            "level",
            "email",
            "id",
            "flow",
            "seed",
            "encryption",
            "reverse",
            "testpre",
            "testseed",
            "vnext",
        ],
        &format!("{p}.settings"),
    )?;
    let flat = !settings["address"].is_null();
    let (server, user) = if flat {
        ensure!(
            settings["reverse"].is_null(),
            "{}",
            unsupported(&format!("{p}.settings.reverse"))
        );
        (settings, settings)
    } else {
        let vnext = settings["vnext"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        ensure!(
            vnext.len() == 1,
            "VLESS settings: \"vnext\" should have one and only one member. Multiple endpoints in \"vnext\" should use multiple VLESS outbounds and routing balancer instead"
        );
        let server = &vnext[0];
        keys(
            server,
            &["address", "port", "users"],
            &format!("{p}.settings.vnext[0]"),
        )?;
        let users = server["users"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        ensure!(
            users.len() == 1,
            "VLESS vnext: \"users\" should have one and only one member. Multiple members in \"users\" should use multiple VLESS outbounds and routing balancer instead"
        );
        let user = &users[0];
        keys(
            user,
            &[
                "id",
                "flow",
                "encryption",
                "level",
                "email",
                "reverse",
                "testpre",
                "testseed",
            ],
            &format!("{p}.settings.vnext[0].users[0]"),
        )?;
        ensure!(
            user["reverse"].is_null(),
            "VLESS users: please use simplified outbound's config style to use \"reverse\""
        );
        (server, user)
    };
    for field in ["testpre", "testseed"] {
        ensure!(
            user[field].is_null() || user[field] == 0 || user[field] == serde_json::json!([]),
            "{}",
            unsupported(&format!("{p}.settings.{field}"))
        );
    }
    let address = address(&server["address"], "VLESS vnext: \"address\"")?;
    let port = server["port"]
        .as_u64()
        .filter(|p| *p <= 65535)
        .with_context(|| format!("{p}.settings.port must be between 0 and 65535"))?
        as u16;
    let id = parse_uuid(user["id"].as_str().unwrap_or_default())?;
    let flow = match &user["flow"] {
        Value::Null => String::new(),
        Value::String(flow) => flow.clone(),
        _ => bail!("{p}.settings.flow must be a string"),
    };
    ensure!(
        matches!(
            flow.as_str(),
            "" | "xtls-rprx-vision" | "xtls-rprx-vision-udp443"
        ),
        "VLESS users: \"flow\" doesn't support \"{flow}\" in this version"
    );
    match user["encryption"].as_str().unwrap_or_default() {
        "none" => {}
        "" => bail!("VLESS users: please add/set \"encryption\":\"none\" for every user"),
        e if e.starts_with("mlkem768x25519plus.") => {
            return Err(unsupported(&format!("{p}.settings encryption {e}")));
        }
        e => bail!("VLESS users: unsupported \"encryption\": {e}"),
    }
    let level = match &user["level"] {
        Value::Null => 0,
        value => value
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .with_context(|| format!("{p}.settings.level must be an unsigned 32-bit integer"))?,
    };
    let sp = format!("{p}.streamSettings");
    let default_name = match &address {
        crate::vless::Address::Ip(ip) => ip.to_string(),
        crate::vless::Address::Domain(d) => d.clone(),
    };
    for raw in ["tcpSettings", "rawSettings"] {
        keys(&stream[raw], &["header"], &format!("{sp}.{raw}"))?;
        let header = stream[raw]["header"]["type"].as_str().unwrap_or("none");
        ensure!(
            header == "none",
            "{}",
            unsupported(&format!("{sp}.{raw}.header {header}"))
        );
    }
    let ws = matches!(stream["network"].as_str(), Some("ws" | "websocket"));
    let security = match stream["security"].as_str().unwrap_or("none") {
        "none" | "" => crate::vless_out::Security::None,
        "tls" => crate::vless_out::Security::Tls(parse_tls_client(
            &stream["tlsSettings"],
            &format!("{sp}.tlsSettings"),
            &default_name,
            ws,
        )?),
        "reality" => {
            ensure!(
                !ws,
                "{}",
                unsupported(&format!("{sp}: REALITY over WebSocket"))
            );
            crate::vless_out::Security::Reality(parse_reality_client(
                &stream["realitySettings"],
                &format!("{sp}.realitySettings"),
                &default_name,
            )?)
        }
        other => return Err(unsupported(&format!("{sp}.security {other}"))),
    };
    let network = match stream["network"].as_str().unwrap_or("raw") {
        "raw" | "tcp" | "" => crate::vless_out::Network::Raw,
        "ws" | "websocket" => {
            let ws = &stream["wsSettings"];
            let (path, mut host) = http_transport(ws, true, &format!("{sp}.wsSettings"))?;
            // conf.WebSocketConfig: "?ed=N" in the path sets the early data limit.
            let raw_path = ws["path"].as_str().unwrap_or_default();
            let early = raw_path
                .split_once('?')
                .and_then(|(_, q)| {
                    q.split('&')
                        .find_map(|kv| kv.strip_prefix("ed="))
                        .and_then(|v| v.parse::<usize>().ok())
                })
                .unwrap_or(0);
            if host.is_empty()
                && let crate::vless_out::Security::Tls(tls) = &security
            {
                host = tls.server_name.clone();
            }
            if host.is_empty() {
                host = default_name.clone();
            }
            let headers = ws["headers"]
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(k, _)| !k.eq_ignore_ascii_case("host"))
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
                .collect();
            crate::vless_out::Network::Ws {
                path,
                host,
                headers,
                early,
                heartbeat: ws["heartbeatPeriod"].as_u64().unwrap_or(0) as u32,
            }
        }
        other => return Err(unsupported(&format!("{sp}.network {other}"))),
    };
    Ok(crate::vless_out::Server {
        address,
        port,
        id,
        flow,
        level,
        network,
        security,
    })
}

fn fingerprint(v: &Value, path: &str) -> Result<crate::tls_client::Fingerprint> {
    let name = match v {
        Value::Null => "",
        Value::String(name) => name,
        _ => bail!("{path}.fingerprint must be a string"),
    };
    crate::tls_client::Fingerprint::parse(name)
        .ok_or_else(|| unsupported(&format!("{path}.fingerprint {name}")))
}

/// TLSConfig.Build for a client: SNI, ALPN and a uTLS fingerprint.
fn parse_tls_client(
    v: &Value,
    path: &str,
    default_name: &str,
    websocket: bool,
) -> Result<crate::tls_client::Client> {
    keys(
        v,
        &[
            "serverName",
            "alpn",
            "fingerprint",
            "allowInsecure",
            "pinnedPeerCertSha256",
            "verifyPeerCertByName",
            "echConfigList",
            "echSockopt",
            "certificates",
            "disableSystemRoot",
            "minVersion",
            "maxVersion",
            "cipherSuites",
            "curvePreferences",
            "masterKeyLog",
            "enableSessionResumption",
            "useSystemCA",
            "rejectUnknownSni",
        ],
        path,
    )?;
    for field in ["serverName", "masterKeyLog"] {
        ensure!(
            v[field].is_null() || v[field].is_string(),
            "{path}.{field} must be a string"
        );
    }
    for field in [
        "allowInsecure",
        "disableSystemRoot",
        "enableSessionResumption",
        "useSystemCA",
        "rejectUnknownSni",
    ] {
        ensure!(
            v[field].is_null() || v[field].is_boolean(),
            "{path}.{field} must be a boolean"
        );
    }
    ensure!(
        v["masterKeyLog"].as_str().is_none_or(str::is_empty),
        "{}",
        unsupported(&format!("{path}.masterKeyLog"))
    );
    ensure!(
        v["echSockopt"].is_null(),
        "{}",
        unsupported(&format!("{path}.echSockopt"))
    );
    ensure!(
        v["allowInsecure"] != true,
        "The feature \"allowInsecure\" has been removed and migrated to \"pinnedPeerCertSha256\"(pcs) and \"verifyPeerCertByName\"(vcn)."
    );
    for field in [
        "pinnedPeerCertSha256",
        "verifyPeerCertByName",
        "echConfigList",
        "certificates",
        "minVersion",
        "maxVersion",
        "cipherSuites",
        "curvePreferences",
    ] {
        let set = match &v[field] {
            Value::Null => false,
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            _ => true,
        };
        ensure!(!set, "{}", unsupported(&format!("{path}.{field}")));
    }
    for field in ["disableSystemRoot", "enableSessionResumption"] {
        ensure!(
            v[field] != true,
            "{}",
            unsupported(&format!("{path}.{field}"))
        );
    }
    let configured = string_list(&v["alpn"], &format!("{path}.alpn"))?;
    // The WebSocket dialer forces http/1.1 (WebsocketHandshakeContext).
    let alpn = if websocket {
        vec!["http/1.1".to_owned()]
    } else if configured.is_empty() {
        vec!["h2".to_owned(), "http/1.1".to_owned()]
    } else {
        configured
    };
    let server_name = v["serverName"].as_str().unwrap_or_default();
    Ok(crate::tls_client::Client {
        server_name: if server_name.is_empty() {
            default_name.to_owned()
        } else {
            server_name.to_owned()
        },
        fingerprint: fingerprint(&v["fingerprint"], path)?,
        alpn,
        reality: None,
    })
}

/// REALITYConfig.Build for a client.
fn parse_reality_client(
    v: &Value,
    path: &str,
    default_name: &str,
) -> Result<crate::tls_client::Client> {
    use base64::Engine;
    keys(
        v,
        &[
            "show",
            "fingerprint",
            "serverName",
            "serverNames",
            "password",
            "publicKey",
            "shortId",
            "shortIds",
            "mldsa65Verify",
            "spiderX",
            "masterKeyLog",
        ],
        path,
    )?;
    let fp = v["fingerprint"].as_str().unwrap_or_default().to_lowercase();
    ensure!(
        fp != "unsafe" && fp != "hellogolang",
        "invalid \"fingerprint\": {fp}"
    );
    ensure!(
        v["serverNames"].as_array().is_none_or(Vec::is_empty),
        "non-empty \"serverNames\", please use \"serverName\" instead"
    );
    ensure!(
        v["shortIds"].as_array().is_none_or(Vec::is_empty),
        "non-empty \"shortIds\", please use \"shortId\" instead"
    );
    let key = v["password"]
        .as_str()
        .filter(|k| !k.is_empty())
        .or(v["publicKey"].as_str())
        .unwrap_or_default();
    ensure!(!key.is_empty(), "empty \"password\"");
    let public_key: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key)
        .ok()
        .and_then(|k| k.try_into().ok())
        .with_context(|| format!("invalid \"password\": {key}"))?;
    let short = v["shortId"].as_str().unwrap_or_default();
    ensure!(short.len() <= 16, "too long \"shortId\": {short}");
    let mut short_id = [0u8; 8];
    ensure!(
        short.len().is_multiple_of(2) && short.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid \"shortId\": {short}"
    );
    for (i, pair) in short.as_bytes().chunks(2).enumerate() {
        short_id[i] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    ensure!(
        v["mldsa65Verify"].as_str().is_none_or(str::is_empty),
        "{}",
        unsupported(&format!("{path}.mldsa65Verify"))
    );
    let spider = v["spiderX"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("/");
    ensure!(spider.starts_with('/'), "invalid \"spiderX\": {spider}");
    // spiderX query p/c/t/i/r set the spider's padding, concurrency, times, interval, return.
    let (spider_path, query) = spider.split_once('?').unwrap_or((spider, ""));
    let mut spider_y = [0i64; 10];
    let mut rest = Vec::new();
    for kv in query.split('&').filter(|kv| !kv.is_empty()) {
        let (k, value) = kv.split_once('=').unwrap_or((kv, ""));
        let index = match k {
            "p" => 0,
            "c" => 2,
            "t" => 4,
            "i" => 6,
            "r" => 8,
            _ => {
                rest.push(kv);
                continue;
            }
        };
        let (a, b) = value.split_once('-').unwrap_or((value, value));
        spider_y[index] = a.parse().unwrap_or(0);
        spider_y[index + 1] = b.parse().unwrap_or(0);
    }
    let spider_x = if rest.is_empty() {
        spider_path.to_owned()
    } else {
        format!("{spider_path}?{}", rest.join("&"))
    };
    let server_name = v["serverName"].as_str().unwrap_or_default();
    Ok(crate::tls_client::Client {
        server_name: if server_name.is_empty() {
            default_name.to_owned()
        } else {
            server_name.to_owned()
        },
        fingerprint: fingerprint(&v["fingerprint"], path)?,
        alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
        reality: Some(crate::tls_client::Reality {
            public_key,
            short_id,
            spider_x,
            spider_y,
        }),
    })
}

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
        strategy: crate::dns::Strategy,
    },
    Dns(std::sync::Arc<crate::dns_outbound::DnsOutbound>),
    Blackhole {
        http: bool,
    },
    Socks(crate::socks::Server),
    Vless(std::sync::Arc<crate::vless_out::Server>),
}

pub struct Outbound {
    pub tag: String,
    pub kind: OutboundKind,
    pub socket: crate::socket::Options,
}

pub struct Config {
    /// Deprecation warnings Go logs while building the config, printed once logging is up.
    pub warnings: Vec<String>,
    pub dns: crate::dns::Dns,
    pub observatory: crate::observatory::Observatory,
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
                "dns",
                "observatory",
                "burstObservatory",
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
                    "xhttpSettings",
                    "splithttpSettings",
                    "realitySettings",
                    "tlsSettings",
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
                "xhttp" | "splithttp" => {
                    let key = if stream["xhttpSettings"].is_null() {
                        "splithttpSettings"
                    } else {
                        "xhttpSettings"
                    };
                    Transport::Xhttp(std::sync::Arc::new(crate::xhttp::Config::parse(
                        &stream[key],
                        &format!("{p}.streamSettings.{key}"),
                    )?))
                }
                other => return Err(unsupported(&format!("{p}.streamSettings.network {other}"))),
            };
            let mut tls = None;
            let reality = match stream["security"].as_str().unwrap_or("none") {
                "none" | "" => None,
                "tls" => {
                    let server = crate::tls_server::Server::parse(
                        &stream["tlsSettings"],
                        &format!("{p}.streamSettings.tlsSettings"),
                    )?;
                    ensure!(
                        !(matches!(transport, Transport::Xhttp(_))
                            && server.alpn() == [b"h3".to_vec()]),
                        "{}",
                        unsupported(&format!("{p}.streamSettings: XHTTP over HTTP/3 (alpn h3)"))
                    );
                    tls = Some(std::sync::Arc::new(server));
                    None
                }
                "reality" => {
                    ensure!(
                        matches!(transport, Transport::Raw | Transport::Xhttp(_)),
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
                tls,
            });
        }
        let mut outbounds = Vec::new();
        let mut warnings = Vec::new();
        for (i, v) in root["outbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let p = format!("outbounds[{i}]");
            keys(v, &["tag", "protocol", "settings", "streamSettings"], &p)?;
            let stream = &v["streamSettings"];
            let vless = v["protocol"] == "vless";
            let allowed: &[&str] = if vless {
                &[
                    "network",
                    "security",
                    "sockopt",
                    "tcpSettings",
                    "rawSettings",
                    "wsSettings",
                    "tlsSettings",
                    "realitySettings",
                ]
            } else {
                &["network", "security", "sockopt"]
            };
            keys(stream, allowed, &format!("{p}.streamSettings"))?;
            for field in ["network", "security"] {
                ensure!(
                    stream[field].is_null() || stream[field].is_string(),
                    "{p}.streamSettings.{field} must be a string"
                );
            }
            if !vless {
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
            }
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
                    let name = settings["domainStrategy"].as_str().unwrap_or("AsIs");
                    let strategy = crate::dns::Strategy::parse(name)
                        .with_context(|| format!("{p}.settings.domainStrategy: unknown {name}"))?;
                    if strategy.has_strategy() {
                        warnings.push("infra/conf: The \"freedom.domainStrategy\" setting is deprecated and will be removed. For compatibility, its value has been automatically migrated to \"sockopt.domainStrategy\". Please update your config before removal.".into());
                    }
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
                Some("vless") => OutboundKind::Vless(std::sync::Arc::new(parse_vless_outbound(
                    settings, stream, &p,
                )?)),
                Some("dns") => OutboundKind::Dns(std::sync::Arc::new(
                    crate::dns_outbound::DnsOutbound::parse(
                        settings,
                        &format!("{p}.settings"),
                        &mut loader,
                        &mut warnings,
                    )?,
                )),
                Some(other) => return Err(unsupported(&format!("{p}.protocol {other}"))),
                None => bail!("{p}.protocol is required"),
            };
            outbounds.push(Outbound {
                tag: v["tag"].as_str().unwrap_or_default().to_owned(),
                kind,
                socket,
            });
        }
        let dns = crate::dns::Dns::parse(&root["dns"], &mut loader)
            .context("failed to build DNS config")?;
        let observatory = crate::observatory::Observatory::parse(
            &root["observatory"],
            &root["burstObservatory"],
        )?;
        // core.RequireFeatures: a balancer that reads observations needs an observatory.
        ensure!(
            !router.needs_observatory() || !observatory.is_none(),
            "core: not all dependencies are resolved."
        );
        Ok(Self {
            warnings,
            dns,
            observatory,
            stats: !root["stats"].is_null(),
            policy: Policy::parse(&root["policy"])?,
            inbounds,
            outbounds,
            router,
            log_level: log["loglevel"].as_str().unwrap_or("warning").to_owned(),
            access_log: if !log.is_object()
                || log["access"] == "none"
                || log["loglevel"]
                    .as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case("none"))
            {
                None
            } else {
                Some(
                    log["access"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .unwrap_or("/dev/stdout")
                        .to_owned(),
                )
            },
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
        let error = Config::parse(r#"{"inbounds":[{"tag":"x","port":443,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"raw","security":"xtls"}}]}"#)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("security xtls"), "{error}");
        let h3 = r#"{"inbounds":[{"port":443,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"alpn":["h3"]}}}]}"#;
        assert!(Config::parse(h3).err().unwrap().to_string().contains("HTTP/3"));
        assert!(Config::parse(r#"{"dns":{"servers":["1.1.1.1"],"script":"x"}}"#).is_err());
        assert!(Config::parse(r#"{"dns":{"servers":["fakedns"]}}"#).is_err());
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
    #[test]
    fn access_logs_use_stdout_by_default_and_honor_disabled_or_file_config() {
        for (log, expected) in [
            (serde_json::json!(null), None),
            (serde_json::json!({"loglevel":"info"}), Some("/dev/stdout")),
            (serde_json::json!({"access":""}), Some("/dev/stdout")),
            (serde_json::json!({"access":"none"}), None),
            (
                serde_json::json!({"loglevel":"none","access":"/tmp/custom"}),
                None,
            ),
            (
                serde_json::json!({"access":"/tmp/custom"}),
                Some("/tmp/custom"),
            ),
        ] {
            let parsed = Config::parse(&serde_json::json!({"log":log}).to_string()).unwrap();
            assert_eq!(parsed.access_log.as_deref(), expected);
        }
    }
    #[test]
    fn malformed_vless_outbound_fields_are_rejected() {
        let base = serde_json::json!({"protocol":"vless","settings":{"address":"127.0.0.1","port":443,"id":"fuzz","encryption":"none"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost"}}});
        for (path, value) in [
            ("/settings/flow", serde_json::json!(false)),
            ("/settings/level", serde_json::json!(4294967296u64)),
            (
                "/streamSettings/tlsSettings/serverName",
                serde_json::json!(false),
            ),
            (
                "/streamSettings/tlsSettings/fingerprint",
                serde_json::json!(17),
            ),
            (
                "/streamSettings/tlsSettings/enableSessionResumption",
                serde_json::json!("true"),
            ),
            (
                "/streamSettings/tlsSettings/masterKeyLog",
                serde_json::json!("/tmp/not-supported"),
            ),
        ] {
            let mut outbound = base.clone();
            let (parent, name) = path.rsplit_once('/').unwrap();
            outbound.pointer_mut(parent).unwrap()[name] = value;
            assert!(
                Config::parse(&serde_json::json!({"outbounds":[outbound]}).to_string()).is_err(),
                "accepted {path}"
            );
        }
    }
}

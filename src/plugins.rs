use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

const OWNER: &str = "remnanode-rust managed";
pub const TORRENT_OUTBOUND: &str = "RW_TB_OUTBOUND_BLOCK";
const DEFAULT_ASN_DB: &str = "/usr/local/share/asn/asn-prefixes.json";
// shortcut: reports are dropped past this cap if the panel stops collecting; raise if panels poll rarely.
const MAX_REPORTS: usize = 10_000;

pub struct Plugins {
    config: Option<Value>,
    plan: Plan,
    settings: Option<Settings>,
    blocks: BTreeMap<IpAddr, Option<Instant>>,
    reports: Vec<Value>,
    pub(crate) nft_available: bool,
    asn_db: PathBuf,
}

impl Default for Plugins {
    fn default() -> Self {
        Self {
            config: None,
            plan: Plan::default(),
            settings: None,
            blocks: BTreeMap::new(),
            reports: Vec::new(),
            nft_available: crate::operations::automatic_drop_available(),
            asn_db: std::env::var_os("ASN_DB_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| DEFAULT_ASN_DB.into()),
        }
    }
}

pub struct SyncOutcome {
    pub accepted: bool,
    /// Upstream stops Xray so the panel restarts it with the new routing/plugin state.
    pub stop_xray: bool,
}

#[derive(Default)]
struct Plan {
    ingress: Vec<String>,
    egress: Vec<String>,
    ports: Vec<u16>,
    whitelist: Vec<IpNet>,
    firewall: bool,
    torrent: Option<Torrent>,
}

#[derive(Clone, PartialEq)]
struct Torrent {
    duration: u32,
    ignored_ips: Vec<IpNet>,
    ignored_users: HashSet<String>,
    include_rule_tags: Vec<String>,
    rule_position: u32,
    webhook: Option<String>,
}

#[derive(Clone)]
struct Settings {
    table: String,
    logging: bool,
    replies: bool,
}

impl Settings {
    // nft rejects quoted table names, so the name is validated as a bare nft identifier.
    fn new(table: &str, logging: bool, replies: bool) -> Result<Self> {
        let table = table.trim();
        ensure!(
            !table.is_empty()
                && table.len() <= 63
                && table
                    .bytes()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
                && table
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')),
            "Invalid NFTABLES_TABLE_NAME"
        );
        Ok(Self {
            table: table.to_owned(),
            logging,
            replies,
        })
    }

    fn from_env() -> Result<Self> {
        fn flag(name: &str, default: bool) -> Result<bool> {
            match std::env::var(name).as_deref() {
                Ok("") | Err(_) => Ok(default),
                Ok("true") => Ok(true),
                Ok("false") => Ok(false),
                _ => bail!("{name} must be true or false"),
            }
        }
        let table =
            std::env::var("NFTABLES_TABLE_NAME").unwrap_or_else(|_| "remnanode_rust".into());
        Self::new(
            if table.trim().is_empty() {
                "remnanode_rust"
            } else {
                &table
            },
            flag("NFTABLES_LOGGING", true)?,
            flag("NFTABLES_ACCEPT_REPLY_TRAFFIC", false)?,
        )
    }
}

fn array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{field} must be an array"))
}

fn strings(value: &Value, field: &str) -> Result<Vec<String>> {
    array(value, field)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("{field} must contain strings"))
        })
        .collect()
}

/// Normalizes an IP or CIDR; CIDR host bits are cleared so nft accepts it.
fn address(value: &str) -> Result<String> {
    if value.contains('/') {
        let net: IpNet = value.parse().context("Invalid IP/CIDR address")?;
        return Ok(net.trunc().to_string());
    }
    Ok(value
        .parse::<IpAddr>()
        .context("Invalid IP address")?
        .to_string())
}

fn net(value: &str) -> Result<IpNet> {
    Ok(match value.parse::<IpNet>() {
        Ok(net) => net,
        Err(_) => value
            .parse::<IpAddr>()
            .context("Invalid IP address")?
            .into(),
    })
}

/// Upstream DEFAULT_IGNORED_IPS: unspecified, loopback and broadcast addresses are never blocked or dropped.
pub(crate) fn listed(list: &[IpNet], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip == IpAddr::V4(Ipv4Addr::BROADCAST)
        || list.iter().any(|net| net.contains(&ip))
}

/// Streams the asn-index JSON ({"13335":{"ipv4":[..],"ipv6":[..]}}) keeping only the requested ASNs.
fn asn_prefixes(path: &Path, wanted: &BTreeSet<u32>) -> Result<HashMap<u32, Vec<String>>> {
    struct Wanted<'a>(&'a BTreeSet<u32>);
    impl<'de> DeserializeSeed<'de> for Wanted<'_> {
        type Value = HashMap<u32, Vec<String>>;
        fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
            de.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for Wanted<'_> {
        type Value = HashMap<u32, Vec<String>>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an ASN prefix map")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            #[derive(serde::Deserialize)]
            struct Prefixes {
                ipv4: Vec<String>,
                ipv6: Vec<String>,
            }
            let mut found = HashMap::new();
            while let Some(key) = map.next_key::<String>()? {
                match key.parse().ok().filter(|asn| self.0.contains(asn)) {
                    Some(asn) => {
                        let prefixes: Prefixes = map.next_value()?;
                        found.insert(asn, [prefixes.ipv4, prefixes.ipv6].concat());
                    }
                    None => {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
            }
            Ok(found)
        }
    }
    if wanted.is_empty() {
        return Ok(HashMap::new());
    }
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "ASN database unavailable; ASN lists resolve to nothing");
            return Ok(HashMap::new());
        }
    };
    let mut reader = serde_json::Deserializer::from_reader(std::io::BufReader::new(file));
    Wanted(wanted)
        .deserialize(&mut reader)
        .context("Invalid ASN database")
}

enum SharedList {
    Ips(Vec<String>),
    Asns(Vec<u32>),
}

type Resolver<'a> = dyn Fn(&Value, &str, bool) -> Result<Vec<String>> + 'a;

impl Plan {
    fn parse(config: &Value, asn_db: &Path) -> Result<Self> {
        ensure!(config.is_object(), "plugin.config must be an object");
        let mut lists: Vec<(String, SharedList)> = Vec::new();
        if let Some(shared) = config.get("sharedLists") {
            for list in array(shared, "sharedLists")? {
                let name = list["name"]
                    .as_str()
                    .filter(|name| name.starts_with("ext:"))
                    .ok_or_else(|| anyhow::anyhow!("Shared list names must start with ext:"))?;
                let items = match list["type"].as_str() {
                    Some("ipList") => SharedList::Ips(
                        strings(&list["items"], "shared list items")?
                            .iter()
                            .map(|ip| address(ip))
                            .collect::<Result<Vec<_>>>()?,
                    ),
                    Some("asList") => SharedList::Asns(
                        array(&list["items"], "ASN list items")?
                            .iter()
                            .map(|asn| {
                                asn.as_u64()
                                    .and_then(|asn| u32::try_from(asn).ok())
                                    .filter(|asn| *asn >= 1)
                                    .ok_or_else(|| anyhow::anyhow!("Invalid ASN number"))
                            })
                            .collect::<Result<Vec<_>>>()?,
                    ),
                    _ => bail!("Unknown shared list type"),
                };
                ensure!(
                    !lists.iter().any(|(existing, _)| existing == name),
                    "Duplicate shared list: {name}"
                );
                lists.push((name.to_owned(), items));
            }
        }
        let wanted: BTreeSet<u32> = lists
            .iter()
            .filter_map(|(_, items)| match items {
                SharedList::Asns(asns) => Some(asns),
                SharedList::Ips(_) => None,
            })
            .flatten()
            .copied()
            .collect();
        let prefixes = asn_prefixes(asn_db, &wanted)?;
        let mut shared: HashMap<String, Vec<String>> = HashMap::new();
        for (name, items) in lists {
            let items = match items {
                SharedList::Ips(ips) => ips,
                SharedList::Asns(asns) => {
                    let mut resolved = Vec::new();
                    for asn in asns {
                        match prefixes.get(&asn) {
                            Some(list) => resolved.extend(list.iter().filter_map(|prefix| {
                                address(prefix)
                                    .inspect_err(|_| tracing::warn!(asn, %prefix, "Skipping invalid ASN prefix"))
                                    .ok()
                            })),
                            None => tracing::warn!(asn, "ASN not found in ASN database"),
                        }
                    }
                    resolved
                }
            };
            shared.insert(name, items);
        }
        let resolve = |feature: &Value, key: &str, required: bool| -> Result<Vec<String>> {
            let Some(items) = feature.get(key) else {
                ensure!(!required, "{key} is required");
                return Ok(Vec::new());
            };
            let mut result = Vec::new();
            for item in strings(items, key)? {
                if item.starts_with("ext:") {
                    match shared.get(&item) {
                        Some(list) => result.extend(list.iter().cloned()),
                        None => tracing::warn!(list = %item, "Shared list not found"),
                    }
                } else {
                    result.push(address(&item)?);
                }
            }
            result.sort();
            result.dedup();
            Ok(result)
        };
        let nets = |items: Vec<String>| -> Result<Vec<IpNet>> {
            items.iter().map(|item| net(item)).collect()
        };
        let mut plan = Self::default();
        for name in [
            "connectionDrop",
            "ingressFilter",
            "egressFilter",
            "torrentBlocker",
            "preStart",
            "postStart",
        ] {
            let Some(feature) = config.get(name) else {
                continue;
            };
            ensure!(feature.is_object(), "{name} must be an object");
            let optional_enabled = matches!(name, "preStart" | "postStart");
            ensure!(
                feature.get("enabled").is_some_and(Value::is_boolean)
                    || (optional_enabled && feature.get("enabled").is_none()),
                "{name}.enabled must be a boolean"
            );
            let enabled = feature["enabled"] == true;
            match name {
                "torrentBlocker" => {
                    let torrent = Torrent::parse(feature, &resolve)?;
                    if enabled {
                        plan.torrent = Some(torrent);
                    }
                }
                "connectionDrop" => {
                    if enabled {
                        plan.whitelist = nets(resolve(feature, "whitelistIps", true)?)?;
                    } else if let Some(items) = feature.get("whitelistIps") {
                        strings(items, "whitelistIps")?;
                    }
                }
                "ingressFilter" => {
                    if enabled {
                        plan.ingress = resolve(feature, "blockedIps", true)?;
                        plan.firewall = true;
                    } else if let Some(items) = feature.get("blockedIps") {
                        strings(items, "blockedIps")?;
                    }
                }
                "egressFilter" => {
                    if enabled {
                        plan.egress = resolve(feature, "blockedIps", false)?;
                        plan.firewall = true;
                    }
                    if let Some(ports) = feature.get("blockedPorts") {
                        let ports = array(ports, "blockedPorts")?
                            .iter()
                            .map(|port| {
                                port.as_u64()
                                    .filter(|port| (1..=65535).contains(port))
                                    .map(|port| port as u16)
                                    .ok_or_else(|| anyhow::anyhow!("Invalid blocked port"))
                            })
                            .collect::<Result<Vec<_>>>()?;
                        if enabled {
                            plan.ports = ports;
                            plan.ports.sort();
                            plan.ports.dedup();
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(cleanup) = config.pointer("/preStart/cleanupSockets") {
            ensure!(
                cleanup["enabled"].is_boolean(),
                "cleanupSockets.enabled must be a boolean"
            );
            let paths = strings(&cleanup["files"], "cleanupSockets.files")?;
            ensure!(paths.len() <= 64, "At most 64 cleanup paths are allowed");
            for path in paths {
                let path = path.trim();
                ensure!(
                    path.starts_with('/') && !path.contains('\0'),
                    "Cleanup path must be absolute"
                );
                glob::Pattern::new(path).context("Invalid cleanup glob pattern")?;
            }
        }
        if let Some(webhook) = config.pointer("/postStart/webhook") {
            ensure!(
                webhook["enabled"].is_boolean(),
                "webhook.enabled must be a boolean"
            );
            let url = reqwest::Url::parse(webhook["url"].as_str().unwrap_or(""))?;
            ensure!(
                matches!(url.scheme(), "http" | "https"),
                "Webhook must use HTTP or HTTPS"
            );
        }
        Ok(plan)
    }

    fn render(&self, settings: &Settings, blocks: &BTreeMap<IpAddr, Option<Instant>>) -> String {
        let table = format!("inet {}", settings.table);
        let mut script = format!(
            "add table {table}\ndelete table {table}\nadd table {table} {{ comment \"{OWNER}\"; }}\n"
        );
        for (name, kind) in [
            ("ingress4", "ipv4_addr"),
            ("ingress6", "ipv6_addr"),
            ("egress4", "ipv4_addr"),
            ("egress6", "ipv6_addr"),
        ] {
            script.push_str(&format!(
                "add set {table} {name} {{ type {kind}; flags interval; auto-merge; }}\n"
            ));
        }
        for (name, kind) in [("blocked4", "ipv4_addr"), ("blocked6", "ipv6_addr")] {
            script.push_str(&format!(
                "add set {table} {name} {{ type {kind}; flags timeout; }}\n"
            ));
        }
        script.push_str(&format!(
            "add set {table} egress_ports {{ type inet_service; }}\n"
        ));
        for chain in ["input", "forward", "output"] {
            script.push_str(&format!("add chain {table} {chain} {{ type filter hook {chain} priority -10; policy accept; }}\n"));
        }
        for chain in ["input", "forward"] {
            script.push_str(&format!("add rule {table} {chain} counter\n"));
            if settings.replies {
                script.push_str(&format!(
                    "add rule {table} {chain} ct direction reply accept\n"
                ));
            }
            for (family, suffix) in [("ip", "4"), ("ip6", "6")] {
                for prefix in ["ingress", "blocked"] {
                    let log = if settings.logging {
                        "log prefix \"remnanode-rust: \" "
                    } else {
                        ""
                    };
                    script.push_str(&format!("add rule {table} {chain} {family} saddr @{prefix}{suffix} {log}counter drop\n"));
                }
            }
        }
        for (family, suffix) in [("ip", "4"), ("ip6", "6")] {
            script.push_str(&format!(
                "add rule {table} output {family} daddr @egress{suffix} counter drop\n"
            ));
        }
        for protocol in ["tcp", "udp"] {
            script.push_str(&format!(
                "add rule {table} output {protocol} dport @egress_ports counter drop\n"
            ));
        }
        for (prefix, ips) in [("ingress", &self.ingress), ("egress", &self.egress)] {
            for ip in ips {
                let suffix = if ip.contains(':') { "6" } else { "4" };
                script.push_str(&format!(
                    "add element {table} {prefix}{suffix} {{ {ip} }}\n"
                ));
            }
        }
        for port in &self.ports {
            script.push_str(&format!("add element {table} egress_ports {{ {port} }}\n"));
        }
        let now = Instant::now();
        for (ip, expiry) in blocks {
            let lifetime = match expiry {
                None => String::new(),
                Some(expiry) => match expiry.checked_duration_since(now) {
                    Some(remaining) if !remaining.is_zero() => {
                        format!(" timeout {}ms", remaining.as_millis().max(1))
                    }
                    _ => continue,
                },
            };
            script.push_str(&block_line(&settings.table, *ip, &lifetime));
        }
        script
    }
}

fn block_line(table: &str, ip: IpAddr, lifetime: &str) -> String {
    let suffix = if ip.is_ipv4() { "4" } else { "6" };
    format!("add element inet {table} blocked{suffix} {{ {ip}{lifetime} }}\n")
}

impl Torrent {
    fn parse(feature: &Value, resolve: &Resolver) -> Result<Self> {
        let duration = feature["blockDuration"]
            .as_u64()
            .and_then(|seconds| u32::try_from(seconds).ok())
            .context("torrentBlocker.blockDuration must be whole seconds (0 = permanent)")?;
        let lists = &feature["ignoreLists"];
        ensure!(
            lists.is_object(),
            "torrentBlocker.ignoreLists must be an object"
        );
        let ignored_ips = resolve(lists, "ip", false)?
            .iter()
            .map(|item| net(item))
            .collect::<Result<_>>()?;
        let ignored_users = match lists.get("userId") {
            None => HashSet::new(),
            Some(users) => array(users, "ignoreLists.userId")?
                .iter()
                .map(|id| {
                    id.as_i64()
                        .map(|id| id.to_string())
                        .context("ignoreLists.userId must contain integers")
                })
                .collect::<Result<_>>()?,
        };
        let mut include_rule_tags = match feature.get("includeRuleTags") {
            None => Vec::new(),
            Some(tags) => {
                let tags = strings(tags, "includeRuleTags")?;
                ensure!(!tags.is_empty(), "includeRuleTags must not be empty");
                tags
            }
        };
        include_rule_tags.sort();
        include_rule_tags.dedup();
        let webhook = match feature.get("webhookUrl") {
            None => None,
            Some(url) => {
                let url = url.as_str().context("webhookUrl must be a string")?;
                let parsed =
                    reqwest::Url::parse(url).context("Invalid torrentBlocker.webhookUrl")?;
                ensure!(
                    matches!(parsed.scheme(), "http" | "https"),
                    "torrentBlocker.webhookUrl must use HTTP or HTTPS"
                );
                Some(url.to_owned())
            }
        };
        let rule_position = match feature.get("rulePlacement") {
            None => 0,
            Some(position) => {
                let position = position
                    .as_f64()
                    .filter(|p| (0.0..=1000.0).contains(p))
                    .context("rulePlacement must be between 0 and 1000")?;
                // Upstream treats non-integer placements as the default position.
                if position.fract() == 0.0 {
                    position as u32
                } else {
                    0
                }
            }
        };
        Ok(Self {
            duration,
            ignored_ips,
            ignored_users,
            include_rule_tags,
            rule_position,
            webhook,
        })
    }
}

/// Mirrors upstream XrayWebhookSchema; returns the event with only the schema's fields.
fn xray_report(event: &Value) -> Option<Value> {
    let mut report = serde_json::Map::new();
    for key in [
        "email",
        "protocol",
        "source",
        "routeTarget",
        "originalTarget",
        "inboundTag",
        "inboundName",
        "inboundLocal",
        "outboundTag",
    ] {
        let value = match event.get(key) {
            None | Some(Value::Null) => Value::Null,
            Some(value @ Value::String(_)) => value.clone(),
            _ => return None,
        };
        report.insert(key.into(), value);
    }
    let level = match event.get("level") {
        None | Some(Value::Null) => Value::Null,
        Some(value) if value.is_number() => value.clone(),
        _ => return None,
    };
    report.insert("level".into(), level);
    for (key, valid) in [
        ("network", Value::is_string as fn(&Value) -> bool),
        ("destination", Value::is_string),
        ("ts", Value::is_number),
    ] {
        report.insert(key.into(), event.get(key).filter(|v| valid(v))?.clone());
    }
    Some(Value::Object(report))
}

fn source_ip(source: &str) -> Option<IpAddr> {
    let source = source
        .strip_prefix("tcp:")
        .or_else(|| source.strip_prefix("udp:"))
        .unwrap_or(source);
    let ip = source
        .parse::<SocketAddr>()
        .map(|address| address.ip())
        .ok()
        .or_else(|| source.parse().ok())
        .or_else(|| source.strip_prefix('[')?.strip_suffix(']')?.parse().ok())?;
    Some(ip.to_canonical())
}

fn iso(time: chrono::DateTime<chrono::Utc>) -> String {
    time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

async fn nft(args: &[&str], input: Option<&str>) -> Result<Vec<u8>> {
    ensure!(
        cfg!(target_os = "linux"),
        "Native nftables plugins require Linux, nft and CAP_NET_ADMIN"
    );
    let mut child = Command::new("nft")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("Cannot start nft; install nftables and grant CAP_NET_ADMIN")?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .await?;
    } else {
        drop(child.stdin.take());
    }
    let result = timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .context("nft command timed out")??;
    ensure!(
        result.status.success(),
        "nft failed: {}",
        String::from_utf8_lossy(&result.stderr).trim()
    );
    Ok(result.stdout)
}

async fn ensure_owned(settings: &Settings) -> Result<()> {
    let tables: Value = serde_json::from_slice(&nft(&["-j", "list", "tables"], None).await?)?;
    let entries = tables["nftables"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Invalid nft table inventory"))?;
    if entries
        .iter()
        .any(|entry| entry["table"]["family"] == "inet" && entry["table"]["name"] == settings.table)
    {
        let table: Value = serde_json::from_slice(
            &nft(&["-j", "list", "table", "inet", &settings.table], None).await?,
        )?;
        ensure!(
            table["nftables"].as_array().is_some_and(|entries| entries
                .iter()
                .any(|entry| entry["table"]["comment"] == OWNER
                    && entry["table"]["name"] == settings.table)),
            "Refusing to replace an nft table not owned by remnanode-rust"
        );
    }
    Ok(())
}

async fn apply(
    plan: &Plan,
    settings: &Settings,
    blocks: &BTreeMap<IpAddr, Option<Instant>>,
) -> Result<()> {
    ensure_owned(settings).await?;
    let script = plan.render(settings, blocks);
    nft(&["--check", "--file", "-"], Some(&script)).await?;
    nft(&["--file", "-"], Some(&script)).await?;
    Ok(())
}

impl Plugins {
    pub fn whitelist(&self) -> &[IpNet] {
        &self.plan.whitelist
    }

    /// Torrent-blocker routing for the Xray config: (rule tags that also report, rule position).
    pub fn torrent_routing(&self) -> Option<(&[String], u32)> {
        self.plan
            .torrent
            .as_ref()
            .map(|t| (t.include_rule_tags.as_slice(), t.rule_position))
    }

    fn settings(&self) -> Result<Settings> {
        self.settings
            .clone()
            .map(Ok)
            .unwrap_or_else(Settings::from_env)
    }

    /// Clears plugin state and deletes the owned nft table. Collected reports are kept until fetched.
    pub async fn reset(&mut self) -> Result<()> {
        let result = match &self.settings {
            Some(settings) => {
                async {
                    ensure_owned(settings).await?;
                    nft(
                        &["--file", "-"],
                        Some(&format!("delete table inet {}\n", settings.table)),
                    )
                    .await
                    .map(drop)
                }
                .await
            }
            None => Ok(()),
        };
        self.config = None;
        self.plan = Plan::default();
        self.settings = None;
        self.blocks.clear();
        result
    }

    async fn reset_logged(&mut self) {
        if let Err(error) = self.reset().await {
            tracing::warn!(%error, "Plugin reset failed");
        }
    }

    pub async fn sync(&mut self, body: &Value) -> Result<SyncOutcome> {
        let plugin = body
            .get("plugin")
            .ok_or_else(|| anyhow::anyhow!("plugin is required"))?;
        if plugin.is_null() {
            let active = self.config.is_some();
            if active {
                self.reset_logged().await;
            }
            return Ok(SyncOutcome {
                accepted: active,
                stop_xray: active,
            });
        }
        ensure!(
            plugin["name"].is_string()
                && plugin["uuid"]
                    .as_str()
                    .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok()),
            "Invalid plugin name or UUID"
        );
        let config = plugin
            .get("config")
            .filter(|config| config.is_object())
            .ok_or_else(|| anyhow::anyhow!("plugin.config must be an object"))?;
        if self.config.as_ref() == Some(config) {
            return Ok(SyncOutcome {
                accepted: true,
                stop_xray: false,
            });
        }
        let parsed = {
            let (config, db) = (config.clone(), self.asn_db.clone());
            tokio::task::spawn_blocking(move || Plan::parse(&config, &db)).await?
        };
        let mut plan = match parsed {
            Ok(plan) => plan,
            Err(error) => {
                tracing::error!(error = %format!("{error:#}"), "Invalid plugin config; resetting plugins");
                self.reset_logged().await;
                return Ok(SyncOutcome {
                    accepted: false,
                    stop_xray: true,
                });
            }
        };
        if !self.nft_available && (plan.firewall || plan.torrent.is_some()) {
            tracing::warn!(
                "Firewall and torrent-blocker plugins need Linux, nft and CAP_NET_ADMIN; skipping them"
            );
            plan.ingress.clear();
            plan.egress.clear();
            plan.ports.clear();
            plan.firewall = false;
            plan.torrent = None;
        }
        let routing = |plan: &Plan| {
            plan.torrent
                .as_ref()
                .map(|t| (t.include_rule_tags.clone(), t.rule_position))
        };
        let restart = routing(&self.plan) != routing(&plan);
        let applied = if plan.firewall || plan.torrent.is_some() {
            match self.settings() {
                Ok(settings) => apply(&plan, &settings, &BTreeMap::new())
                    .await
                    .map(|()| self.settings = Some(settings)),
                Err(error) => Err(error),
            }
        } else if self.settings.is_some() {
            self.reset().await
        } else {
            Ok(())
        };
        if let Err(error) = applied {
            tracing::error!(error = %format!("{error:#}"), "Applying plugins failed; resetting plugins");
            self.reset_logged().await;
            return Ok(SyncOutcome {
                accepted: false,
                stop_xray: restart,
            });
        }
        // Upstream recreates its tables on every sync, which drops earlier IP blocks.
        self.blocks.clear();
        self.config = Some(config.clone());
        self.plan = plan;
        Ok(SyncOutcome {
            accepted: true,
            stop_xray: restart,
        })
    }

    pub fn collect(&mut self) -> Value {
        json!({"reports": std::mem::take(&mut self.reports)})
    }

    /// Blocks one IP in the blocked set: a single element add once the table exists.
    async fn block(&mut self, ip: IpAddr, seconds: u32) -> Result<()> {
        ensure!(
            self.nft_available,
            "nftables needs Linux, nft and CAP_NET_ADMIN"
        );
        let expiry = (seconds > 0).then(|| Instant::now() + Duration::from_secs(seconds.into()));
        let settings = self.settings()?;
        if self.settings.is_none() {
            let mut blocks = self.blocks.clone();
            blocks.insert(ip, expiry);
            apply(&self.plan, &settings, &blocks).await?;
            self.settings = Some(settings);
            self.blocks = blocks;
        } else {
            let lifetime = if seconds > 0 {
                format!(" timeout {seconds}s")
            } else {
                String::new()
            };
            nft(
                &["--file", "-"],
                Some(&block_line(&settings.table, ip, &lifetime)),
            )
            .await?;
            self.blocks.insert(ip, expiry);
        }
        Ok(())
    }

    async fn drop_connections(&self, ip: IpAddr) {
        if !crate::operations::automatic_drop_available() {
            return;
        }
        if let Err(error) =
            crate::operations::drop_ips(vec![ip.to_string()], self.whitelist()).await
        {
            tracing::warn!(%ip, %error, "Dropping connections failed");
        }
    }

    /// Handles a routing webhook from Xray (upstream XrayWebhookHandler).
    pub async fn torrent_event(&mut self, event: Value) {
        let Some(torrent) = self.plan.torrent.clone() else {
            return;
        };
        let Some(xray_report) = xray_report(&event) else {
            tracing::warn!("Invalid Xray webhook payload");
            return;
        };
        let (Some(ip), Some(user)) = (
            xray_report["source"].as_str().and_then(source_ip),
            xray_report["email"]
                .as_str()
                .filter(|user| !user.is_empty()),
        ) else {
            return;
        };
        if listed(&torrent.ignored_ips, ip) || torrent.ignored_users.contains(user) {
            return;
        }
        let blocked = match self.block(ip, torrent.duration).await {
            Ok(()) => true,
            Err(error) => {
                tracing::error!(%ip, %error, "Failed to block IP");
                false
            }
        };
        if blocked {
            self.drop_connections(ip).await;
        }
        tracing::info!(%ip, %user, blocked, duration = torrent.duration, "[TORRENT-BLOCKER]");
        let now = chrono::Utc::now();
        let report = json!({
            "actionReport": {
                "blocked": blocked,
                "ip": ip.to_string(),
                "blockDuration": torrent.duration,
                "willUnblockAt": iso(now + chrono::Duration::seconds(torrent.duration.into())),
                "userId": user,
                "processedAt": iso(now),
            },
            "xrayReport": xray_report,
        });
        if self.reports.len() < MAX_REPORTS {
            self.reports.push(report.clone());
        }
        if let Some(url) = torrent.webhook {
            tokio::spawn(async move {
                let result = async {
                    reqwest::Client::builder()
                        .timeout(Duration::from_secs(10))
                        .build()?
                        .post(url)
                        .json(&report)
                        .send()
                        .await?
                        .error_for_status()
                }
                .await;
                if let Err(error) = result {
                    tracing::warn!(%error, "Torrent-blocker webhook failed");
                }
            });
        }
    }

    pub async fn handle(&mut self, path: &str, body: &Value) -> Result<Value> {
        let mut requested: Vec<(IpAddr, u32)> = Vec::new();
        let mut unblock: Vec<IpAddr> = Vec::new();
        match path {
            "/node/plugin/nftables/block-ips" => {
                for item in array(&body["ips"], "ips")? {
                    let ip: IpAddr = item["ip"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("ip must be a string"))?
                        .parse()
                        .context("Invalid block IP")?;
                    let seconds = item["timeout"]
                        .as_f64()
                        .filter(|s| s.is_finite() && *s >= 0.0 && *s <= f64::from(u32::MAX))
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "timeout must be nonnegative seconds within uint32 range"
                            )
                        })?;
                    requested.push((ip, seconds.ceil() as u32));
                }
            }
            "/node/plugin/nftables/unblock-ips" => {
                for value in strings(&body["ips"], "ips")? {
                    unblock.push(value.parse().context("Invalid unblock IP")?);
                }
            }
            "/node/plugin/nftables/recreate-tables" => {}
            _ => bail!("Unknown plugin endpoint"),
        }
        if !self.nft_available {
            return Ok(json!({"accepted":false}));
        }
        let result: Result<()> = async {
            if path.ends_with("/block-ips") {
                for (ip, seconds) in requested {
                    self.block(ip, seconds).await?;
                    self.drop_connections(ip).await;
                }
                return Ok(());
            }
            let mut blocks = self.blocks.clone();
            let mut ingress = self.plan.ingress.clone();
            if path.ends_with("/recreate-tables") {
                blocks.clear();
            }
            for ip in unblock {
                blocks.remove(&ip);
                ingress.retain(|value| value != &ip.to_string());
            }
            blocks.retain(|_, expiry| expiry.is_none_or(|expiry| expiry > Instant::now()));
            let settings = self.settings()?;
            let plan = Plan {
                ingress,
                egress: self.plan.egress.clone(),
                ports: self.plan.ports.clone(),
                ..Default::default()
            };
            // Validate and apply the replacement before committing any in-memory mutation.
            apply(&plan, &settings, &blocks).await?;
            self.plan.ingress = plan.ingress;
            self.blocks = blocks;
            self.settings = Some(settings);
            Ok(())
        }
        .await;
        if let Err(error) = &result {
            tracing::error!(%path, error = %format!("{error:#}"), "nftables request failed");
        }
        Ok(json!({"accepted": result.is_ok()}))
    }

    pub async fn pre_start(&self) {
        #[cfg(unix)]
        if let Some(config) = &self.config
            && config.pointer("/preStart/enabled") == Some(&json!(true))
            && config.pointer("/preStart/cleanupSockets/enabled") == Some(&json!(true))
            && let Some(files) = config
                .pointer("/preStart/cleanupSockets/files")
                .and_then(Value::as_array)
        {
            use std::os::unix::fs::FileTypeExt;
            for pattern in files.iter().filter_map(Value::as_str) {
                let Ok(paths) = glob::glob(pattern.trim()) else {
                    continue;
                };
                for path in paths.take(256).flatten() {
                    if let Ok(metadata) = tokio::fs::symlink_metadata(&path).await
                        && metadata.file_type().is_socket()
                        && let Err(error) = tokio::fs::remove_file(&path).await
                    {
                        tracing::warn!(%error, "Socket cleanup failed");
                    }
                }
            }
        }
    }

    pub fn post_start(&self, metadata: Value) {
        let Some(config) = &self.config else {
            return;
        };
        if config.pointer("/postStart/enabled") != Some(&json!(true))
            || config.pointer("/postStart/webhook/enabled") != Some(&json!(true))
        {
            return;
        }
        let Some(url) = config
            .pointer("/postStart/webhook/url")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return;
        };
        tokio::spawn(async move {
            let Ok(client) = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
            else {
                return;
            };
            if let Err(error) = client.post(url).json(&json!({"scope":"service", "event":"service.core_started", "timestamp":chrono::Utc::now().to_rfc3339(), "metadata":metadata})).send().await.and_then(reqwest::Response::error_for_status) {
                tracing::warn!(%error, "Post-start webhook failed");
            }
        });
    }
}

#[cfg(test)]
pub(crate) fn enable_torrent_for_test(plugins: &mut Plugins, tags: &[&str], position: u32) {
    plugins.plan.torrent = Some(Torrent {
        duration: 60,
        ignored_ips: vec!["10.0.0.0/8".parse().unwrap()],
        ignored_users: HashSet::from(["7".to_owned()]),
        include_rule_tags: tags.iter().map(|t| t.to_string()).collect(),
        rule_position: position,
        webhook: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    const UUID: &str = "52cd4e17-ec80-4b29-b0c3-83a360e064b3";

    fn no_asn() -> PathBuf {
        "/nonexistent/asn.json".into()
    }

    #[tokio::test]
    async fn invalid_config_is_rejected_and_stops_xray_like_upstream() {
        let mut state = Plugins {
            nft_available: false,
            ..Default::default()
        };
        let outcome = state
            .sync(&json!({"plugin":{"name":"t","uuid":UUID,"config":{"torrentBlocker":{"enabled":true}}}}))
            .await
            .unwrap();
        assert!(!outcome.accepted && outcome.stop_xray);
        let outcome = state.sync(&json!({"plugin":null})).await.unwrap();
        assert!(!outcome.accepted && !outcome.stop_xray);
        assert!(
            state
                .sync(&json!({"plugin":{"name":"t","uuid":"nope","config":{}}}))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn firewall_plugins_are_skipped_without_net_admin() {
        let mut state = Plugins {
            nft_available: false,
            ..Default::default()
        };
        let outcome = state
            .sync(&json!({"plugin":{"name":"t","uuid":UUID,"config":{
                "torrentBlocker":{"enabled":true,"blockDuration":60,"ignoreLists":{}},
                "ingressFilter":{"enabled":true,"blockedIps":["192.0.2.1"]}
            }}}))
            .await
            .unwrap();
        assert!(outcome.accepted && !outcome.stop_xray);
        assert!(state.torrent_routing().is_none());
        assert_eq!(
            state
                .handle("/node/plugin/nftables/recreate-tables", &json!({}))
                .await
                .unwrap(),
            json!({"accepted":false})
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn cleanup_removes_sockets_only() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let regular = dir.path().join("regular");
        let link = dir.path().join("link");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::write(&regular, "keep me").unwrap();
        std::os::unix::fs::symlink(&socket, &link).unwrap();
        let mut plugins = Plugins::default();
        plugins.sync(&json!({"plugin":{"name":"test","uuid":UUID,"config":{"preStart":{"enabled":true,"cleanupSockets":{"enabled":true,"files":[socket,regular,link]}}}}})).await.unwrap();
        plugins.pre_start().await;
        assert!(!socket.exists());
        assert_eq!(std::fs::read_to_string(&regular).unwrap(), "keep me");
        assert!(
            std::fs::symlink_metadata(link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn plans_filters_and_shared_lists_without_shell_text() {
        let plan = Plan::parse(&json!({
            "sharedLists":[{"name":"ext:test","type":"ipList","items":["10.2.3.4/8","2001:db8::/32","198.51.100.0/24"]}],
            "ingressFilter":{"enabled":true,"blockedIps":["ext:test"]},
            "egressFilter":{"enabled":true,"blockedIps":["192.0.2.8"],"blockedPorts":[25,443]},
            "connectionDrop":{"enabled":true,"whitelistIps":["192.0.2.1","ext:test"]}
        }), &no_asn()).unwrap();
        assert!(listed(&plan.whitelist, "192.0.2.1".parse().unwrap()));
        assert!(listed(&plan.whitelist, "198.51.100.77".parse().unwrap()));
        assert!(!listed(&plan.whitelist, "192.0.2.2".parse().unwrap()));
        let script = plan.render(
            &Settings::new("remnanode_rust", true, true).unwrap(),
            &Default::default(),
        );
        assert!(
            script.starts_with("add table inet remnanode_rust\n"),
            "nft rejects quoted table names"
        );
        assert!(script.contains("10.0.0.0/8"));
        assert!(script.contains("2001:db8::/32"));
        assert!(script.contains("hook forward priority -10"));
        assert!(script.contains("ct direction reply accept"));
        assert!(script.contains("tcp dport @egress_ports"));
        assert!(script.contains("udp dport @egress_ports"));
        assert!(!script.contains("flush ruleset"));
    }

    #[test]
    fn default_ignored_addresses_match_upstream() {
        for ip in [
            "127.0.0.1",
            "127.8.9.10",
            "::1",
            "0.0.0.0",
            "::",
            "255.255.255.255",
            "::ffff:127.0.0.1",
        ] {
            assert!(listed(&[], ip.parse().unwrap()), "{ip}");
        }
        assert!(!listed(&[], "192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn asn_lists_resolve_from_streamed_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("asn.json");
        std::fs::write(&db, r#"{"1":{"ipv4":["192.0.2.0/24"],"ipv6":[]},"13335":{"ipv4":["1.1.1.0/24"],"ipv6":["2606:4700::/32"]},"x":{"ignored":true}}"#).unwrap();
        let plan = Plan::parse(
            &json!({
                "sharedLists":[{"name":"ext:cf","type":"asList","items":[13335, 99999]}],
                "ingressFilter":{"enabled":true,"blockedIps":["ext:cf"]},
                "connectionDrop":{"enabled":true,"whitelistIps":["ext:cf"]}
            }),
            &db,
        )
        .unwrap();
        assert_eq!(plan.ingress, vec!["1.1.1.0/24", "2606:4700::/32"]);
        assert!(listed(&plan.whitelist, "1.1.1.1".parse().unwrap()));
        // A missing database matches upstream: lookups are disabled, nothing is blocked.
        let plan = Plan::parse(
            &json!({
                "sharedLists":[{"name":"ext:cf","type":"asList","items":[13335]}],
                "ingressFilter":{"enabled":true,"blockedIps":["ext:cf"]}
            }),
            &no_asn(),
        )
        .unwrap();
        assert!(plan.ingress.is_empty());
    }

    #[test]
    fn torrent_config_matches_upstream_schema() {
        let plan = Plan::parse(&json!({
            "sharedLists":[{"name":"ext:office","type":"ipList","items":["203.0.113.0/24"]}],
            "torrentBlocker":{"enabled":true,"blockDuration":3600,"ignoreLists":{"ip":["192.0.2.9","ext:office"],"userId":[42]},
                "includeRuleTags":["b","a"],"rulePlacement":3,"webhookUrl":"https://example.com/hook"}
        }), &no_asn()).unwrap();
        let torrent = plan.torrent.unwrap();
        assert_eq!(torrent.duration, 3600);
        assert_eq!(torrent.include_rule_tags, vec!["a", "b"]);
        assert_eq!(torrent.rule_position, 3);
        assert!(torrent.ignored_users.contains("42"));
        assert!(listed(
            &torrent.ignored_ips,
            "203.0.113.50".parse().unwrap()
        ));
        for bad in [
            json!({"enabled":true,"ignoreLists":{}}),
            json!({"enabled":true,"blockDuration":-1,"ignoreLists":{}}),
            json!({"enabled":true,"blockDuration":5,"ignoreLists":{},"includeRuleTags":[]}),
            json!({"enabled":true,"blockDuration":5,"ignoreLists":{},"rulePlacement":1001}),
            json!({"enabled":true,"blockDuration":5,"ignoreLists":{},"webhookUrl":"ftp://x"}),
        ] {
            assert!(
                Plan::parse(&json!({"torrentBlocker":bad}), &no_asn()).is_err(),
                "{bad}"
            );
        }
        let disabled = Plan::parse(
            &json!({"torrentBlocker":{"enabled":false,"blockDuration":5,"ignoreLists":{}}}),
            &no_asn(),
        )
        .unwrap();
        assert!(disabled.torrent.is_none());
    }

    #[tokio::test]
    async fn torrent_event_reports_ignores_and_flushes() {
        let mut plugins = Plugins {
            nft_available: false,
            ..Default::default()
        };
        enable_torrent_for_test(&mut plugins, &[], 0);
        let event = |email: &str, source: &str| {
            json!({"email":email,"level":0,"protocol":"bittorrent","network":"tcp",
            "source":source,"destination":"198.51.100.1:6881","routeTarget":null,"originalTarget":null,"inboundTag":"vless",
            "inboundName":null,"inboundLocal":null,"outboundTag":TORRENT_OUTBOUND,"ts":1,"extra":"dropped"})
        };
        plugins.torrent_event(event("7", "192.0.2.1:5000")).await; // ignored user
        plugins.torrent_event(event("8", "10.1.2.3:5000")).await; // ignored CIDR
        plugins.torrent_event(event("8", "127.0.0.1:5000")).await; // default ignored
        plugins.torrent_event(json!({"email":"8"})).await; // invalid schema
        plugins
            .torrent_event(event("8", "tcp:[2001:db8::5]:5000"))
            .await;
        let reports = plugins.collect()["reports"].as_array().unwrap().clone();
        assert_eq!(reports.len(), 1);
        let action = &reports[0]["actionReport"];
        assert_eq!(action["ip"], "2001:db8::5");
        assert_eq!(action["userId"], "8");
        assert_eq!(action["blockDuration"], 60);
        assert!(action["blocked"].is_boolean());
        assert!(action["willUnblockAt"].as_str().unwrap().ends_with('Z'));
        assert!(reports[0]["xrayReport"].get("extra").is_none());
        assert_eq!(plugins.collect(), json!({"reports":[]}));
    }

    #[test]
    fn source_addresses_parse_like_upstream_regex() {
        for (source, ip) in [
            ("1.2.3.4:80", "1.2.3.4"),
            ("udp:1.2.3.4:80", "1.2.3.4"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
            ("[::ffff:1.2.3.4]:1", "1.2.3.4"),
        ] {
            assert_eq!(source_ip(source), Some(ip.parse().unwrap()), "{source}");
        }
        assert_eq!(source_ip("example.com:80"), None);
    }

    #[test]
    fn rejects_invalid_ips_ports_and_nft_identifiers_before_changes() {
        assert!(Settings::new("table; flush ruleset", true, false).is_err());
        assert!(Settings::new("-bad", true, false).is_err());
        let parse = |config: Value| Plan::parse(&config, &no_asn());
        assert!(
            parse(
                json!({"ingressFilter":{"enabled":true,"blockedIps":["1.2.3.4; flush ruleset"]}})
            )
            .is_err()
        );
        assert!(parse(json!({"egressFilter":{"enabled":true,"blockedPorts":[65536]}})).is_err());
        assert!(
            parse(json!({"connectionDrop":{"enabled":true,"whitelistIps":["10.0.0.0/8"]}})).is_ok()
        );
        assert!(
            parse(json!({"ingressFilter":{"enabled":true,"blockedIps":["ext:missing"]}})).is_ok()
        );
        assert!(
            parse(json!({"sharedLists":[{"name":"ext:a","type":"asList","items":[0]}]})).is_err()
        );
    }

    /// Set NFT_TESTS=1 to run real nft; needs Linux, nftables and CAP_NET_ADMIN (e.g. --cap-add NET_ADMIN).
    #[tokio::test]
    async fn real_nftables_lifecycle() {
        if std::env::var_os("NFT_TESTS").is_none() {
            return;
        }
        let list = || async {
            String::from_utf8(
                nft(&["list", "table", "inet", "remnanode_rust_test"], None)
                    .await
                    .unwrap(),
            )
            .unwrap()
        };
        let mut plugins = Plugins::default();
        assert!(plugins.nft_available, "CAP_NET_ADMIN missing");
        plugins.settings = Some(Settings::new("remnanode_rust_test", true, false).unwrap());
        let outcome = plugins
            .sync(&json!({"plugin":{"name":"t","uuid":UUID,"config":{
                "sharedLists":[{"name":"ext:x","type":"ipList","items":["198.51.100.0/24"]}],
                "ingressFilter":{"enabled":true,"blockedIps":["ext:x","192.0.2.10"]},
                "egressFilter":{"enabled":true,"blockedPorts":[25]},
                "torrentBlocker":{"enabled":true,"blockDuration":120,"ignoreLists":{}}
            }}}))
            .await
            .unwrap();
        assert!(outcome.accepted && outcome.stop_xray);
        let table = list().await;
        assert!(
            table.contains("198.51.100.0/24")
                && table.contains("192.0.2.10")
                && table.contains("25"),
            "{table}"
        );
        plugins.torrent_event(json!({"email":"9","network":"tcp","source":"203.0.113.7:1","destination":"x:1","ts":1})).await;
        assert!(list().await.contains("203.0.113.7 timeout"));
        assert_eq!(
            plugins.collect()["reports"][0]["actionReport"]["blocked"],
            true
        );
        let accepted = plugins
            .handle(
                "/node/plugin/nftables/block-ips",
                &json!({"ips":[{"ip":"2001:db8::9","timeout":0}]}),
            )
            .await
            .unwrap();
        assert_eq!(accepted, json!({"accepted":true}));
        assert!(list().await.contains("2001:db8::9"));
        plugins
            .handle(
                "/node/plugin/nftables/unblock-ips",
                &json!({"ips":["203.0.113.7","192.0.2.10"]}),
            )
            .await
            .unwrap();
        let table = list().await;
        assert!(
            !table.contains("203.0.113.7")
                && !table.contains("192.0.2.10")
                && table.contains("2001:db8::9"),
            "{table}"
        );
        plugins.reset().await.unwrap();
        assert!(
            nft(&["list", "table", "inet", "remnanode_rust_test"], None)
                .await
                .is_err()
        );
    }
}

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

const OWNER: &str = "remnanode-rust managed";

#[derive(Default)]
pub struct Plugins {
    config: Option<Value>,
    plan: Plan,
    settings: Option<Settings>,
    blocks: BTreeMap<IpAddr, Option<Instant>>,
}

#[derive(Default)]
struct Plan {
    ingress: Vec<String>,
    egress: Vec<String>,
    ports: Vec<u16>,
    whitelist: HashSet<IpAddr>,
    firewall: bool,
}

#[derive(Clone)]
struct Settings {
    table: String,
    logging: bool,
    replies: bool,
}

impl Settings {
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

fn address(value: &str, cidr: bool) -> Result<String> {
    if let Some((ip, prefix)) = value.split_once('/') {
        ensure!(
            cidr,
            "CIDR ranges are not supported in connection-drop whitelists"
        );
        let ip: IpAddr = ip.parse().context("Invalid IP/CIDR address")?;
        let prefix: u8 = prefix.parse().context("Invalid CIDR prefix")?;
        return match ip {
            IpAddr::V4(ip) => {
                ensure!(prefix <= 32, "Invalid IPv4 CIDR prefix");
                let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
                Ok(format!(
                    "{}/{prefix}",
                    std::net::Ipv4Addr::from(u32::from(ip) & mask)
                ))
            }
            IpAddr::V6(ip) => {
                ensure!(prefix <= 128, "Invalid IPv6 CIDR prefix");
                let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
                Ok(format!(
                    "{}/{prefix}",
                    std::net::Ipv6Addr::from(u128::from(ip) & mask)
                ))
            }
        };
    }
    Ok(value
        .parse::<IpAddr>()
        .context("Invalid IP address")?
        .to_string())
}

impl Plan {
    fn parse(config: &Value) -> Result<Self> {
        ensure!(config.is_object(), "plugin.config must be an object");
        let mut shared = HashMap::new();
        if let Some(lists) = config.get("sharedLists") {
            for list in array(lists, "sharedLists")? {
                let name = list["name"]
                    .as_str()
                    .filter(|name| name.starts_with("ext:"))
                    .ok_or_else(|| anyhow::anyhow!("Shared list names must start with ext:"))?;
                let items = match list["type"].as_str() {
                    Some("ipList") => Some(
                        strings(&list["items"], "shared list items")?
                            .iter()
                            .map(|ip| address(ip, true))
                            .collect::<Result<Vec<_>>>()?,
                    ),
                    Some("asList") => {
                        for asn in array(&list["items"], "ASN list items")? {
                            ensure!(
                                asn.as_u64()
                                    .is_some_and(|asn| (1..=u64::from(u32::MAX)).contains(&asn)),
                                "Invalid ASN number"
                            );
                        }
                        None
                    }
                    _ => bail!("Unknown shared list type"),
                };
                ensure!(
                    shared.insert(name.to_owned(), items).is_none(),
                    "Duplicate shared list: {name}"
                );
            }
        }
        let resolve =
            |feature: &Value, key: &str, cidr: bool, required: bool| -> Result<Vec<String>> {
                let Some(items) = feature.get(key) else {
                    ensure!(!required, "{key} is required");
                    return Ok(Vec::new());
                };
                let mut result = Vec::new();
                for item in strings(items, key)? {
                    if item.starts_with("ext:") {
                        let list = shared
                            .get(&item)
                            .ok_or_else(|| anyhow::anyhow!("Shared list not found: {item}"))?
                            .as_ref()
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "ASN shared lists are not supported by this build: {item}"
                                )
                            })?;
                        for ip in list {
                            result.push(address(ip, cidr)?);
                        }
                    } else {
                        result.push(address(&item, cidr)?);
                    }
                }
                result.sort();
                result.dedup();
                Ok(result)
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
                "torrentBlocker" => ensure!(
                    !enabled,
                    "Torrent blocker is not supported: Xray routing/webhook integration is not implemented"
                ),
                "connectionDrop" => {
                    if enabled {
                        plan.whitelist = resolve(feature, "whitelistIps", false, true)?
                            .iter()
                            .map(|ip| ip.parse().context("Invalid whitelist IP"))
                            .collect::<Result<_>>()?;
                    } else if let Some(items) = feature.get("whitelistIps") {
                        strings(items, "whitelistIps")?;
                    }
                }
                "ingressFilter" => {
                    if enabled {
                        plan.ingress = resolve(feature, "blockedIps", true, true)?;
                        plan.firewall = true;
                    } else if let Some(items) = feature.get("blockedIps") {
                        strings(items, "blockedIps")?;
                    }
                }
                "egressFilter" => {
                    if enabled {
                        plan.egress = resolve(feature, "blockedIps", true, false)?;
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
        let table = format!("inet \"{}\"", settings.table);
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
            let suffix = if ip.is_ipv4() { "4" } else { "6" };
            let lifetime = match expiry {
                None => String::new(),
                Some(expiry) => match expiry.checked_duration_since(now) {
                    Some(remaining) if !remaining.is_zero() => {
                        format!(" timeout {}ms", remaining.as_millis().max(1))
                    }
                    _ => continue,
                },
            };
            script.push_str(&format!(
                "add element {table} blocked{suffix} {{ {ip}{lifetime} }}\n"
            ));
        }
        script
    }
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
    pub fn whitelist(&self) -> &HashSet<IpAddr> {
        &self.plan.whitelist
    }

    pub async fn reset(&mut self) -> Result<()> {
        if let Some(settings) = &self.settings {
            ensure_owned(settings).await?;
            nft(
                &["--file", "-"],
                Some(&format!("delete table inet \"{}\"\n", settings.table)),
            )
            .await?;
        }
        *self = Self::default();
        Ok(())
    }

    pub async fn sync(&mut self, body: &Value) -> Result<Value> {
        let plugin = body
            .get("plugin")
            .ok_or_else(|| anyhow::anyhow!("plugin is required"))?;
        if plugin.is_null() {
            let accepted = self.config.is_some();
            if accepted {
                self.reset().await?;
            }
            return Ok(json!({"accepted":accepted}));
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
            .ok_or_else(|| anyhow::anyhow!("plugin.config is required"))?;
        let plan = Plan::parse(config)?;
        if self.config.as_ref() == Some(config) {
            return Ok(json!({"accepted":true}));
        }
        if plan.firewall {
            let settings = self
                .settings
                .clone()
                .map(Ok)
                .unwrap_or_else(Settings::from_env)?;
            apply(&plan, &settings, &BTreeMap::new()).await?;
            self.settings = Some(settings);
        } else if self.settings.is_some() {
            self.reset().await?;
        }
        self.blocks.clear();
        self.config = Some(config.clone());
        self.plan = plan;
        Ok(json!({"accepted":true}))
    }

    pub async fn handle(&mut self, path: &str, body: &Value) -> Result<Value> {
        if path.ends_with("/sync") {
            return self.sync(body).await;
        }
        if path.ends_with("/torrent-blocker/collect") {
            return Ok(json!({"reports":[]}));
        }
        let mut blocks = self.blocks.clone();
        blocks.retain(|_, expiry| expiry.is_none_or(|expiry| expiry > Instant::now()));
        let mut ingress = self.plan.ingress.clone();
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
                        .filter(|seconds| {
                            seconds.is_finite()
                                && *seconds >= 0.0
                                && *seconds <= f64::from(u32::MAX)
                        })
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "timeout must be nonnegative seconds within uint32 range"
                            )
                        })?;
                    let expiry = if seconds == 0.0 {
                        None
                    } else {
                        Some(
                            Instant::now()
                                .checked_add(Duration::from_secs_f64(seconds))
                                .ok_or_else(|| anyhow::anyhow!("IP block timeout is too large"))?,
                        )
                    };
                    blocks.insert(ip, expiry);
                }
            }
            "/node/plugin/nftables/unblock-ips" => {
                for value in strings(&body["ips"], "ips")? {
                    let ip: IpAddr = value.parse().context("Invalid unblock IP")?;
                    blocks.remove(&ip);
                    ingress.retain(|value| value != &ip.to_string());
                }
            }
            "/node/plugin/nftables/recreate-tables" => {
                blocks.clear();
            }
            _ => bail!("Unknown plugin endpoint"),
        }
        let settings = self
            .settings
            .clone()
            .map(Ok)
            .unwrap_or_else(Settings::from_env)?;
        // Validate and apply the replacement before committing any in-memory mutation.
        let plan = Plan {
            ingress,
            egress: self.plan.egress.clone(),
            ports: self.plan.ports.clone(),
            ..Default::default()
        };
        apply(&plan, &settings, &blocks).await?;
        self.plan.ingress = plan.ingress;
        self.blocks = blocks;
        self.settings = Some(settings);
        Ok(json!({"accepted":true}))
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
mod tests {
    use super::*;
    #[tokio::test]
    async fn unsupported_plugins_cannot_report_success() {
        let mut state = Plugins::default();
        assert!(state.sync(&json!({"plugin":{"name":"test","uuid":"52cd4e17-ec80-4b29-b0c3-83a360e064b3","config":{"torrentBlocker":{"enabled":true}}}})).await.is_err());
        assert_eq!(
            state.sync(&json!({"plugin":null})).await.unwrap()["accepted"],
            false
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
        plugins.sync(&json!({"plugin":{"name":"test","uuid":"52cd4e17-ec80-4b29-b0c3-83a360e064b3","config":{"preStart":{"enabled":true,"cleanupSockets":{"enabled":true,"files":[socket,regular,link]}}}}})).await.unwrap();
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
}

#[cfg(test)]
mod native_tests {
    use super::*;

    #[test]
    fn plans_filters_and_shared_lists_without_shell_text() {
        let plan = Plan::parse(&json!({
            "sharedLists":[{"name":"ext:test","type":"ipList","items":["10.2.3.4/8","2001:db8::/32"]}],
            "ingressFilter":{"enabled":true,"blockedIps":["ext:test"]},
            "egressFilter":{"enabled":true,"blockedIps":["192.0.2.8"],"blockedPorts":[25,443]},
            "connectionDrop":{"enabled":true,"whitelistIps":["192.0.2.1"]}
        })).unwrap();
        assert!(plan.whitelist.contains(&"192.0.2.1".parse().unwrap()));
        let script = plan.render(
            &Settings::new("remnanode_rust", true, true).unwrap(),
            &Default::default(),
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
    fn rejects_invalid_ips_ports_and_nft_identifiers_before_changes() {
        assert!(Settings::new("table; flush ruleset", true, false).is_err());
        assert!(Settings::new("-bad", true, false).is_err());
        assert!(
            Plan::parse(
                &json!({"ingressFilter":{"enabled":true,"blockedIps":["1.2.3.4; flush ruleset"]}})
            )
            .is_err()
        );
        assert!(
            Plan::parse(&json!({"egressFilter":{"enabled":true,"blockedPorts":[65536]}})).is_err()
        );
        assert!(
            Plan::parse(&json!({"connectionDrop":{"enabled":true,"whitelistIps":["10.0.0.0/8"]}}))
                .is_err()
        );
        assert!(
            Plan::parse(&json!({"ingressFilter":{"enabled":true,"blockedIps":["ext:missing"]}}))
                .is_err()
        );
        assert!(Plan::parse(&json!({"sharedLists":[{"name":"ext:a","type":"asList","items":[13335]}],"ingressFilter":{"enabled":true,"blockedIps":["ext:a"]}})).is_err());
        assert!(
            Plan::parse(&json!({"sharedLists":[{"name":"ext:a","type":"asList","items":[13335]}]}))
                .is_ok()
        );
    }
}

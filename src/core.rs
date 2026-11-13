use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use sysinfo::{CpuRefreshKind, Networks, System};
use tokio::{
    process::{Child, Command},
    time::{Instant, sleep, timeout},
};

use crate::{
    grpc::Grpc,
    plugins::{Plugins, TORRENT_OUTBOUND},
};

const API_TAG: &str = "REMNAWAVE_API";
const API_INBOUND: &str = "REMNAWAVE_API_INBOUND";

pub struct Core {
    pub endpoint: String,
    pub inbounds: HashMap<String, HashSet<String>>,
    pub inbound_ciphers: HashMap<String, i32>,
    binary: PathBuf,
    state_dir: PathBuf,
    child: Option<Child>,
    version: Option<String>,
    empty_config_hash: Option<String>,
    webhook_token: String,
}

impl Core {
    pub fn new(binary: PathBuf, state_dir: PathBuf, endpoint: String) -> Self {
        let mut token = [0u8; 24];
        fs::File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut token))
            .expect("read /dev/urandom");
        Self {
            endpoint,
            inbounds: HashMap::new(),
            inbound_ciphers: HashMap::new(),
            binary,
            // Xray only treats absolute paths as unix-socket webhook targets.
            state_dir: std::path::absolute(&state_dir).unwrap_or(state_dir),
            child: None,
            version: None,
            empty_config_hash: None,
            webhook_token: token.iter().map(|b| format!("{b:02x}")).collect(),
        }
    }

    /// Private unix socket where Xray posts routing webhooks (torrent blocker).
    pub fn webhook_socket(&self) -> PathBuf {
        self.state_dir.join("internal.sock")
    }

    pub fn webhook_token(&self) -> &str {
        &self.webhook_token
    }

    /// Creates the private state directory and binds the webhook socket inside it.
    pub fn bind_webhook(&self) -> Result<tokio::net::UnixListener> {
        private_directory(&self.state_dir)?;
        let socket = self.webhook_socket();
        match fs::remove_file(&socket) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error)?,
            _ => {}
        }
        tokio::net::UnixListener::bind(&socket).context("bind internal webhook socket")
    }

    fn webhook_url(&self) -> String {
        format!(
            "{}:/internal/webhook?token={}",
            self.webhook_socket().display(),
            self.webhook_token
        )
    }

    pub async fn start(&mut self, body: &Value) -> Result<Value> {
        self.start_response(body, None).await
    }

    pub async fn start_with_plugins(&mut self, body: &Value, plugins: &Plugins) -> Result<Value> {
        self.start_response(body, Some(plugins)).await
    }

    async fn start_response(&mut self, body: &Value, plugins: Option<&Plugins>) -> Result<Value> {
        let result = self.start_inner(body, plugins).await;
        if let Err(error) = &result {
            tracing::warn!(binary=%self.binary.display(),endpoint=%self.endpoint,error=%format!("{error:#}"),"Core start failed");
        }
        Ok(json!({
            "isStarted": result.is_ok(), "version": self.version,
            "error": result.err().map(|e| format!("{e:#}")),
            "nodeInformation":{"version":crate::upstream_version()},
            "system":{"info":system_info(), "stats":system_stats(), "interface":interface_stats()}
        }))
    }

    async fn start_inner(&mut self, body: &Value, plugins: Option<&Plugins>) -> Result<()> {
        let source = body.get("xrayConfig").context("xrayConfig is required")?;
        ensure!(source.is_object(), "xrayConfig must be an object");
        let internals = body.get("internals").context("internals is required")?;
        ensure!(internals.is_object(), "internals must be an object");
        // Upstream 3.4.5 ships no integration modules, so integration configs are accepted and ignored.
        ensure!(
            internals.get("integrations").is_none_or(Value::is_object),
            "internals.integrations must be an object"
        );
        validate_internals(internals)?;
        validate_geodata(source.get("geodata"))?;
        let torrent = plugins.and_then(Plugins::torrent_routing);
        let config = api_config(source, &self.endpoint, torrent, &self.webhook_url())?;
        let force = internals
            .get("forceRestart")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let disable_hashes = std::env::var("DISABLE_HASHED_SET_CHECK").is_ok_and(|v| v == "true");
        if !force
            && !disable_hashes
            && !self.needs_restart(&internals["hashes"])
            && self.is_ready().await
        {
            return Ok(());
        }

        let (binary, assets_dir) = self.prepare_geodata(source.get("geodata")).await?;
        let stage = stage_config(&self.state_dir, &config)?;
        self.validate(&binary, &stage.path, &assets_dir).await?;
        let config_path = self.state_dir.join("config.json");
        fs::rename(&stage.path, &config_path).context("replace Xray config")?;
        self.stop_child().await?;
        if let Some(plugins) = plugins {
            plugins.pre_start().await;
        }
        self.inbounds.clear();
        self.inbound_ciphers.clear();
        self.empty_config_hash = None;
        self.child = Some(
            Command::new(&binary)
                .env("XRAY_LOCATION_ASSET", &assets_dir)
                .args(["run", "-config"])
                .arg(&config_path)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .context("spawn Xray")?,
        );

        let ready = self.wait_ready().await;
        if let Err(error) = ready {
            self.stop_child()
                .await
                .context("clean up failed Xray start")?;
            return Err(error);
        }
        self.version = read_version(&binary).await;
        tracing::info!(binary=%binary.display(),endpoint=%self.endpoint,pid=?self.child.as_ref().and_then(Child::id),version=?self.version,"Core started and gRPC is ready");
        self.empty_config_hash = internals["hashes"]["emptyConfig"]
            .as_str()
            .map(str::to_owned);
        let tags: HashSet<&str> = internals["hashes"]["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry["tag"].as_str())
            .collect();
        if let Some(inbounds) = source["inbounds"].as_array() {
            for inbound in inbounds {
                if inbound["protocol"] == "shadowsocks"
                    && let Some(tag) = inbound["tag"].as_str()
                    && let Some(cipher) = match inbound["settings"]["method"].as_str() {
                        Some("aes-128-gcm") => Some(5),
                        Some("aes-256-gcm") => Some(6),
                        Some("chacha20-poly1305") => Some(7),
                        Some("xchacha20-poly1305") => Some(8),
                        _ => None,
                    }
                {
                    self.inbound_ciphers.insert(tag.to_owned(), cipher);
                }
                if let Some(tag) = inbound["tag"].as_str().filter(|tag| tags.contains(tag)) {
                    let clients = inbound["settings"]["clients"].as_array();
                    let users = clients
                        .into_iter()
                        .flatten()
                        .filter_map(|c| c["id"].as_str())
                        .map(str::to_owned)
                        .collect();
                    self.inbounds.insert(tag.to_owned(), users);
                }
            }
        }
        if let Some(plugins) = plugins {
            plugins.post_start(
                internals
                    .get("metadata")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            );
        }
        Ok(())
    }

    fn needs_restart(&self, hashes: &Value) -> bool {
        let Some(empty) = self.empty_config_hash.as_deref() else {
            return true;
        };
        if hashes["emptyConfig"].as_str() != Some(empty) {
            return true;
        }
        let Some(inbounds) = hashes["inbounds"].as_array() else {
            return true;
        };
        if inbounds.len() != self.inbounds.len() {
            return true;
        }
        let mut seen = HashSet::new();
        for inbound in inbounds {
            let Some(tag) = inbound["tag"].as_str() else {
                return true;
            };
            let Some(users) = self.inbounds.get(tag) else {
                return true;
            };
            if !seen.insert(tag) || inbound["hash"].as_str() != Some(&user_set_hash(users)) {
                return true;
            }
        }
        false
    }

    async fn validate(&self, binary: &Path, config: &Path, assets_dir: &Path) -> Result<()> {
        let output = timeout(
            Duration::from_secs(15),
            Command::new(binary)
                .env("XRAY_LOCATION_ASSET", assets_dir)
                .args(["run", "-test", "-config"])
                .arg(config)
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .context("Xray config validation timed out")?
        .context("run Xray config validation")?;
        if !output.status.success() {
            let message = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            bail!(
                "Xray config validation failed ({}): {}",
                output.status,
                message.chars().take(2000).collect::<String>().trim()
            );
        }
        Ok(())
    }

    async fn prepare_geodata(&self, geodata: Option<&Value>) -> Result<(PathBuf, PathBuf)> {
        let assets_dir = std::env::var_os("XRAY_LOCATION_ASSET")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/usr/local/share/xray"));
        let mut binary = self.binary.clone();
        if let Some(core) = geodata.and_then(|value| value.get("core")) {
            private_directory(&self.state_dir)?;
            let custom = self.state_dir.join("custom-core");
            let expected = core["sha256"].as_str().unwrap().to_ascii_lowercase();
            if !verified_file(&custom, &expected)? {
                download(
                    core["url"].as_str().unwrap(),
                    &custom,
                    Some(&expected),
                    true,
                )
                .await?;
            }
            ensure!(
                read_version(&custom).await.is_some(),
                "Downloaded custom core did not report a version"
            );
            binary = custom;
        }
        if let Some(assets) = geodata
            .and_then(|value| value.get("assets"))
            .and_then(Value::as_array)
        {
            if !assets.is_empty() {
                fs::create_dir_all(&assets_dir).context("create Xray asset directory")?;
                ensure!(
                    fs::symlink_metadata(&assets_dir)?.file_type().is_dir(),
                    "Xray asset directory must not be a symlink"
                );
            }
            for asset in assets {
                let target = assets_dir.join(asset["file"].as_str().unwrap());
                match fs::symlink_metadata(&target) {
                    Ok(metadata) => {
                        ensure!(
                            metadata.file_type().is_file(),
                            "Xray asset must be a regular file"
                        );
                        if metadata.len() > 0 {
                            continue;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error).context("inspect Xray asset"),
                }
                // Failed downloads leave existing assets intact; an empty geodata stub cannot work.
                download(asset["url"].as_str().unwrap(), &target, None, false).await?;
            }
        }
        Ok((binary, assets_dir))
    }

    async fn process_alive(&mut self) -> Result<bool> {
        let Some(child) = self.child.as_mut() else {
            return Ok(false);
        };
        if child.try_wait().context("poll Xray process")?.is_some() {
            self.child = None;
            self.inbounds.clear();
            self.inbound_ciphers.clear();
            self.empty_config_hash = None;
            return Ok(false);
        }
        Ok(true)
    }

    async fn is_ready(&mut self) -> bool {
        if !self.process_alive().await.unwrap_or(false) {
            return false;
        }
        timeout(Duration::from_secs(2), async {
            Grpc::connect(&self.endpoint).await?.sys_stats().await
        })
        .await
        .is_ok_and(|result| result.is_ok())
    }

    async fn wait_ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            ensure!(
                self.process_alive().await?,
                "Xray process exited before its API became ready"
            );
            if self.is_ready().await {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "Xray API did not become ready in time"
            );
            sleep(Duration::from_millis(100)).await;
        }
    }

    async fn stop_child(&mut self) -> Result<()> {
        if let Some(child) = self.child.as_mut()
            && child.try_wait().context("poll Xray before stop")?.is_none()
        {
            child.start_kill().context("kill Xray")?;
            child.wait().await.context("reap Xray")?;
        }
        self.child = None;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<Value> {
        self.stop_child().await?;
        self.inbounds.clear();
        self.inbound_ciphers.clear();
        self.empty_config_hash = None;
        Ok(json!({"isStopped":true}))
    }

    pub async fn health(&mut self) -> Value {
        let ready = self.is_ready().await;
        json!({"isAlive":true,"xrayInternalStatusCached":ready,"xrayVersion":self.version,"nodeVersion":crate::upstream_version()})
    }
}

fn api_config(
    config: &Value,
    endpoint: &str,
    torrent: Option<(&[String], u32)>,
    webhook: &str,
) -> Result<Value> {
    let url = reqwest::Url::parse(endpoint).context("invalid Xray API endpoint")?;
    let address = url
        .host_str()
        .context("Xray API endpoint needs a host")?
        .trim_matches(['[', ']']);
    let ip: IpAddr = address
        .parse()
        .context("Xray API endpoint must be a loopback IP")?;
    ensure!(
        url.scheme() == "http"
            && ip.is_loopback()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "Xray API endpoint must be a plain HTTP loopback address"
    );
    let port = url
        .port()
        .context("Xray API endpoint needs an explicit port")?;
    ensure!(port != 0, "Xray API port must be nonzero");
    ensure!(config.is_object(), "xrayConfig must be an object");
    let mut config = config.clone();
    for name in ["inbounds", "outbounds"] {
        ensure!(
            config.get(name).is_none_or(Value::is_array),
            "{name} must be an array"
        );
    }
    for name in ["policy", "routing"] {
        ensure!(
            config.get(name).is_none_or(Value::is_object),
            "{name} must be an object"
        );
    }
    for field in ["levels", "system"] {
        ensure!(
            config["policy"].get(field).is_none_or(Value::is_object),
            "policy.{field} must be an object"
        );
    }
    ensure!(
        config["policy"]["levels"]
            .get("0")
            .is_none_or(Value::is_object),
        "policy.levels.0 must be an object"
    );
    ensure!(
        config["routing"].get("rules").is_none_or(Value::is_array),
        "routing.rules must be an array"
    );
    let mut inbounds = config["inbounds"].as_array().cloned().unwrap_or_default();
    ensure!(
        !inbounds
            .iter()
            .any(|v| v["tag"] == API_INBOUND || v["tag"] == API_TAG),
        "reserved Xray API inbound tag"
    );
    ensure!(
        !config["outbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|v| v["tag"] == API_TAG),
        "reserved Xray API outbound tag"
    );
    inbounds.insert(0, json!({"tag":API_INBOUND,"listen":ip.to_string(),"port":port,"protocol":"dokodemo-door","settings":{"address":ip.to_string()}}));
    config["inbounds"] = Value::Array(inbounds);
    config["stats"] = json!({});
    config["api"] =
        json!({"tag":API_TAG,"services":["HandlerService","StatsService","RoutingService"]});
    if config.get("policy").is_none() {
        config["policy"] = json!({});
    }
    if config["policy"].get("levels").is_none() {
        config["policy"]["levels"] = json!({});
    }
    if config["policy"]["levels"].get("0").is_none() {
        config["policy"]["levels"]["0"] = json!({});
    }
    for key in ["statsUserUplink", "statsUserDownlink"] {
        config["policy"]["levels"]["0"][key] = json!(true);
    }
    let net_admin = cfg!(target_os = "linux")
        && fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("CapEff:")
                        .map(str::trim)
                        .map(str::to_owned)
                })
            })
            .and_then(|caps| u64::from_str_radix(&caps, 16).ok())
            .is_some_and(|caps| caps & (1 << 12) != 0);
    config["policy"]["levels"]["0"]["statsUserOnline"] = json!(net_admin);
    if config["policy"].get("system").is_none() {
        config["policy"]["system"] = json!({});
    }
    for key in [
        "statsInboundUplink",
        "statsInboundDownlink",
        "statsOutboundUplink",
        "statsOutboundDownlink",
    ] {
        config["policy"]["system"][key] = json!(true);
    }
    if config.get("routing").is_none() {
        config["routing"] = json!({});
    }
    let mut rules = config["routing"]["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    rules.retain(|rule| rule["outboundTag"] != API_TAG);
    // Upstream skips its API rule when routing is script-driven.
    let script = config["routing"]
        .get("script")
        .is_some_and(|script| !matches!(script, Value::Null | Value::Bool(false)) && script != "");
    if !script {
        rules.insert(
            0,
            json!({"type":"field","inboundTag":[API_INBOUND],"outboundTag":API_TAG}),
        );
    }
    if let Some((tags, position)) = torrent {
        if config.get("outbounds").is_none() {
            config["outbounds"] = json!([]);
        }
        config["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"tag":TORRENT_OUTBOUND,"protocol":"blackhole"}));
        let hook = json!({"url":webhook,"deduplication":5});
        // Upstream resolveRuleIndex: just after the API rule, or after `position` user rules.
        let user_rules = rules.len().saturating_sub(1);
        let index = if position == 0 {
            1
        } else {
            1 + (position as usize).min(user_rules)
        };
        rules.insert(
            index.min(rules.len()),
            json!({"protocol":["bittorrent"],"outboundTag":TORRENT_OUTBOUND,"webhook":hook}),
        );
        for rule in &mut rules {
            if rule["ruleTag"]
                .as_str()
                .is_some_and(|tag| tags.iter().any(|t| t == tag))
            {
                rule["webhook"] = hook.clone();
            }
        }
    }
    config["routing"]["rules"] = Value::Array(rules);
    Ok(config)
}

fn validate_internals(internals: &Value) -> Result<()> {
    ensure!(
        internals.get("forceRestart").is_none_or(Value::is_boolean),
        "internals.forceRestart must be a boolean"
    );
    let hashes = internals
        .get("hashes")
        .context("internals.hashes is required")?;
    ensure!(
        hashes.is_object() && hashes["emptyConfig"].is_string(),
        "internals.hashes.emptyConfig must be a string"
    );
    let inbounds = hashes["inbounds"]
        .as_array()
        .context("internals.hashes.inbounds must be an array")?;
    let mut tags = HashSet::new();
    for inbound in inbounds {
        ensure!(
            inbound["tag"].is_string()
                && inbound["hash"].is_string()
                && inbound["usersCount"].is_number(),
            "Invalid inbound hash entry"
        );
        ensure!(
            tags.insert(inbound["tag"].as_str().unwrap()),
            "Duplicate inbound hash tag"
        );
    }
    if let Some(metadata) = internals.get("metadata") {
        ensure!(
            metadata.is_object()
                && metadata["name"].is_string()
                && metadata["uuid"].is_string()
                && metadata["id"].is_number()
                && metadata["countryCode"].is_string()
                && metadata["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().all(Value::is_string)),
            "Invalid internals.metadata"
        );
    }
    Ok(())
}

fn https_url(value: &Value) -> Result<()> {
    let url = reqwest::Url::parse(value.as_str().context("Download URL must be a string")?)
        .context("Invalid download URL")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none(),
        "Download URL must use HTTPS without credentials"
    );
    Ok(())
}

fn validate_geodata(geodata: Option<&Value>) -> Result<()> {
    let Some(geodata) = geodata else {
        return Ok(());
    };
    ensure!(geodata.is_object(), "geodata must be an object");
    if let Some(core) = geodata.get("core") {
        ensure!(core.is_object(), "geodata.core must be an object");
        https_url(&core["url"])?;
        ensure!(
            core["sha256"]
                .as_str()
                .is_some_and(|sha| sha.len() == 64 && sha.bytes().all(|c| c.is_ascii_hexdigit())),
            "geodata.core.sha256 must be a SHA256 hexadecimal digest"
        );
    }
    if let Some(assets) = geodata.get("assets") {
        let assets = assets
            .as_array()
            .context("geodata.assets must be an array")?;
        for asset in assets {
            https_url(&asset["url"])?;
            ensure!(
                asset["file"].as_str().is_some_and(|file| !file.is_empty()
                    && file != "."
                    && file != ".."
                    && file
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))),
                "geodata asset must use a file name without a path"
            );
        }
    }
    Ok(())
}

async fn read_version(binary: &Path) -> Option<String> {
    let output = timeout(
        Duration::from_secs(5),
        Command::new(binary)
            .arg("version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
}

fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context("create private Xray state directory")?;
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_dir(),
        "Xray state directory must not be a symlink"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

struct PrivateStage {
    path: PathBuf,
}
impl PrivateStage {
    fn new(parent: &Path) -> Result<(Self, fs::File)> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = parent.join(format!(
            ".stage-{}-{}.json",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        Ok((Self { path }, file))
    }
}
impl Drop for PrivateStage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn stage_config(state_dir: &Path, config: &Value) -> Result<PrivateStage> {
    private_directory(state_dir)?;
    let (stage, mut file) = PrivateStage::new(state_dir)?;
    file.write_all(&serde_json::to_vec(config)?)?;
    file.sync_all()?;
    Ok(stage)
}

fn verified_file(path: &Path, expected: &str) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("inspect custom core"),
    };
    ensure!(
        metadata.file_type().is_file(),
        "Custom core must be a regular file"
    );
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        digest.update(&buffer[..size]);
    }
    Ok(format!("{:x}", digest.finalize()) == expected)
}

fn finish_download(
    stage: &Path,
    target: &Path,
    actual: &str,
    expected: Option<&str>,
    executable: bool,
) -> Result<()> {
    ensure!(
        expected.is_none_or(|expected| expected == actual),
        "Downloaded file SHA256 mismatch"
    );
    fs::set_permissions(
        stage,
        fs::Permissions::from_mode(if executable { 0o700 } else { 0o600 }),
    )?;
    fs::rename(stage, target).context("install downloaded file")?;
    Ok(())
}

async fn download(
    url: &str,
    target: &Path,
    expected: Option<&str>,
    executable: bool,
) -> Result<()> {
    const MAX_SIZE: u64 = 128 * 1024 * 1024;
    let (stage, file) = PrivateStage::new(
        target
            .parent()
            .context("Download target has no directory")?,
    )?;
    let mut file = tokio::fs::File::from_std(file);
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    let mut response = client
        .get(url)
        .send()
        .await
        .context("download Xray file")?
        .error_for_status()?;
    ensure!(
        response.url().scheme() == "https",
        "Download redirected away from HTTPS"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= MAX_SIZE),
        "Download exceeds 128 MiB"
    );
    let mut digest = Sha256::new();
    let mut size = 0u64;
    while let Some(chunk) = response.chunk().await.context("read Xray download")? {
        size += chunk.len() as u64;
        ensure!(size <= MAX_SIZE, "Download exceeds 128 MiB");
        digest.update(&chunk);
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
    }
    ensure!(size > 0, "Download body is empty");
    file.sync_all().await?;
    drop(file);
    finish_download(
        &stage.path,
        target,
        &format!("{:x}", digest.finalize()),
        expected,
        executable,
    )
}

// Matches @remnawave/hashed-set 0.0.4, including signed JavaScript hex formatting.
fn user_set_hash(users: &HashSet<String>) -> String {
    let (mut high, mut low) = (0u32, 0u32);
    for user in users {
        let (mut h, mut l) = (5381u32, 5387u32);
        for c in user.encode_utf16() {
            h = h.wrapping_mul(33).wrapping_add(c as u32);
            l = l.wrapping_mul(65).wrapping_add((c as u32) * 37);
        }
        high ^= h;
        low ^= l;
    }
    fn js_hex(value: u32) -> String {
        let signed = value as i32;
        let raw = if signed < 0 {
            format!("-{:x}", signed.unsigned_abs())
        } else {
            format!("{signed:x}")
        };
        format!("{raw:0>8}")
    }
    format!("{}{}", js_hex(high), js_hex(low))
}

pub fn system_info() -> Value {
    let mut system = System::new();
    system.refresh_memory();
    system.refresh_cpu_list(CpuRefreshKind::everything());
    let interfaces: Vec<String> = Networks::new_with_refreshed_list()
        .keys()
        .cloned()
        .collect();
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        arch => arch,
    };
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        os => os,
    };
    let kind = match std::env::consts::OS {
        "linux" => "Linux",
        "macos" => "Darwin",
        "windows" => "Windows_NT",
        os => os,
    };
    json!({"arch":arch,"cpus":system.cpus().len(),"cpuModel":system.cpus().first().map(|c| c.brand()).unwrap_or("unknown"),"memoryTotal":system.total_memory(),"hostname":System::host_name().unwrap_or_default(),"platform":platform,"release":System::kernel_version().unwrap_or_default(),"type":kind,"version":System::long_os_version().unwrap_or_default(),"networkInterfaces":interfaces})
}

/// getSystemStats: Node's os.freemem() is MemAvailable on Linux.
pub fn system_stats() -> Value {
    let mut system = System::new();
    system.refresh_memory();
    let load = System::load_average();
    let free = system.available_memory();
    json!({"memoryFree":free,"memoryUsed":system.total_memory().saturating_sub(free),"uptime":System::uptime(),"loadAvg":[load.one,load.five,load.fifteen],"interface":null})
}

/// The default-route interface's rates (network-stats.service getDefault), or null.
static INTERFACE: std::sync::Mutex<Option<Value>> = std::sync::Mutex::new(None);

pub fn interface_stats() -> Value {
    INTERFACE.lock().unwrap().clone().unwrap_or(Value::Null)
}

/// network-stats.service: samples /proc/net/dev every second for the interface of the
/// lowest-metric default route in /proc/net/route. Disabled where /proc/net/dev is missing.
pub fn start_network_stats() {
    let Ok(dev) = fs::read_to_string("/proc/net/dev") else {
        tracing::warn!("/proc/net/dev not found — network stats polling disabled (non-Linux OS?)");
        return;
    };
    let route = fs::read_to_string("/proc/net/route").unwrap_or_default();
    let Some(iface) = default_interface(&route) else {
        tracing::warn!("Could not resolve default interface from /proc/net/route");
        return;
    };
    tracing::info!(interface = %iface, "Network stats polling started (interval: 1000ms)");
    let mut previous = interface_bytes(&dev, &iface).map(|bytes| (bytes, Instant::now()));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now = Instant::now();
            let current = fs::read_to_string("/proc/net/dev")
                .ok()
                .and_then(|dev| interface_bytes(&dev, &iface));
            if let (Some(((rx0, tx0), at)), Some((rx, tx))) = (previous, current) {
                let elapsed = now.duration_since(at).as_secs_f64();
                if elapsed > 0.0 {
                    let rate = |new: u64, old: u64| (new as f64 - old as f64).max(0.0) / elapsed;
                    *INTERFACE.lock().unwrap() = Some(
                        json!({"interface":iface,"rxBytesPerSec":rate(rx, rx0),"txBytesPerSec":rate(tx, tx0),"rxTotal":rx,"txTotal":tx}),
                    );
                }
            }
            if let Some(bytes) = current {
                previous = Some((bytes, now));
            }
        }
    });
}

fn default_interface(route: &str) -> Option<String> {
    route
        .lines()
        .skip(1)
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|f| f.len() >= 11 && f[1] == "00000000")
        .min_by_key(|f| f[6].parse::<u64>().unwrap_or(0))
        .map(|f| f[0].to_owned())
}

/// (rx bytes, tx bytes) of `iface` in /proc/net/dev.
fn interface_bytes(dev: &str, iface: &str) -> Option<(u64, u64)> {
    dev.lines().skip(2).find_map(|line| {
        let (name, rest) = line.split_once(':')?;
        let fields: Vec<_> = rest.split_whitespace().collect();
        (name.trim() == iface && fields.len() >= 16)
            .then(|| Some((fields[0].parse().ok()?, fields[8].parse().ok()?)))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn network_stats_parse_proc_files_like_upstream() {
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            wg0\t00000000\t00000000\t0001\t0\t0\t200\t00000000\t0\t0\t0\n\
            eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(default_interface(route).as_deref(), Some("eth0"));
        assert_eq!(default_interface("Iface\n"), None);
        let dev = "Inter-|   Receive |  Transmit\n face |bytes packets|bytes\n\
            \x20   lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n\
            \x20 eth0: 123456 10 0 0 0 0 0 0 654321 9 0 0 0 0 0 0\n\
            \x20 bad0: 1 2 3\n";
        assert_eq!(interface_bytes(dev, "eth0"), Some((123456, 654321)));
        assert_eq!(interface_bytes(dev, "bad0"), None);
        assert_eq!(interface_bytes(dev, "wg0"), None);
    }

    #[test]
    fn validates_hash_contract_before_touching_the_process() {
        assert!(validate_internals(&json!({})).is_err());
        assert!(
            validate_internals(
                &json!({"hashes":{"emptyConfig":"base","inbounds":[]},"forceRestart":"false"})
            )
            .is_err()
        );
        assert!(validate_internals(&json!({"hashes":{"emptyConfig":"base","inbounds":[{"tag":"in","hash":"x","usersCount":"1"}]}})).is_err());
        assert!(
            validate_internals(
                &json!({"hashes":{"emptyConfig":"base","inbounds":[]},"metadata":{"name":"node"}})
            )
            .is_err()
        );
        assert!(validate_internals(&json!({"hashes":{"emptyConfig":"base","inbounds":[{"tag":"in","hash":"x","usersCount":1}]},"metadata":{"name":"node","uuid":"id","id":1,"countryCode":"NL","tags":["tag"]}})).is_ok());
    }

    #[test]
    fn validates_https_sha256_and_asset_path_boundaries() {
        let digest = "a".repeat(64);
        assert!(validate_geodata(Some(&json!({"core":{"url":"https://example.org/xray","sha256":digest},"assets":[{"url":"https://example.org/geo.dat","file":"geoip-custom.dat"}]}))).is_ok());
        for file in [
            "",
            ".",
            "..",
            "../escape",
            "/absolute",
            "nested/file",
            "back\\slash",
            "a:b",
        ] {
            assert!(
                validate_geodata(Some(
                    &json!({"assets":[{"url":"https://example.org/asset","file":file}]})
                ))
                .is_err(),
                "{file}"
            );
        }
        for url in [
            "http://example.org/file",
            "file:///tmp/xray",
            "https://user:pass@example.org/file",
        ] {
            assert!(validate_geodata(Some(&json!({"core":{"url":url,"sha256":digest}}))).is_err());
        }
        assert!(
            validate_geodata(Some(
                &json!({"core":{"url":"https://example.org/xray","sha256":"wrong"}})
            ))
            .is_err()
        );
    }

    #[test]
    fn checksum_failure_never_replaces_existing_binary_or_makes_stage_executable() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("custom-core");
        fs::write(&target, "working binary").unwrap();
        let (stage, mut file) = PrivateStage::new(dir.path()).unwrap();
        file.write_all(b"new binary").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"new binary"));
        assert!(
            finish_download(&stage.path, &target, &digest, Some(&"0".repeat(64)), true).is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), b"working binary");
        assert_eq!(
            fs::metadata(&stage.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        finish_download(&stage.path, &target, &digest, Some(&digest), true).unwrap();
        assert!(verified_file(&target, &digest).unwrap());
        assert_eq!(
            fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[tokio::test]
    async fn insecure_download_preserves_target_and_removes_staged_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("geoip.dat");
        fs::write(&target, b"original").unwrap();
        assert!(
            download("http://127.0.0.1:1/file", &target, None, false)
                .await
                .is_err()
        );
        assert_eq!(fs::read(target).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn user_hash_matches_upstream_signed_utf16_fixtures() {
        for (users, expected) in [
            (vec![], "0000000000000000"),
            (vec!["alice"], "0f174dc37b0060c1"),
            (vec!["😀"], "00762822096ad59c"),
            (
                vec!["550e8400-e29b-41d4-a716-446655440000"],
                "-6a5957487275060a",
            ),
            (vec!["alice", "bob", "alice"], "049f2fbb221bb1ab"),
        ] {
            assert_eq!(
                user_set_hash(&users.into_iter().map(str::to_owned).collect()),
                expected
            );
        }
    }

    #[test]
    fn restart_check_uses_live_user_sets_and_rejects_duplicate_inbound_hashes() {
        let mut core = Core::new(
            "xray".into(),
            "state".into(),
            "http://127.0.0.1:61000".into(),
        );
        core.empty_config_hash = Some("base".into());
        core.inbounds
            .insert("vless".into(), HashSet::from(["alice".into()]));
        let hashes =
            json!({"emptyConfig":"base", "inbounds":[{"tag":"vless","hash":"0f174dc37b0060c1"}]});
        assert!(!core.needs_restart(&hashes));
        core.inbounds.get_mut("vless").unwrap().insert("bob".into());
        assert!(core.needs_restart(&hashes));
        let current =
            json!({"emptyConfig":"base", "inbounds":[{"tag":"vless","hash":"049f2fbb221bb1ab"}]});
        assert!(!core.needs_restart(&current));
        assert!(core.needs_restart(&json!({"emptyConfig":"new", "inbounds":current["inbounds"]})));
        core.inbounds.insert("other".into(), HashSet::new());
        assert!(core.needs_restart(&json!({"emptyConfig":"base", "inbounds":[current["inbounds"][0],current["inbounds"][0]]})));
    }

    #[tokio::test]
    #[ignore = "requires XRAY_BINARY pointing to a real Xray executable"]
    async fn real_xray_lifecycle() {
        let binary = std::env::var_os("XRAY_BINARY").expect("set XRAY_BINARY");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let user_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let user_port = user_listener.local_addr().unwrap().port();
        let ss_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ss_port = ss_listener.local_addr().unwrap().port();
        drop(listener);
        drop(user_listener);
        drop(ss_listener);
        let temp = tempfile::tempdir().unwrap();
        let mut core = Core::new(binary.into(), temp.path().join("state"), endpoint);
        let socket_path = temp.path().join("cleanup.sock");
        let _socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let mut plugins = Plugins::default();
        plugins.sync(&json!({"plugin":{"name":"cleanup","uuid":"52cd4e17-ec80-4b29-b0c3-83a360e064b3","config":{"preStart":{"enabled":true,"cleanupSockets":{"enabled":true,"files":[socket_path]}}}}})).await.unwrap();
        let mut body = json!({"xrayConfig":{"inbounds":[{"tag":"untracked","listen":"127.0.0.1","port":user_port,"protocol":"socks","settings":{}},{"tag":"ss-untracked","listen":"127.0.0.1","port":ss_port,"protocol":"shadowsocks","settings":{"method":"aes-128-gcm","clients":[{"password":"testpassword","method":"aes-128-gcm","email":"fixture"}]}}], "outbounds":[{"protocol":"freedom","tag":"direct"}]}, "internals":{"hashes":{"emptyConfig":"base","inbounds":[]}}});
        let result = core.start_with_plugins(&body, &plugins).await.unwrap();
        assert_eq!(result["isStarted"], true, "{result}");
        assert!(result["version"].as_str().is_some());
        let first_pid = core.child.as_ref().unwrap().id();
        assert!(core.inbounds.is_empty());
        assert_eq!(core.inbound_ciphers.get("ss-untracked"), Some(&5));
        assert!(!socket_path.exists());
        let _new_socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        assert_eq!(core.health().await["xrayInternalStatusCached"], true);
        let result = core.start_with_plugins(&body, &plugins).await.unwrap();
        assert_eq!(result["isStarted"], true, "{result}");
        assert_eq!(core.child.as_ref().unwrap().id(), first_pid);
        assert!(socket_path.exists());
        body["internals"]["forceRestart"] = json!(true);
        let result = core.start_with_plugins(&body, &plugins).await.unwrap();
        assert_eq!(result["isStarted"], true, "{result}");
        assert_ne!(core.child.as_ref().unwrap().id(), first_pid);
        assert!(!socket_path.exists());
        assert_eq!(core.stop().await.unwrap()["isStopped"], true);
        assert!(core.child.is_none());
        assert_eq!(core.health().await["xrayInternalStatusCached"], false);
    }

    #[tokio::test]
    #[ignore = "requires XRAY_BINARY pointing to a real Xray executable"]
    async fn real_xray_fires_torrent_webhook_to_internal_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let binary = std::env::var_os("XRAY_BINARY").expect("set XRAY_BINARY");
        let api = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (endpoint, proxy_port) = (
            format!("http://{}", api.local_addr().unwrap()),
            proxy.local_addr().unwrap().port(),
        );
        drop((api, proxy));
        let temp = tempfile::tempdir().unwrap();
        let mut core = Core::new(binary.into(), temp.path().join("state"), endpoint);
        let (sender, mut received) = tokio::sync::mpsc::unbounded_channel();
        let capture = axum::Router::new().route(
            "/internal/webhook",
            axum::routing::post(move |uri: axum::http::Uri, body: axum::body::Bytes| {
                let _ = sender.send((
                    uri.to_string(),
                    serde_json::from_slice::<Value>(&body).unwrap(),
                ));
                async { axum::http::StatusCode::OK }
            }),
        );
        tokio::spawn(axum::serve(core.bind_webhook().unwrap(), capture).into_future());
        let mut plugins = Plugins::default();
        crate::plugins::enable_torrent_for_test(&mut plugins, &[], 0);
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let body = json!({"xrayConfig":{
            "inbounds":[{"tag":"vless","listen":"127.0.0.1","port":proxy_port,"protocol":"vless",
                "settings":{"clients":[{"id":id,"email":"alice"}],"decryption":"none"},
                "sniffing":{"enabled":true,"destOverride":["http","tls"]}}],
            "outbounds":[{"tag":"direct","protocol":"freedom"}]},
            "internals":{"hashes":{"emptyConfig":"base","inbounds":[]}}});
        let result = core.start_with_plugins(&body, &plugins).await.unwrap();
        assert_eq!(result["isStarted"], true, "{result}");
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .unwrap();
        let mut request = vec![0];
        request.extend_from_slice(uuid::Uuid::parse_str(id).unwrap().as_bytes());
        request.extend_from_slice(&[0, 1, 0x1a, 0xe1, 1, 127, 0, 0, 1]);
        request.push(19);
        request.extend_from_slice(b"BitTorrent protocol");
        request.extend_from_slice(&[0; 48]);
        stream.write_all(&request).await.unwrap();
        let (uri, event) = tokio::time::timeout(Duration::from_secs(10), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            uri,
            format!("/internal/webhook?token={}", core.webhook_token())
        );
        assert_eq!(event["email"], "alice");
        assert_eq!(event["protocol"], "bittorrent");
        assert_eq!(event["outboundTag"], TORRENT_OUTBOUND);
        assert!(event["source"].as_str().unwrap().starts_with("127.0.0.1:"));
        // The blackhole outbound closes the torrent connection instead of proxying it.
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
        assert!(rest.len() <= 2, "torrent traffic was proxied: {rest:?}");
        core.stop().await.unwrap();
    }

    #[test]
    fn injects_api_without_losing_user_policy_or_routing() {
        let original = json!({
            "inbounds":[{"tag":"user", "protocol":"vless", "settings":{"clients":[]}}],
            "outbounds":[{"tag":"direct", "protocol":"freedom"}],
            "policy":{"levels":{"0":{"handshake":7},"2":{"connIdle":30}},"system":{"custom":true}},
            "routing":{"domainStrategy":"IPIfNonMatch", "rules":[{"domain":["example.org"],"outboundTag":"direct"}]}
        });
        let config = api_config(&original, "http://127.0.0.1:61000", None, "").unwrap();
        assert_eq!(config["api"]["tag"], "REMNAWAVE_API");
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["port"], 61000);
        assert_eq!(config["inbounds"][1], original["inbounds"][0]);
        assert_eq!(config["outbounds"], original["outbounds"]);
        assert_eq!(config["policy"]["levels"]["0"]["handshake"], 7);
        assert_eq!(config["policy"]["levels"]["2"]["connIdle"], 30);
        assert_eq!(config["policy"]["levels"]["0"]["statsUserUplink"], true);
        assert_eq!(
            config["routing"]["rules"][0]["outboundTag"],
            "REMNAWAVE_API"
        );
        assert_eq!(
            config["routing"]["rules"][1],
            original["routing"]["rules"][0]
        );
        assert_eq!(config["stats"], json!({}));
    }

    #[test]
    fn refuses_remote_management_listeners_and_reserved_tags() {
        for endpoint in [
            "http://0.0.0.0:61000",
            "http://example.org:61000",
            "https://127.0.0.1:61000",
        ] {
            assert!(api_config(&json!({}), endpoint, None, "").is_err());
        }
        assert!(
            api_config(
                &json!({"inbounds":[{"tag":"REMNAWAVE_API_INBOUND"}]}),
                "http://127.0.0.1:61000",
                None,
                ""
            )
            .is_err()
        );
    }

    #[test]
    fn injects_torrent_blocker_rule_like_upstream() {
        let original = json!({"routing":{"rules":[
            {"ruleTag":"a","outboundTag":"direct"},{"ruleTag":"b","outboundTag":"direct"},{"outboundTag":"direct"}
        ]}});
        let rules = |position, tags: &[String]| {
            api_config(
                &original,
                "http://127.0.0.1:1",
                Some((tags, position)),
                "/s.sock:/internal/webhook?token=t",
            )
            .unwrap()["routing"]["rules"]
                .as_array()
                .unwrap()
                .clone()
        };
        let default = rules(0, &[]);
        assert_eq!(default[0]["outboundTag"], API_TAG);
        assert_eq!(default[1]["protocol"], json!(["bittorrent"]));
        assert_eq!(default[1]["outboundTag"], TORRENT_OUTBOUND);
        assert_eq!(
            default[1]["webhook"],
            json!({"url":"/s.sock:/internal/webhook?token=t","deduplication":5})
        );
        assert_eq!(rules(2, &[])[3]["outboundTag"], TORRENT_OUTBOUND);
        assert_eq!(rules(1000, &[])[4]["outboundTag"], TORRENT_OUTBOUND);
        let tagged = rules(0, &["b".to_owned()]);
        assert!(tagged[2].get("webhook").is_none() && tagged[3]["webhook"]["deduplication"] == 5);
        let config = api_config(&original, "http://127.0.0.1:1", Some((&[], 0)), "x").unwrap();
        assert_eq!(
            config["outbounds"],
            json!([{"tag":TORRENT_OUTBOUND,"protocol":"blackhole"}])
        );
        let scripted = api_config(
            &json!({"routing":{"script":"x","rules":[]}}),
            "http://127.0.0.1:1",
            None,
            "",
        )
        .unwrap();
        assert_eq!(scripted["routing"]["rules"], json!([]));
    }

    #[tokio::test]
    async fn accepts_integrations_like_upstream_build() {
        let temp = tempfile::tempdir().unwrap();
        let mut core = Core::new(
            "/does/not/exist".into(),
            temp.path().into(),
            "http://127.0.0.1:61000".into(),
        );
        let response = core
            .start(&json!({"xrayConfig":{},"internals":{"integrations":{"foo":{"enabled":true}}}}))
            .await
            .unwrap();
        assert_eq!(response["isStarted"], false);
        let error = response["error"].as_str().unwrap();
        assert!(!error.contains("integrations"), "{error}");
        assert_eq!(
            response["nodeInformation"]["version"],
            crate::upstream_version()
        );
    }

    #[tokio::test]
    async fn failed_validation_preserves_running_child_and_private_config() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("xray");
        std::fs::write(&binary, "#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Xray 26.1.1'; exit 0; fi\nif [ \"$2\" = -test ]; then echo 'bad config' >&2; exit 1; fi\nexit 2\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = temp.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::write(state.join("config.json"), b"old config").unwrap();
        let mut core = Core::new(binary, state.clone(), "http://127.0.0.1:61000".into());
        core.child = Some(
            tokio::process::Command::new("sleep")
                .arg("30")
                .kill_on_drop(true)
                .spawn()
                .unwrap(),
        );
        let response = core
            .start(&json!({"xrayConfig":{},"internals":{"hashes":{"emptyConfig":"base","inbounds":[]}}}))
            .await
            .unwrap();
        assert_eq!(response["isStarted"], false);
        assert!(response["error"].as_str().unwrap().contains("bad config"));
        assert!(core.child.as_mut().unwrap().try_wait().unwrap().is_none());
        assert_eq!(
            std::fs::read(state.join("config.json")).unwrap(),
            b"old config"
        );
        assert_eq!(std::fs::read_dir(&state).unwrap().count(), 1);
        assert_eq!(core.stop().await.unwrap()["isStopped"], true);
    }

    #[tokio::test]
    async fn failed_child_is_reaped_and_config_is_private() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("xray");
        std::fs::write(&binary, "#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Xray 26.1.1'; exit 0; fi\nif [ \"$2\" = -test ]; then exit 0; fi\nexit 42\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = temp.path().join("state");
        let mut core = Core::new(binary, state.clone(), "http://127.0.0.1:61000".into());
        let response = core
            .start(&json!({"xrayConfig":{},"internals":{"hashes":{"emptyConfig":"base","inbounds":[]}}}))
            .await
            .unwrap();
        assert_eq!(response["isStarted"], false);
        assert!(response["error"].as_str().unwrap().contains("exit"));
        assert!(core.child.is_none());
        assert_eq!(
            std::fs::metadata(state.join("config.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(state).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

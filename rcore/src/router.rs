//! Port of xray-core app/router: first-match field rules, domain strategies, balancers and
//! routing webhooks.
use crate::app::Instance;
use crate::config::{go_duration_ns, keys, port_list, string_list, unsupported};
use crate::dns::IpOption;
use crate::geodata::{DomainMatcher, IpMatcher, Kind, Loader};
use crate::observatory::OutboundStatus;
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
    /// session.Inbound.Source/Local; unset for the core's own dispatches.
    pub source: Option<SocketAddr>,
    pub local: Option<SocketAddr>,
    pub domain: Option<String>,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub protocol: String,
    pub user: String,
    pub level: u32,
    pub vless_route: u16,
    /// session.Content.SkipDNSResolve
    pub skip_dns: bool,
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
    /// outboundTag; empty when the rule names a balancer.
    pub outbound: String,
    pub balancer: Option<Arc<Balancer>>,
    pub tag: String,
    cond: Conditions,
    webhook: Option<Arc<Webhook>>,
}

pub struct Router {
    strategy: Strategy,
    rules: Vec<Rule>,
    balancers: Vec<Arc<Balancer>>,
}

/// features/routing/dns ResolvableContext.GetTargetIPs: resolves the target domain once, on the
/// first IP condition that asks.
struct TargetIps {
    resolvable: bool,
    cache: Vec<IpAddr>,
    failed: bool,
}

impl TargetIps {
    fn new(resolvable: bool) -> Self {
        Self {
            resolvable,
            cache: Vec::new(),
            failed: false,
        }
    }

    async fn get(&mut self, ctx: &Ctx, inst: &Arc<Instance>) -> Vec<IpAddr> {
        if !self.resolvable {
            return ctx.ip.into_iter().collect();
        }
        if !self.cache.is_empty() {
            return self.cache.clone();
        }
        if self.failed {
            return Vec::new();
        }
        if let Some(domain) = ctx.domain.as_deref().filter(|d| !d.is_empty()) {
            let option = IpOption { v4: true, v6: true };
            match inst.config.dns.lookup_ip(inst, domain, option).await {
                Ok((ips, _)) => {
                    self.cache = ips.clone();
                    return ips;
                }
                Err(e) => tracing::info!("features/routing/dns: resolve ip for {domain} > {e}"),
            }
        }
        if let Some(ip) = ctx.ip {
            self.cache = vec![ip];
            return self.cache.clone();
        }
        self.failed = true;
        Vec::new()
    }
}

impl Rule {
    /// The condition chain in Go's order (BuildCondition); target IPs resolve lazily.
    async fn applies(&self, ctx: &Ctx, ips: &mut TargetIps, inst: &Arc<Instance>) -> bool {
        let c = &self.cond;
        if !c.inbound_tag.is_empty()
            && (ctx.inbound_tag.is_empty() || !c.inbound_tag.contains(&ctx.inbound_tag))
        {
            return false;
        }
        if let Some((tcp, udp)) = c.network
            && !(if ctx.udp { udp } else { tcp })
        {
            return false;
        }
        if !c.protocol.is_empty()
            && (ctx.protocol.is_empty()
                || !c
                    .protocol
                    .iter()
                    .any(|p| ctx.protocol.starts_with(p.as_str())))
        {
            return false;
        }
        if !c.port.is_empty() && !in_ports(&c.port, ctx.port) {
            return false;
        }
        let source_port = ctx.source.map_or(0, |s| s.port());
        if !c.source_port.is_empty() && !in_ports(&c.source_port, source_port) {
            return false;
        }
        let local_port = ctx.local.map_or(0, |s| s.port());
        if !c.local_port.is_empty() && !in_ports(&c.local_port, local_port) {
            return false;
        }
        if !c.vless_route.is_empty() && !in_ports(&c.vless_route, ctx.vless_route) {
            return false;
        }
        if !c.user.is_empty()
            && (ctx.user.is_empty()
                || !c.user.iter().any(|u| match u {
                    UserMatch::Exact(e) => *e == ctx.user,
                    UserMatch::Regex(r) => r.is_match(&ctx.user),
                }))
        {
            return false;
        }
        if let Some(m) = &c.ip
            && !ips.get(ctx, inst).await.iter().any(|ip| m.matches(*ip))
        {
            return false;
        }
        if let Some(m) = &c.source
            && !ctx.source.is_some_and(|s| m.matches(s.ip()))
        {
            return false;
        }
        if let Some(m) = &c.local_ip
            && !ctx.local.is_some_and(|l| m.matches(l.ip()))
        {
            return false;
        }
        if let Some(d) = &c.domain
            && !ctx
                .domain
                .as_deref()
                .is_some_and(|domain| !domain.is_empty() && d.matches(domain))
        {
            return false;
        }
        true
    }
}

/// weight.go numberFinder.
static NUMBER: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"\d+(\.\d+)?").unwrap());

/// StrategyWeight: a cost for outbounds whose tag contains (or matches) `find`.
struct Cost {
    regexp: bool,
    find: String,
    value: f32,
}

/// StrategyLeastLoadConfig with the WeightManager cache.
struct LeastLoad {
    costs: Vec<Cost>,
    cache: Mutex<HashMap<String, f64>>,
    baselines: Vec<i64>,
    expected: i32,
    max_rtt: i64,
    tolerance: f32,
}

enum Balance {
    Random,
    RoundRobin(Mutex<usize>),
    LeastPing,
    LeastLoad(LeastLoad),
}

/// router.Balancer.
pub struct Balancer {
    pub tag: String,
    selectors: Vec<String>,
    fallback: String,
    strategy: Balance,
    over: Mutex<String>,
}

/// outbound.Manager.Select: tagged outbounds with a selector prefix, sorted.
pub fn select(inst: &Instance, selectors: &[String]) -> Vec<String> {
    let mut tags: Vec<String> = inst
        .config
        .outbounds
        .iter()
        .filter(|o| !o.tag.is_empty() && selectors.iter().any(|s| o.tag.starts_with(s.as_str())))
        .map(|o| o.tag.clone())
        .collect();
    tags.sort();
    tags.dedup();
    tags
}

/// Keeps candidates the observatory reports alive (or does not know), as random and
/// roundRobin do once a fallbackTag is set.
fn alive(candidates: Vec<String>, status: &[OutboundStatus]) -> Vec<String> {
    candidates
        .into_iter()
        .filter(|c| status.iter().find(|s| s.tag == *c).is_none_or(|s| s.alive))
        .collect()
}

/// leastLoad's node.
struct Node {
    tag: String,
    count_all: i64,
    count_fail: i64,
    rtt_average: i64,
    rtt_deviation_cost: i64,
}

impl LeastLoad {
    /// WeightManager.Get.
    fn weight(&self, tag: &str) -> f64 {
        if let Some(w) = self.cache.lock().unwrap().get(tag) {
            return *w;
        }
        let mut weight = 1.0;
        for cost in &self.costs {
            let matched = if cost.regexp {
                match regex::Regex::new(&cost.find) {
                    Ok(re) => re
                        .find(tag)
                        .map(|m| m.as_str().to_owned())
                        .unwrap_or_default(),
                    Err(e) => {
                        tracing::error!("app/router: invalid regexp: {}err: {e}", cost.find);
                        String::new()
                    }
                }
            } else if tag.contains(cost.find.as_str()) {
                cost.find.clone()
            } else {
                String::new()
            };
            if matched.is_empty() {
                continue;
            }
            weight = if cost.value > 0.0 {
                f64::from(cost.value)
            } else {
                // numberFinder `\d+(\.\d+)?` over the matched text.
                NUMBER
                    .find(&matched)
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(1.0)
            };
            break;
        }
        self.cache.lock().unwrap().insert(tag.to_owned(), weight);
        weight
    }

    fn cost(&self, tag: &str, value: f64) -> i64 {
        (value * self.weight(tag).powf(0.5)) as i64
    }

    /// getNodes + selectLeastLoad.
    fn pick(&self, candidates: &[String], status: &[OutboundStatus]) -> Vec<String> {
        let mut nodes: Vec<Node> = status
            .iter()
            .filter(|v| {
                v.alive
                    && !(self.max_rtt != 0 && v.delay >= self.max_rtt / 1_000_000)
                    && candidates.contains(&v.tag)
                    && !v.health.as_ref().is_some_and(|h| {
                        h.all > 0
                            && self.tolerance > 0.0
                            && h.fail as f64 / h.all as f64 > f64::from(self.tolerance)
                    })
            })
            .map(|v| match &v.health {
                Some(h) => Node {
                    tag: v.tag.clone(),
                    count_all: h.all,
                    count_fail: h.fail,
                    rtt_average: h.average,
                    rtt_deviation_cost: self.cost(&v.tag, h.deviation as f64),
                },
                None => Node {
                    tag: v.tag.clone(),
                    count_all: 1,
                    count_fail: 1,
                    rtt_average: v.delay * 1_000_000,
                    rtt_deviation_cost: self.cost(&v.tag, (v.delay * 1_000_000) as f64),
                },
            })
            .collect();
        nodes.sort_by(|l, r| {
            l.rtt_deviation_cost
                .cmp(&r.rtt_deviation_cost)
                .then(l.rtt_average.cmp(&r.rtt_average))
                .then(l.count_fail.cmp(&r.count_fail))
                .then(r.count_all.cmp(&l.count_all))
                .then(l.tag.cmp(&r.tag))
        });
        if nodes.is_empty() {
            tracing::info!("app/router: least load: no qualified outbound");
            return Vec::new();
        }
        let available = nodes.len();
        let mut expected = self.expected as usize;
        if self.expected as usize > available {
            return nodes.into_iter().map(|n| n.tag).collect();
        }
        if expected == 0 {
            expected = 1;
        }
        let mut count = if self.baselines.is_empty() {
            expected
        } else {
            0
        };
        for baseline in &self.baselines {
            for (i, node) in nodes.iter().enumerate().skip(count) {
                if node.rtt_deviation_cost >= *baseline {
                    break;
                }
                count = i + 1;
            }
            if count >= expected {
                tracing::debug!(
                    "app/router: applied baseline: {}",
                    crate::dns::go_duration(Duration::from_nanos(*baseline as u64))
                );
                break;
            }
        }
        if self.expected > 0 && count < expected {
            count = expected;
        }
        nodes.into_iter().take(count).map(|n| n.tag).collect()
    }
}

impl Balancer {
    /// Whether the strategy needs an observatory feature (Go fails to start without one).
    fn needs_observatory(&self) -> bool {
        matches!(self.strategy, Balance::LeastPing | Balance::LeastLoad(_))
            || !self.fallback.is_empty()
    }

    /// Balancer.PickOutbound.
    pub fn pick(&self, inst: &Instance) -> Result<String> {
        let candidates = select(inst, &self.selectors);
        let over = self.over.lock().unwrap().clone();
        let tag = if !over.is_empty() {
            over
        } else {
            let status = inst.config.observatory.observation();
            match &self.strategy {
                Balance::Random | Balance::RoundRobin(_) => {
                    let tags = match &status {
                        Some(status) if !self.fallback.is_empty() => alive(candidates, status),
                        _ => candidates,
                    };
                    match &self.strategy {
                        _ if tags.is_empty() => String::new(),
                        Balance::RoundRobin(index) => {
                            let mut index = index.lock().unwrap();
                            let tag = tags[*index % tags.len()].clone();
                            *index = (*index + 1) % tags.len();
                            tag
                        }
                        _ => tags[crate::dns::roll(tags.len())].clone(),
                    }
                }
                Balance::LeastPing => match &status {
                    None => {
                        tracing::error!("app/router: observer is nil");
                        String::new()
                    }
                    Some(status) => {
                        let mut least = 99_999_999i64;
                        let mut selected = String::new();
                        for v in status {
                            if candidates.contains(&v.tag) && v.alive && v.delay < least {
                                selected = v.tag.clone();
                                least = v.delay;
                            }
                        }
                        selected
                    }
                },
                Balance::LeastLoad(ll) => match &status {
                    None => {
                        tracing::error!("app/router: observer is nil");
                        String::new()
                    }
                    Some(status) => {
                        let selects = ll.pick(&candidates, status);
                        if selects.is_empty() {
                            String::new()
                        } else {
                            selects[crate::dns::roll(selects.len())].clone()
                        }
                    }
                },
            }
        };
        if tag.is_empty() {
            if !self.fallback.is_empty() {
                tracing::info!(
                    "app/router: fallback to [{}], due to empty tag returned",
                    self.fallback
                );
                return Ok(self.fallback.clone());
            }
            bail!("app/router: balancing strategy returns empty tag");
        }
        Ok(tag)
    }

    /// infra/conf BalancingRule.Build.
    fn parse(v: &Value, p: &str) -> Result<Self> {
        keys(v, &["tag", "selector", "strategy", "fallbackTag"], p)?;
        let tag = v["tag"].as_str().unwrap_or_default().to_owned();
        ensure!(!tag.is_empty(), "empty balancer tag");
        let selectors = string_list(&v["selector"], &format!("{p}.selector"))?;
        ensure!(!selectors.is_empty(), "empty selector list");
        let strategy = &v["strategy"];
        keys(strategy, &["type", "settings"], &format!("{p}.strategy"))?;
        let settings = &strategy["settings"];
        let kind = strategy["type"].as_str().unwrap_or_default().to_lowercase();
        let strategy = match kind.as_str() {
            "" | "random" => Balance::Random,
            "roundrobin" => Balance::RoundRobin(Mutex::new(0)),
            "leastping" => Balance::LeastPing,
            "leastload" => {
                let sp = format!("{p}.strategy.settings");
                keys(
                    settings,
                    &["costs", "baselines", "expected", "maxRTT", "tolerance"],
                    &sp,
                )?;
                let mut costs = Vec::new();
                for (i, c) in settings["costs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    keys(
                        c,
                        &["regexp", "match", "value"],
                        &format!("{sp}.costs[{i}]"),
                    )?;
                    costs.push(Cost {
                        regexp: c["regexp"].as_bool().unwrap_or(false),
                        find: c["match"].as_str().unwrap_or_default().to_owned(),
                        value: c["value"].as_f64().unwrap_or(0.0) as f32,
                    });
                }
                let mut baselines = Vec::new();
                for (i, b) in settings["baselines"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    let ns = go_duration_ns(b, &format!("{sp}.baselines[{i}]"))?;
                    if ns > 0 {
                        baselines.push(ns);
                    }
                }
                let duration = |k: &str| -> Result<i64> {
                    if settings[k].is_null() {
                        Ok(0)
                    } else {
                        go_duration_ns(&settings[k], &format!("{sp}.{k}"))
                    }
                };
                Balance::LeastLoad(LeastLoad {
                    costs,
                    cache: Mutex::default(),
                    baselines,
                    expected: settings["expected"].as_i64().unwrap_or(0).max(0) as i32,
                    max_rtt: duration("maxRTT")?.max(0),
                    tolerance: (settings["tolerance"].as_f64().unwrap_or(0.0) as f32)
                        .clamp(0.0, 1.0),
                })
            }
            other => bail!("unknown balancing strategy: {other}"),
        };
        Ok(Self {
            tag,
            selectors,
            fallback: v["fallbackTag"].as_str().unwrap_or_default().to_owned(),
            strategy,
            over: Mutex::default(),
        })
    }
}

impl Router {
    pub fn parse(value: &Value, loader: &mut Loader) -> Result<Self> {
        // Xray 26.11.9 ignores the retired matcher selector at both routing and rule level.
        keys(
            value,
            &["domainStrategy", "domainMatcher", "rules", "balancers"],
            "routing",
        )?;
        let strategy = match value["domainStrategy"].as_str().unwrap_or("AsIs") {
            "AsIs" | "" => Strategy::AsIs,
            "IPIfNonMatch" => Strategy::IpIfNonMatch,
            "IPOnDemand" => Strategy::IpOnDemand,
            other => bail!("routing.domainStrategy: unknown {other}"),
        };
        let mut balancers: Vec<Arc<Balancer>> = Vec::new();
        for (i, b) in value["balancers"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let balancer = Balancer::parse(b, &format!("routing.balancers[{i}]"))?;
            ensure!(
                balancers.iter().all(|x| x.tag != balancer.tag),
                "duplicate balancer tag"
            );
            balancers.push(Arc::new(balancer));
        }
        let mut rules = Vec::new();
        let mut rule_tags = Vec::new();
        for (i, r) in value["rules"].as_array().into_iter().flatten().enumerate() {
            let p = format!("routing.rules[{i}]");
            keys(
                r,
                &[
                    "type",
                    "outboundTag",
                    "balancerTag",
                    "ruleTag",
                    "domain",
                    "domains",
                    "domainMatcher",
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
            let outbound = r["outboundTag"].as_str().unwrap_or_default().to_owned();
            let balancer_tag = r["balancerTag"].as_str().unwrap_or_default();
            let balancer = if !outbound.is_empty() {
                None
            } else if !balancer_tag.is_empty() {
                let found = balancers.iter().find(|b| b.tag == balancer_tag);
                Some(
                    found
                        .with_context(|| format!("balancer {balancer_tag} not found"))?
                        .clone(),
                )
            } else {
                bail!("neither outboundTag nor balancerTag is specified in routing rule");
            };
            let tag = r["ruleTag"].as_str().unwrap_or_default().to_owned();
            ensure!(
                tag.is_empty() || !rule_tags.contains(&tag),
                "duplicate ruleTag {tag}"
            );
            rule_tags.push(tag.clone());
            rules.push(Rule {
                outbound,
                balancer,
                tag,
                cond,
                webhook,
            });
        }
        Ok(Self {
            strategy,
            rules,
            balancers,
        })
    }

    /// Whether a balancer requires an observatory (core.RequireFeatures).
    pub fn needs_observatory(&self) -> bool {
        self.balancers.iter().any(|b| b.needs_observatory())
    }

    /// True when a rule sends all of `inbound`'s traffic to `outbound` (the API pattern).
    pub fn routes_inbound_to(&self, inbound: &str, outbound: &str) -> bool {
        self.rules
            .iter()
            .any(|r| r.outbound == outbound && r.cond.inbound_tag.iter().any(|t| t == inbound))
    }

    /// PickRoute: the first matching rule and its outbound tag (a balancer's pick), firing the
    /// rule's webhook. IPOnDemand resolves the domain on the first IP condition; IPIfNonMatch
    /// retries every rule with the resolved IPs.
    pub async fn pick(&self, ctx: &Ctx, inst: &Arc<Instance>) -> Result<Option<(&Rule, String)>> {
        let mut ips = TargetIps::new(self.strategy == Strategy::IpOnDemand && !ctx.skip_dns);
        let mut hit = None;
        for rule in &self.rules {
            if rule.applies(ctx, &mut ips, inst).await {
                hit = Some(rule);
                break;
            }
        }
        if hit.is_none()
            && self.strategy == Strategy::IpIfNonMatch
            && ctx.domain.as_deref().is_some_and(|d| !d.is_empty())
            && !ctx.skip_dns
        {
            let mut ips = TargetIps::new(true);
            for rule in &self.rules {
                if rule.applies(ctx, &mut ips, inst).await {
                    hit = Some(rule);
                    break;
                }
            }
        }
        let Some(rule) = hit else {
            return Ok(None);
        };
        let tag = match &rule.balancer {
            Some(balancer) => balancer.pick(inst)?,
            None => rule.outbound.clone(),
        };
        if let Some(hook) = &rule.webhook {
            hook.fire(ctx, &tag);
        }
        Ok(Some((rule, tag)))
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
            "source": ctx.source.map(|s| host(s.ip().to_canonical(), s.port())),
            "destination": destination,
            "originalTarget": null,
            "routeTarget": null,
            "inboundTag": ctx.inbound_tag,
            "inboundName": ctx.inbound_name,
            "inboundLocal": ctx.local.map(|l| host(l.ip().to_canonical(), l.port())),
            "outboundTag": outbound,
            "ts": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default(),
        });
        let hook = self.clone();
        tokio::spawn(async move {
            if let Err(error) = hook.post(event.to_string()).await {
                tracing::warn!("app/router: routing webhook failed > {error:#}");
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
    use crate::config::Config;

    fn ctx(domain: Option<&str>, ip: Option<&str>, protocol: &str) -> Ctx {
        Ctx {
            inbound_tag: "in".into(),
            inbound_name: "vless",
            udp: false,
            source: Some("1.2.3.4:5000".parse().unwrap()),
            local: Some("10.0.0.1:443".parse().unwrap()),
            domain: domain.map(str::to_owned),
            ip: ip.map(|i| i.parse().unwrap()),
            port: 443,
            protocol: protocol.into(),
            user: "alice".into(),
            level: 0,
            vless_route: 0,
            skip_dns: false,
        }
    }

    /// An instance with freedom outbounds named by `tags`, plus `extra` top-level sections.
    fn instance(routing: Value, tags: &[&str], extra: Value) -> Arc<Instance> {
        let outbounds: Vec<Value> = tags
            .iter()
            .map(|t| json!({"tag": t, "protocol": "freedom"}))
            .collect();
        let mut root = json!({"outbounds": outbounds, "routing": routing});
        if let Value::Object(extra) = extra {
            root.as_object_mut().unwrap().extend(extra);
        }
        Instance::new(Config::parse(&root.to_string()).unwrap()).unwrap()
    }

    async fn pick(inst: &Arc<Instance>, c: Ctx) -> Option<String> {
        inst.config
            .router
            .pick(&c, inst)
            .await
            .unwrap()
            .map(|(_, tag)| tag)
    }

    #[tokio::test]
    async fn first_matching_rule_wins() {
        let inst = instance(
            json!({"rules":[
                {"protocol":["bittorrent"],"outboundTag":"block"},
                {"domain":["domain:example.com"],"port":"443","outboundTag":"a"},
                {"ip":["10.0.0.0/8"],"user":["regexp:^al"],"outboundTag":"b"},
                {"inboundTag":["in"],"network":"udp","outboundTag":"c"}
            ]}),
            &["block", "a", "b", "c"],
            Value::Null,
        );
        let inst = &inst;
        assert_eq!(
            pick(inst, ctx(None, Some("8.8.8.8"), "bittorrent"))
                .await
                .as_deref(),
            Some("block")
        );
        assert_eq!(
            pick(inst, ctx(Some("www.example.com"), None, "tls"))
                .await
                .as_deref(),
            Some("a")
        );
        assert_eq!(
            pick(inst, ctx(None, Some("10.1.1.1"), "")).await.as_deref(),
            Some("b")
        );
        assert_eq!(pick(inst, ctx(None, Some("8.8.8.8"), "")).await, None);
        assert!(
            Router::parse(
                &json!({"rules":[{"balancerTag":"x"}]}),
                &mut Loader::default()
            )
            .is_err()
        );
        assert!(Router::parse(&json!({"rules":[{"port":"1"}]}), &mut Loader::default()).is_err());
    }

    #[tokio::test]
    async fn retired_domain_matcher_fields_do_not_change_routing() {
        for legacy in [
            json!("hybrid"),
            json!("linear"),
            json!("mph"),
            json!("unknown"),
            json!(17),
            Value::Null,
        ] {
            let inst = instance(
                json!({"domainMatcher":legacy,"rules":[
                    {"domainMatcher":legacy,"domain":["domain:example.com"],"outboundTag":"matched"},
                    {"domain":["full:other.test"],"outboundTag":"other"}
                ]}),
                &["matched", "other"],
                Value::Null,
            );
            let pick = |d: &str| pick(&inst, ctx(Some(d), None, ""));
            assert_eq!(pick("www.example.com").await.as_deref(), Some("matched"));
            assert_eq!(pick("other.test").await.as_deref(), Some("other"));
            assert!(pick("example.com.evil.test").await.is_none());
        }
        assert!(
            Router::parse(
                &json!({"domainMatcher":"hybrid","unportedFeature":true}),
                &mut Loader::default()
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn ip_strategies_resolve_through_dns_hosts() {
        let dns = json!({"dns": {"hosts": {"site.test": "10.9.9.9"}, "servers": ["localhost"]}});
        let rules = json!([{"ip":["10.9.0.0/16"],"outboundTag":"lan"}]);
        for (strategy, want) in [
            ("AsIs", None),
            ("IPIfNonMatch", Some("lan")),
            ("IPOnDemand", Some("lan")),
        ] {
            let inst = instance(
                json!({"domainStrategy": strategy, "rules": rules}),
                &["direct", "lan"],
                dns.clone(),
            );
            assert_eq!(
                pick(&inst, ctx(Some("site.test"), None, ""))
                    .await
                    .as_deref(),
                want,
                "{strategy}"
            );
            // The DNS module's own queries skip resolution, as SkipDNSResolve does.
            let own = Ctx {
                skip_dns: true,
                ..ctx(Some("site.test"), None, "")
            };
            assert_eq!(pick(&inst, own).await, None);
        }
    }

    #[tokio::test]
    async fn balancers_pick_by_selector_and_strategy() {
        let inst = instance(
            json!({
                "balancers": [
                    {"tag": "rr", "selector": ["px-"], "strategy": {"type": "roundRobin"}},
                    {"tag": "rnd", "selector": ["px-b"]},
                    {"tag": "none", "selector": ["zz"], "fallbackTag": "direct"},
                ],
                "rules": [
                    {"inboundTag": ["rr"], "balancerTag": "rr"},
                    {"inboundTag": ["rnd"], "balancerTag": "rnd"},
                    {"inboundTag": ["none"], "balancerTag": "none"},
                    {"inboundTag": ["both"], "outboundTag": "direct", "balancerTag": "rr"}
                ]
            }),
            &["direct", "px-c", "px-a", "px-b"],
            json!({"observatory": {"subjectSelector": ["px-"]}}),
        );
        let tagged = |t: &str| Ctx {
            inbound_tag: t.into(),
            ..ctx(None, Some("1.1.1.1"), "")
        };
        let mut seen = Vec::new();
        for _ in 0..4 {
            seen.push(pick(&inst, tagged("rr")).await.unwrap());
        }
        assert_eq!(seen, ["px-a", "px-b", "px-c", "px-a"]);
        assert_eq!(pick(&inst, tagged("rnd")).await.as_deref(), Some("px-b"));
        assert_eq!(pick(&inst, tagged("none")).await.as_deref(), Some("direct"));
        assert_eq!(pick(&inst, tagged("both")).await.as_deref(), Some("direct"));
        // leastPing needs an observatory feature, as core.RequireFeatures does.
        let lonely = json!({"outbounds": [{"tag": "a", "protocol": "freedom"}], "routing": {
            "balancers": [{"tag": "b", "selector": ["a"], "strategy": {"type": "leastPing"}}],
            "rules": [{"inboundTag": ["x"], "balancerTag": "b"}]}});
        assert!(Config::parse(&lonely.to_string()).is_err());
    }

    #[test]
    fn least_load_orders_by_cost_then_baselines() {
        let ll = LeastLoad {
            costs: vec![Cost {
                regexp: false,
                find: "slow".into(),
                value: 4.0,
            }],
            cache: Mutex::default(),
            baselines: vec![60_000_000],
            expected: 1,
            max_rtt: 500_000_000,
            tolerance: 0.0,
        };
        let status = |tag: &str, delay: i64| OutboundStatus {
            tag: tag.into(),
            alive: true,
            delay,
            health: None,
        };
        let all = vec![
            status("fast", 50),
            status("slow-1", 40),
            status("mid", 55),
            status("dead", 700),
        ];
        let candidates: Vec<String> = ["fast", "slow-1", "mid", "dead"].map(String::from).to_vec();
        // slow-1 costs 40ms * sqrt(4) = 80ms; dead exceeds maxRTT; baseline 60ms keeps two.
        assert_eq!(ll.pick(&candidates, &all), ["fast", "mid"]);
    }
}

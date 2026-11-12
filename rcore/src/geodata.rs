//! Port of xray-core common/geodata: rule parsing, geoip/geosite .dat files and matchers.
use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, PartialEq, prost::Message)]
struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}
#[derive(Clone, PartialEq, prost::Message)]
struct GeoIp {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    reverse_match: bool,
}
#[derive(Clone, PartialEq, prost::Message)]
struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoIp>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct Attribute {
    #[prost(string, tag = "1")]
    key: String,
}
#[derive(Clone, PartialEq, prost::Message)]
struct DomainEntry {
    #[prost(int32, tag = "1")]
    kind: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attribute: Vec<Attribute>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct GeoSite {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<DomainEntry>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoSite>,
}

/// Locates asset files like Xray: XRAY_LOCATION_ASSET, then next to the binary.
pub fn asset_path(file: &str) -> PathBuf {
    if let Some(dir) =
        std::env::var_os("XRAY_LOCATION_ASSET").or_else(|| std::env::var_os("xray.location.asset"))
    {
        return Path::new(&dir).join(file);
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(file)))
        .unwrap_or_else(|| file.into())
}

/// Caches decoded .dat files for the duration of one config build.
#[derive(Default)]
pub struct Loader {
    ip: HashMap<String, GeoIpList>,
    site: HashMap<String, GeoSiteList>,
}

impl Loader {
    fn geoip(&mut self, file: &str, code: &str) -> Result<GeoIp> {
        if !self.ip.contains_key(file) {
            let bytes = std::fs::read(asset_path(file))
                .with_context(|| format!("failed to open {file}"))?;
            self.ip.insert(
                file.into(),
                prost::Message::decode(bytes.as_slice())
                    .with_context(|| format!("invalid {file}"))?,
            );
        }
        self.ip[file]
            .entry
            .iter()
            .find(|e| e.country_code.eq_ignore_ascii_case(code))
            .cloned()
            .with_context(|| format!("code not found in {file}: {code}"))
    }
    fn geosite(&mut self, file: &str, code: &str) -> Result<GeoSite> {
        if !self.site.contains_key(file) {
            let bytes = std::fs::read(asset_path(file))
                .with_context(|| format!("failed to open {file}"))?;
            self.site.insert(
                file.into(),
                prost::Message::decode(bytes.as_slice())
                    .with_context(|| format!("invalid {file}"))?,
            );
        }
        self.site[file]
            .entry
            .iter()
            .find(|e| e.country_code.eq_ignore_ascii_case(code))
            .cloned()
            .with_context(|| format!("code not found in {file}: {code}"))
    }
}

fn cut_reverse(mut s: &str) -> (&str, bool) {
    let mut reverse = false;
    while let Some(rest) = s.strip_prefix('!') {
        s = rest;
        reverse = !reverse;
    }
    (s, reverse)
}

struct IpRule {
    nets: Vec<IpNet>,
    reverse: bool,
}

/// OR of IP rules; a reversed rule matches IPs outside its set.
#[derive(Default)]
pub struct IpMatcher(Vec<IpRule>);

impl IpMatcher {
    pub fn parse(rules: &[String], loader: &mut Loader) -> Result<Self> {
        let mut out = Vec::new();
        for raw in rules {
            let (rule, reverse) = cut_reverse(raw);
            let rule = match rule.strip_prefix("geoip:") {
                Some(code) => format!("ext:geoip.dat:{code}"),
                None => rule.to_owned(),
            };
            let ext = ["ext:", "ext-ip:"]
                .iter()
                .find_map(|p| rule.strip_prefix(p));
            out.push(match ext {
                Some(spec) => {
                    let (file, code) = spec
                        .split_once(':')
                        .with_context(|| format!("illegal ip rule: {raw}: syntax error"))?;
                    ensure!(!file.is_empty(), "illegal ip rule: {raw}: empty file");
                    let (code, code_reverse) = cut_reverse(code);
                    ensure!(!code.is_empty(), "illegal ip rule: {raw}: empty code");
                    let geo = loader.geoip(file, &code.to_uppercase())?;
                    let nets = geo
                        .cidr
                        .iter()
                        .filter_map(|c| {
                            let ip: IpAddr = match c.ip.len() {
                                4 => <[u8; 4]>::try_from(c.ip.as_slice()).ok()?.into(),
                                16 => <[u8; 16]>::try_from(c.ip.as_slice()).ok()?.into(),
                                _ => return None,
                            };
                            IpNet::new(ip, c.prefix as u8).ok().map(|n| n.trunc())
                        })
                        .collect();
                    IpRule {
                        nets,
                        reverse: (reverse != code_reverse) != geo.reverse_match,
                    }
                }
                None => IpRule {
                    nets: vec![
                        parse_cidr(&rule).with_context(|| format!("illegal ip rule: {raw}"))?,
                    ],
                    reverse,
                },
            });
        }
        Ok(Self(out))
    }
    pub fn matches(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0
            .iter()
            .any(|rule| rule.nets.iter().any(|n| n.contains(&ip)) != rule.reverse)
    }
}

fn parse_cidr(s: &str) -> Result<IpNet> {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, ""));
    let ip: IpAddr = ip
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .context("unsupported address family")?;
    let ip = ip.to_canonical();
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = if prefix.is_empty() {
        max
    } else {
        prefix.parse::<u8>().context("invalid CIDR prefix length")?
    };
    ensure!(
        prefix <= max,
        "CIDR prefix length {prefix} exceeds max {max}"
    );
    Ok(IpNet::new(ip, prefix)?.trunc())
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Substr,
    Regex,
    Domain,
    Full,
}

enum DomainRule {
    Plain(Kind, String),
    Regex(regex::Regex),
}

/// OR of domain rules (Xray DomainMatcher). Matching is case-insensitive.
#[derive(Default)]
pub struct DomainMatcher(Vec<DomainRule>);

impl DomainMatcher {
    pub fn parse(rules: &[String], default: Kind, loader: &mut Loader) -> Result<Self> {
        let mut out = Vec::new();
        for raw in rules {
            let rule = match raw.strip_prefix("geosite:") {
                Some(code) => format!("ext:geosite.dat:{code}"),
                None => raw.clone(),
            };
            let ext = ["ext:", "ext-domain:", "ext-site:"]
                .iter()
                .find_map(|p| rule.strip_prefix(p));
            if let Some(spec) = ext {
                let (file, code) = spec
                    .split_once(':')
                    .with_context(|| format!("illegal domain rule: {raw}: syntax error"))?;
                ensure!(!file.is_empty(), "illegal domain rule: {raw}: empty file");
                ensure!(
                    !code.ends_with('@') && !code.contains("@@"),
                    "illegal domain rule: {raw}: empty attr"
                );
                let (code, attrs) = code.split_once('@').unwrap_or((code, ""));
                ensure!(!code.is_empty(), "illegal domain rule: {raw}: empty code");
                let attrs: Vec<String> = attrs
                    .split('@')
                    .filter(|a| !a.is_empty())
                    .map(str::to_lowercase)
                    .collect();
                for entry in loader.geosite(file, &code.to_uppercase())?.domain {
                    if !attrs.iter().all(|a| {
                        entry
                            .attribute
                            .iter()
                            .any(|x| x.key.eq_ignore_ascii_case(a))
                    }) {
                        continue;
                    }
                    let kind = match entry.kind {
                        0 => Kind::Substr,
                        1 => Kind::Regex,
                        2 => Kind::Domain,
                        3 => Kind::Full,
                        other => bail!("unknown domain type {other} in {file}"),
                    };
                    out.push(Self::rule(kind, &entry.value)?);
                }
                continue;
            }
            let (kind, value) = if let Some(v) = rule.strip_prefix("regexp:") {
                (Kind::Regex, v.to_owned())
            } else if let Some(v) = rule.strip_prefix("domain:") {
                (Kind::Domain, v.to_owned())
            } else if let Some(v) = rule.strip_prefix("full:") {
                (Kind::Full, v.to_owned())
            } else if let Some(v) = rule.strip_prefix("keyword:") {
                (Kind::Substr, v.to_owned())
            } else if let Some(v) = rule.strip_prefix("dotless:") {
                ensure!(
                    !v.contains('.'),
                    "illegal domain rule: {raw}: substr in dotless rule should not contain a dot"
                );
                (
                    Kind::Regex,
                    if v.is_empty() {
                        "^[^.]*$".into()
                    } else {
                        format!("^[^.]*{v}[^.]*$")
                    },
                )
            } else {
                (default, rule.clone())
            };
            out.push(
                Self::rule(kind, &value).with_context(|| format!("illegal domain rule: {raw}"))?,
            );
        }
        Ok(Self(out))
    }
    fn rule(kind: Kind, value: &str) -> Result<DomainRule> {
        Ok(match kind {
            Kind::Regex => DomainRule::Regex(regex::Regex::new(value)?),
            kind => DomainRule::Plain(kind, value.to_lowercase()),
        })
    }
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        self.0.iter().any(|rule| match rule {
            DomainRule::Regex(re) => re.is_match(&domain),
            DomainRule::Plain(Kind::Full, v) => domain == *v,
            DomainRule::Plain(Kind::Domain, v) => {
                domain == *v
                    || (domain.len() > v.len()
                        && domain.ends_with(v.as_str())
                        && domain.as_bytes()[domain.len() - v.len() - 1] == b'.')
            }
            DomainRule::Plain(_, v) => domain.contains(v.as_str()),
        })
    }
}

/// xray-core common/geodata/consts.go private IP list, used by freedom's default final rule.
pub fn private_ips() -> IpMatcher {
    let list = [
        "0.0.0.0/8",
        "0.0.0.0/32",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/29",
        "192.0.0.8/32",
        "192.0.0.9/32",
        "192.0.0.10/32",
        "192.0.0.170/32",
        "192.0.0.171/32",
        "192.0.2.0/24",
        "192.52.193.0/24",
        "192.88.99.2/32",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "224.0.0.0/4",
        "::1/128",
        "::/128",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "100:0:0:1::/64",
        "2001::/32",
        "2001:1::1/128",
        "2001:1::2/128",
        "2001:1::3/128",
        "2001:2::/48",
        "2001:3::/32",
        "2001:20::/28",
        "2001:30::/28",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ];
    IpMatcher::parse(&list.map(String::from), &mut Loader::default()).expect("valid private list")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn custom_rules_follow_xray_syntax() {
        let mut loader = Loader::default();
        let d = DomainMatcher::parse(
            &[
                "domain:example.com",
                "full:exact.org",
                "keyword:tube",
                "regexp:^a+b$",
                "plain",
            ]
            .map(String::from),
            Kind::Substr,
            &mut loader,
        )
        .unwrap();
        for hit in [
            "example.com",
            "Sub.Example.COM",
            "exact.org",
            "youtube.com",
            "aab",
            "explainer.net",
        ] {
            assert!(d.matches(hit), "{hit}");
        }
        for miss in ["notexample.com", "a.exact.org", "aabc"] {
            assert!(!d.matches(miss), "{miss}");
        }
        let ip = IpMatcher::parse(
            &["10.0.0.0/8", "!192.168.0.0/16", "2001:db8::1"].map(String::from),
            &mut loader,
        )
        .unwrap();
        assert!(ip.matches("10.1.2.3".parse().unwrap()));
        assert!(ip.matches("8.8.8.8".parse().unwrap()));
        assert!(ip.matches("2001:db8::1".parse().unwrap()));
        let only = IpMatcher::parse(&["!192.168.0.0/16".into()], &mut loader).unwrap();
        assert!(!only.matches("192.168.1.1".parse().unwrap()));
        assert!(private_ips().matches("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!private_ips().matches("1.1.1.1".parse().unwrap()));
        assert!(DomainMatcher::parse(&["dotless:a.b".into()], Kind::Substr, &mut loader).is_err());
    }
}

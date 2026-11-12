#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn groups_traffic_without_mixing_in_online_or_other_entities() {
        let stats = vec![
            Stat {
                name: "user>>>alice>>>traffic>>>uplink".into(),
                value: 14,
            },
            Stat {
                name: "user>>>alice>>>traffic>>>downlink".into(),
                value: 7,
            },
            Stat {
                name: "user>>>alice>>>online".into(),
                value: 1,
            },
            Stat {
                name: "user>>>bob>>>traffic>>>uplink".into(),
                value: 0,
            },
            Stat {
                name: "outbound>>>direct>>>traffic>>>uplink".into(),
                value: 30,
            },
        ];
        assert_eq!(
            traffic(stats, "user", None).unwrap(),
            json!([{"username":"alice","uplink":14,"downlink":7}])
        );
    }
    #[test]
    fn validates_every_user_before_building_any_mutation() {
        let body = json!({"data":[{"type":"trojan","tag":"tls","username":"a","password":"secret"}, {"type":"bogus","tag":"tls","username":"a"}],"hashData":{"vlessUuid":"550e8400-e29b-41d4-a716-446655440000"}});
        assert!(additions(&body, false).is_err());
    }
    #[test]
    fn rejects_non_boolean_reset_before_resetting_stats() {
        assert!(reset(&json!({"reset":"false"})).is_err());
        assert!(reset(&json!({"reset":true})).unwrap());
    }
    #[test]
    fn builds_all_five_account_types() {
        for (kind, expected) in [
            ("trojan", "xray.proxy.trojan.Account"),
            ("vless", "xray.proxy.vless.Account"),
            ("shadowsocks", "xray.proxy.shadowsocks.Account"),
            ("shadowsocks22", "xray.proxy.shadowsocks_2022.Account"),
            ("hysteria", "xray.proxy.hysteria.account.Account"),
        ] {
            let item = json!({"type":kind,"tag":"in","username":"user","password":"secret","uuid":"550e8400-e29b-41d4-a716-446655440000","flow":"","cipherType":7,"ivCheck":true});
            let user = make_user(&item).unwrap();
            assert_eq!(user.account.unwrap().r#type, expected);
        }
    }
}

use crate::{core::Core, grpc::*};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ipnet::IpNet;
use prost::Message;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command};

fn string<'a>(body: &'a Value, key: &str) -> Result<&'a str> {
    let value = body
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("{key} must be a string"))?;
    ensure!(!value.is_empty(), "{key} must not be empty");
    Ok(value)
}
fn identity<'a>(body: &'a Value, key: &str) -> Result<&'a str> {
    let value = string(body, key)?;
    ensure!(
        !value.contains(">>>") && !value.chars().any(char::is_control),
        "{key} contains invalid characters"
    );
    Ok(value)
}
fn uuid(body: &Value, key: &str) -> Result<String> {
    let value = string(body, key)?;
    let parsed = uuid::Uuid::parse_str(value).with_context(|| format!("{key} must be a UUID"))?;
    ensure!(value.len() == 36, "{key} must be a hyphenated UUID");
    Ok(parsed.to_string())
}
fn array<'a>(body: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    body.get(key)
        .and_then(Value::as_array)
        .with_context(|| format!("{key} must be an array"))
}
fn strings(body: &Value, key: &str) -> Result<Vec<String>> {
    array(body, key)?
        .iter()
        .map(|v| {
            let s = v.as_str().context("array entry must be a string")?;
            ensure!(
                !s.is_empty() && !s.contains(">>>") && !s.chars().any(char::is_control),
                "invalid {key} entry"
            );
            Ok(s.to_owned())
        })
        .collect()
}
fn reset(body: &Value) -> Result<bool> {
    body.get("reset")
        .and_then(Value::as_bool)
        .context("reset must be a boolean")
}
fn flow(body: &Value) -> Result<String> {
    let flow = body
        .get("flow")
        .and_then(Value::as_str)
        .context("flow must be a string")?;
    ensure!(
        matches!(flow, "" | "xtls-rprx-vision"),
        "unsupported VLESS flow"
    );
    Ok(flow.into())
}
fn make_user(item: &Value) -> Result<User> {
    let email = identity(item, "username")?.to_owned();
    identity(item, "tag")?;
    let kind = string(item, "type")?;
    let account = match kind {
        "vless" => typed(
            "xray.proxy.vless.Account",
            &VlessAccount {
                id: uuid(item, "uuid")?,
                flow: flow(item)?,
                encryption: "none".into(),
            },
        ),
        "trojan" => typed(
            "xray.proxy.trojan.Account",
            &SingleString {
                value: string(item, "password")?.into(),
            },
        ),
        "hysteria" => typed(
            "xray.proxy.hysteria.account.Account",
            &SingleString {
                value: string(item, "password")?.into(),
            },
        ),
        "shadowsocks22" => typed(
            "xray.proxy.shadowsocks_2022.Account",
            &SingleString {
                value: string(item, "password")?.into(),
            },
        ),
        "shadowsocks" => {
            let cipher = item
                .get("cipherType")
                .and_then(Value::as_i64)
                .context("cipherType must be an integer")?;
            ensure!(
                matches!(cipher, -1 | 0 | 5 | 6 | 7 | 8),
                "unsupported Shadowsocks cipherType"
            );
            ensure!(
                item.get("ivCheck").and_then(Value::as_bool).is_some(),
                "ivCheck must be a boolean"
            );
            typed(
                "xray.proxy.shadowsocks.Account",
                &ShadowsocksAccount {
                    password: string(item, "password")?.into(),
                    cipher_type: cipher as i32,
                    iv_check: false,
                },
            )
        }
        _ => bail!("unsupported user type: {kind}"),
    };
    Ok(User {
        level: 0,
        email,
        account: Some(account),
    })
}
struct Addition {
    username: String,
    old_hash: String,
    hash: String,
    accounts: Vec<(String, User)>,
    drop_old: bool,
}
fn additions(body: &Value, bulk: bool) -> Result<(Vec<String>, Vec<Addition>)> {
    if !bulk {
        let hash = uuid(&body["hashData"], "vlessUuid")?;
        let previous = body["hashData"]
            .get("prevVlessUuid")
            .map(|_| uuid(&body["hashData"], "prevVlessUuid"))
            .transpose()?;
        let data = array(body, "data")?;
        ensure!(!data.is_empty(), "data must contain at least one user");
        let accounts: Vec<_> = data
            .iter()
            .map(|item| Ok((identity(item, "tag")?.to_owned(), make_user(item)?)))
            .collect::<Result<_>>()?;
        let username = accounts[0].1.email.clone();
        ensure!(
            accounts.iter().all(|(_, user)| user.email == username),
            "all data entries must have the same username"
        );
        let tags = accounts.iter().map(|(tag, _)| tag.clone()).collect();
        return Ok((
            tags,
            vec![Addition {
                username,
                old_hash: previous.clone().unwrap_or_else(|| hash.clone()),
                hash,
                accounts,
                drop_old: previous.is_some(),
            }],
        ));
    }
    let tags = strings(body, "affectedInboundTags")?;
    let users=array(body,"users")?.iter().map(|entry|{
        let data=&entry["userData"];
        let username=identity(data,"userId")?.to_owned();
        let old_hash=uuid(data,"hashUuid")?;
        let hash=uuid(data,"vlessUuid")?;
        let trojan=string(data,"trojanPassword")?;
        let ss=string(data,"ssPassword")?;
        let accounts=array(entry,"inboundData")?.iter().map(|item|{
            let tag=identity(item,"tag")?.to_owned();
            ensure!(tags.contains(&tag),"inboundData tag must be in affectedInboundTags");
            let kind=string(item,"type")?;
            let password=match kind {"trojan"=>trojan.to_owned(),"shadowsocks22"=>STANDARD.encode(ss),"hysteria"=>hash.clone(),_=>ss.to_owned()};
            let mut normalized=json!({"type":kind,"tag":tag,"username":username,"password":password,"uuid":hash,"cipherType":0,"ivCheck":false});
            if kind=="vless" { normalized["flow"]=json!(flow(item)?); }
            Ok((tag,make_user(&normalized)?))
        }).collect::<Result<Vec<_>>>()?;
        Ok(Addition{username,old_hash,hash,accounts,drop_old:false})
    }).collect::<Result<_>>()?;
    Ok((tags, users))
}
fn resolve_ciphers(users: &mut [Addition], ciphers: &HashMap<String, i32>) -> Result<()> {
    for user in users {
        for (tag, user) in &mut user.accounts {
            let account = user.account.as_mut().context("missing user account")?;
            if account.r#type == "xray.proxy.shadowsocks.Account" {
                let mut ss = ShadowsocksAccount::decode(account.value.as_slice())?;
                if ss.cipher_type == 0 {
                    ss.cipher_type= *ciphers.get(tag).with_context(||format!("Shadowsocks cipher for {tag} is unknown; use add-user with an explicit cipherType"))?;
                }
                ensure!(
                    matches!(ss.cipher_type, 5..=8),
                    "unsupported Shadowsocks cipherType"
                );
                account.value = ss.encode_to_vec();
            }
        }
    }
    Ok(())
}
fn removals(body: &Value, bulk: bool) -> Result<Vec<(String, String)>> {
    if !bulk {
        return Ok(vec![(
            identity(body, "username")?.to_owned(),
            uuid(&body["hashData"], "vlessUuid")?,
        )]);
    }
    array(body, "users")?
        .iter()
        .map(|v| Ok((identity(v, "userId")?.to_owned(), uuid(v, "hashUuid")?)))
        .collect()
}
fn traffic(stats: Vec<Stat>, kind: &str, tag: Option<&str>) -> Result<Value> {
    let mut values: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    for stat in stats {
        let parts: Vec<_> = stat.name.split(">>>").collect();
        if parts.len() != 4
            || parts[0] != kind
            || parts[2] != "traffic"
            || !matches!(parts[3], "uplink" | "downlink")
            || tag.is_some_and(|tag| tag != parts[1])
        {
            continue;
        }
        ensure!(stat.value >= 0, "Xray returned a negative traffic counter");
        let counters = values.entry(parts[1].into()).or_default();
        let target = if parts[3] == "uplink" {
            &mut counters.0
        } else {
            &mut counters.1
        };
        *target = target
            .checked_add(stat.value)
            .context("traffic counter overflow")?;
    }
    let key = if kind == "user" { "username" } else { kind };
    Ok(Value::Array(
        values
            .into_iter()
            .filter(|(_, (up, down))| kind != "user" || *up != 0 || *down != 0)
            .map(|(name, (up, down))| json!({key:name,"uplink":up,"downlink":down}))
            .collect(),
    ))
}
fn online(response: StatResponse) -> Result<bool> {
    let stat = response
        .stat
        .context("Xray online response contains no stat")?;
    ensure!(stat.value >= 0, "Xray returned a negative online counter");
    Ok(stat.value > 0)
}
fn dated_ips(ips: impl IntoIterator<Item = (String, i64)>) -> Result<Value> {
    let mut ips = ips
        .into_iter()
        .map(|(ip, seen)| {
            ip.parse::<IpAddr>()
                .context("Xray returned an invalid IP")?;
            let date = chrono::DateTime::from_timestamp(seen, 0)
                .context("Xray returned an invalid lastSeen timestamp")?;
            Ok(json!({"ip":ip,"lastSeen":date.to_rfc3339_opts(chrono::SecondsFormat::Millis,true)}))
        })
        .collect::<Result<Vec<_>>>()?;
    ips.sort_by(|a, b| a["ip"].as_str().cmp(&b["ip"].as_str()));
    Ok(json!(ips))
}
async fn users_ips(grpc: &mut Grpc) -> Result<Value> {
    let response: Result<UsersResponse> = grpc
        .call(
            "/xray.app.stats.command.StatsService/GetUsersStats",
            UsersRequest {
                include_traffic: false,
                reset: false,
            },
        )
        .await;
    match response {
        Ok(response) => Ok(
            json!({"users":response.users.into_iter().map(|u|Ok(json!({"userId":u.email,"ips":dated_ips(u.ips.into_iter().map(|ip|(ip.ip,ip.last_seen)))?}))).collect::<Result<Vec<_>>>()?}),
        ),
        Err(e)
            if e.downcast_ref::<tonic::Status>()
                .is_some_and(|s| s.code() == tonic::Code::Unimplemented) =>
        {
            let users: OnlineUsers = grpc
                .call(
                    "/xray.app.stats.command.StatsService/GetAllOnlineUsers",
                    Empty {},
                )
                .await?;
            let mut result = Vec::new();
            for name in users.users.into_iter().collect::<HashSet<_>>() {
                let username = name
                    .strip_prefix("user>>>")
                    .and_then(|n| n.strip_suffix(">>>online"))
                    .context("invalid online metric name")?;
                result.push(
                    json!({"userId":username,"ips":dated_ips(grpc.ips(username,false).await?)?}),
                );
            }
            Ok(json!({"users":result}))
        }
        Err(e) => Err(e),
    }
}
pub(crate) fn automatic_drop_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|line| line.strip_prefix("CapEff:\t"))
                    .map(str::to_owned)
            })
            .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
            .is_some_and(|cap| cap & (1 << 12) != 0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
fn drop_targets(ips: Vec<String>, whitelist: &[IpNet]) -> Result<HashSet<IpAddr>> {
    let ips = ips
        .iter()
        .map(|ip| ip.parse::<IpAddr>().context("invalid IP address"))
        .collect::<Result<HashSet<_>>>()?;
    Ok(ips
        .into_iter()
        .filter(|ip| !crate::plugins::listed(whitelist, *ip))
        .collect())
}
pub(crate) async fn drop_ips(ips: Vec<String>, whitelist: &[IpNet]) -> Result<()> {
    let ips = drop_targets(ips, whitelist)?;
    ensure!(
        cfg!(target_os = "linux"),
        "connection dropping requires Linux ss -K and CAP_NET_ADMIN"
    );
    for ip in ips {
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            Command::new("ss")
                .stdout(std::process::Stdio::null())
                .args(["-K", "dst", &ip.to_string()])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .context("ss -K timed out")?
        .context("execute ss -K")?;
        ensure!(
            output.status.success() && output.stderr.is_empty(),
            "ss -K failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
async fn geocheck(body: &Value) -> Result<Value> {
    let ip = body
        .get("ip")
        .map(|v| v.as_str().context("ip must be a string"))
        .transpose()?
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let interface = body
        .get("interface")
        .map(|v| v.as_str().context("interface must be a string"))
        .transpose()?
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(ip) = ip {
        ip.parse::<IpAddr>().context("invalid geocheck IP")?;
    }
    if let Some(interface) = interface {
        ensure!(
            interface.len() <= 64
                && interface
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c)),
            "invalid interface"
        );
    }
    let mut command = Command::new("/usr/local/bin/geocheck");
    if let Some(bind) = ip.or(interface) {
        command.args(["--interface", bind]);
    }
    command
        .args(["--json", "--svg-base64", "--quiet"])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().context("execute geocheck")?;
    let stdout = child.stdout.take().context("geocheck stdout")?;
    let stderr = child.stderr.take().context("geocheck stderr")?;
    let run = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut stdout = stdout.take(32 * 1024 * 1024 + 1);
        let mut stderr = stderr.take(65537);
        let (a, b) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
        a?;
        b?;
        ensure!(
            out.len() <= 32 * 1024 * 1024 && err.len() <= 65536,
            "geocheck output exceeds size limit"
        );
        ensure!(
            child.wait().await?.success(),
            "geocheck failed: {}",
            String::from_utf8_lossy(&err)
        );
        let report: Value = serde_json::from_slice(&out).context("invalid geocheck report")?;
        ensure!(
            report["image"]["data"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "geocheck report carries no image"
        );
        Ok(report)
    };
    tokio::time::timeout(Duration::from_secs(45), run)
        .await
        .context("geocheck timed out")?
}

pub async fn handle(path: &str, body: &Value, core: &mut Core) -> Result<Value> {
    handle_with_whitelist(path, body, core, &[]).await
}

pub async fn handle_with_whitelist(
    path: &str,
    body: &Value,
    core: &mut Core,
    whitelist: &[IpNet],
) -> Result<Value> {
    if path == "/node/stats/get-geocheck" {
        return geocheck(body).await;
    }
    if path == "/node/handler/drop-ips" {
        let ips = strings(body, "ips")?;
        ensure!(!ips.is_empty(), "ips must not be empty");
        drop_ips(ips, whitelist).await?;
        return Ok(json!({"success":true}));
    }
    if matches!(path, "/node/handler/add-user" | "/node/handler/add-users") {
        let (tags, mut users) = additions(body, path.ends_with("add-users"))?;
        resolve_ciphers(&mut users, &core.inbound_ciphers)?;
        let mut grpc = Grpc::connect(&core.endpoint).await?;
        let tags: HashSet<_> = core.inbounds.keys().cloned().chain(tags).collect();
        for user in users {
            let ips = if user.drop_old && automatic_drop_available() {
                Some(grpc.ips(&user.username, true).await?)
            } else {
                None
            };
            for tag in &tags {
                grpc.remove(tag, &user.username)
                    .await
                    .with_context(|| format!("remove user from {tag}"))?;
                core.inbounds
                    .entry(tag.clone())
                    .or_default()
                    .remove(&user.old_hash);
            }
            if let Some(ips) = ips {
                drop_ips(ips.into_keys().collect(), whitelist).await?;
            }
            for (tag, account) in user.accounts {
                grpc.add(&tag, account)
                    .await
                    .with_context(|| format!("add user to {tag}"))?;
                core.inbounds
                    .entry(tag)
                    .or_default()
                    .insert(user.hash.clone());
            }
        }
        return Ok(json!({"success":true,"error":null}));
    }
    if matches!(
        path,
        "/node/handler/remove-user" | "/node/handler/remove-users"
    ) {
        let users = removals(body, path.ends_with("remove-users"))?;
        if core.inbounds.is_empty() {
            return Ok(json!({"success":true,"error":null}));
        }
        let mut grpc = Grpc::connect(&core.endpoint).await?;
        for (username, hash) in users {
            let ips = if automatic_drop_available() {
                Some(grpc.ips(&username, true).await?)
            } else {
                None
            };
            for (tag, hashes) in &mut core.inbounds {
                grpc.remove(tag, &username)
                    .await
                    .with_context(|| format!("remove user from {tag}"))?;
                hashes.remove(&hash);
            }
            if let Some(ips) = ips {
                drop_ips(ips.into_keys().collect(), whitelist).await?;
            }
        }
        return Ok(json!({"success":true,"error":null}));
    }
    if path == "/node/handler/drop-users-connections" {
        let users = strings(body, "userIds")?;
        ensure!(!users.is_empty(), "userIds must not be empty");
        ensure!(
            cfg!(target_os = "linux"),
            "connection dropping requires Linux ss -K and CAP_NET_ADMIN"
        );
        let mut grpc = Grpc::connect(&core.endpoint).await?;
        let mut ips = Vec::new();
        for user in users {
            ips.extend(grpc.ips(&user, true).await?.into_keys());
        }
        drop_ips(ips, whitelist).await?;
        return Ok(json!({"success":true}));
    }
    match path {
        "/node/stats/get-user-online-status" => {
            let name = format!("user>>>{}>>>online", identity(body, "username")?);
            let mut grpc = Grpc::connect(&core.endpoint).await?;
            let result: Result<StatResponse> = grpc
                .call(
                    "/xray.app.stats.command.StatsService/GetStatsOnline",
                    StatsRequest { name, reset: false },
                )
                .await;
            match result {
                Ok(response) => Ok(json!({"isOnline":online(response)?})),
                Err(e) if is_not_found(&e) => Ok(json!({"isOnline":false})),
                Err(e) => Err(e),
            }
        }
        "/node/stats/get-user-ip-list" => {
            let user = identity(body, "userId")?;
            let mut grpc = Grpc::connect(&core.endpoint).await?;
            Ok(json!({"ips":dated_ips(grpc.ips(user,true).await?)?}))
        }
        "/node/stats/get-users-ip-list" => {
            users_ips(&mut Grpc::connect(&core.endpoint).await?).await
        }
        "/node/stats/get-system-stats" => {
            let xray = Grpc::connect(&core.endpoint).await?.sys_stats().await?;
            Ok(
                json!({"xrayInfo":xray,"plugins":{"torrentBlocker":{"reportsCount":0}},"system":{"stats":crate::core::system_stats()}}),
            )
        }
        "/node/stats/get-users-stats"
        | "/node/stats/get-inbound-stats"
        | "/node/stats/get-outbound-stats"
        | "/node/stats/get-all-inbounds-stats"
        | "/node/stats/get-all-outbounds-stats"
        | "/node/stats/get-combined-stats" => {
            let reset = reset(body)?;
            let tag = if matches!(
                path,
                "/node/stats/get-inbound-stats" | "/node/stats/get-outbound-stats"
            ) {
                Some(identity(body, "tag")?)
            } else {
                None
            };
            let mut grpc = Grpc::connect(&core.endpoint).await?;
            if path.ends_with("get-combined-stats") {
                return Ok(
                    json!({"inbounds":traffic(grpc.query("inbound>>>",reset).await?,"inbound",None)?,"outbounds":traffic(grpc.query("outbound>>>",reset).await?,"outbound",None)?}),
                );
            }
            let (kind, key) = if path.contains("inbound") {
                ("inbound", "inbounds")
            } else if path.contains("outbound") {
                ("outbound", "outbounds")
            } else {
                ("user", "users")
            };
            let pattern =
                tag.map_or_else(|| format!("{kind}>>>"), |tag| format!("{kind}>>>{tag}>>>"));
            let result = traffic(grpc.query(&pattern, reset).await?, kind, tag)?;
            if tag.is_some() {
                result
                    .as_array()
                    .and_then(|v| v.first())
                    .cloned()
                    .context("Xray traffic stats not found")
            } else {
                Ok(json!({key:result}))
            }
        }
        _ => bail!("unknown operation: {path}"),
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;
    #[test]
    fn online_status_requires_positive_real_counter() {
        for (value, expected) in [(0, false), (1, true), (2, true)] {
            assert_eq!(
                online(StatResponse {
                    stat: Some(Stat {
                        name: "user>>>alice>>>online".into(),
                        value
                    })
                })
                .unwrap(),
                expected
            );
        }
        assert!(online(StatResponse { stat: None }).is_err());
        assert!(
            online(StatResponse {
                stat: Some(Stat {
                    name: String::new(),
                    value: -1
                })
            })
            .is_err()
        );
    }
    #[test]
    fn bulk_legacy_shadowsocks_uses_configured_cipher_before_mutating() {
        let body = json!({"affectedInboundTags":["ss"],"users":[{"inboundData":[{"tag":"ss","type":"shadowsocks"}],"userData":{"userId":"alice","hashUuid":"550e8400-e29b-41d4-a716-446655440000","vlessUuid":"550e8400-e29b-41d4-a716-446655440000","trojanPassword":"secret","ssPassword":"secret"}}]});
        let (_, mut users) = additions(&body, true).unwrap();
        assert!(resolve_ciphers(&mut users, &HashMap::new()).is_err());
        resolve_ciphers(&mut users, &HashMap::from([("ss".into(), 5)])).unwrap();
        assert_eq!(
            ShadowsocksAccount::decode(
                users[0].accounts[0]
                    .1
                    .account
                    .as_ref()
                    .unwrap()
                    .value
                    .as_slice()
            )
            .unwrap()
            .cipher_type,
            5
        );
    }
    #[test]
    fn validates_all_drop_targets_and_preserves_whitelist() {
        let whitelist = ["192.0.2.0/24".parse().unwrap()];
        assert_eq!(
            drop_targets(
                vec![
                    "192.0.2.9".into(),
                    "::1".into(),
                    "2001:db8::1".into(),
                    "2001:db8::1".into()
                ],
                &whitelist
            )
            .unwrap(),
            HashSet::from(["2001:db8::1".parse().unwrap()])
        );
        assert!(
            drop_targets(
                vec!["127.0.0.1".into(), "1.2.3.4; rm -rf /".into()],
                &whitelist
            )
            .is_err()
        );
    }
    use prost::Message;
    #[test]
    fn bulk_shadowsocks22_uses_base64_of_ss_password_and_validates_all_fields() {
        let mut body = json!({"affectedInboundTags":["ss"],"users":[{"inboundData":[{"tag":"ss","type":"shadowsocks22"}],"userData":{"userId":"alice","hashUuid":"550e8400-e29b-41d4-a716-446655440000","vlessUuid":"550e8400-e29b-41d4-a716-446655440001","trojanPassword":"secret","ssPassword":"0123456789012345"}}]});
        let (_, users) = additions(&body, true).unwrap();
        let account = users[0].accounts[0].1.account.as_ref().unwrap();
        assert_eq!(
            SingleString::decode(account.value.as_slice())
                .unwrap()
                .value,
            "MDEyMzQ1Njc4OTAxMjM0NQ=="
        );
        body["users"][0]["userData"]["hashUuid"] = json!("invalid");
        assert!(additions(&body, true).is_err());
    }
    #[test]
    fn serializes_ip_timestamp_as_panel_iso_date() {
        assert_eq!(
            dated_ips(vec![("127.0.0.1".into(), 0)]).unwrap(),
            json!([{"ip":"127.0.0.1","lastSeen":"1970-01-01T00:00:00.000Z"}])
        );
        assert!(dated_ips(vec![("not-an-ip".into(), 0)]).is_err());
    }
    #[tokio::test]
    async fn malformed_mutations_never_touch_core_or_connect() {
        let mut core = Core::new(
            "/missing".into(),
            "/missing".into(),
            "http://unreachable.invalid:1".into(),
        );
        core.inbounds
            .insert("in".into(), HashSet::from(["original".into()]));
        let old = core.inbounds.clone();
        for (path, body) in [
            (
                "/node/handler/add-user",
                json!({"data":[],"hashData":{"vlessUuid":"invalid"}}),
            ),
            (
                "/node/handler/add-users",
                json!({"affectedInboundTags":["new"],"users":[{"inboundData":[],"userData":{"userId":"alice","hashUuid":"invalid"}}]}),
            ),
            (
                "/node/handler/remove-users",
                json!({"users":[{"userId":"alice","hashUuid":"550e8400-e29b-41d4-a716-446655440000"},{"userId":"bob","hashUuid":true}]}),
            ),
            ("/node/stats/get-users-stats", json!({"reset":"true"})),
        ] {
            let error = handle(path, &body, &mut core).await.unwrap_err();
            assert!(!error.to_string().contains("connect"), "{error:#}");
            assert_eq!(core.inbounds, old);
        }
    }
}

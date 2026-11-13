//! The DNS module, the dns outbound, DNS-backed domain strategies and observatory-driven
//! balancers, run on rcore and (with XRAY_BINARY) on Go Xray from the same config.
//! DNS answers must match Go's byte for byte.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
};

const ID: [u8; 16] = [1; 16];
const UUID: &str = "01010101-0101-0101-0101-010101010101";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start(dir: &Path, name: &str, binary: &str, config: &Value, port: u16) -> Result<Child> {
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, config.to_string())?;
    let log = std::fs::File::create(dir.join(format!("{name}.log")))?;
    let child = Command::new(binary)
        .args(["run", "-config"])
        .arg(path)
        .kill_on_drop(true)
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(child);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("{name} failed to listen")
}

/// A raw VLESS request to `host` (IPv4 text or a domain).
async fn vless(port: u16, host: &str, dest: u16, udp: bool) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let mut request = vec![0];
    request.extend_from_slice(&ID);
    request.extend_from_slice(&[0, if udp { 2 } else { 1 }]);
    request.extend_from_slice(&dest.to_be_bytes());
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            request.extend_from_slice(&[2, host.len() as u8]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    stream.write_all(&request).await?;
    Ok(stream)
}

fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = id.to_be_bytes().to_vec();
    m.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    m
}

/// The question section's end in a message without compression in its question.
fn question_end(m: &[u8]) -> usize {
    let mut off = 12;
    while m[off] != 0 {
        off += 1 + m[off] as usize;
    }
    off + 5
}

/// A fake upstream: A -> 192.0.2.7, AAAA -> 2001:db8::7 (TTL 120), anything else NOERROR and
/// empty. Records every query it gets.
async fn upstream() -> Result<(u16, Arc<Mutex<Vec<Vec<u8>>>>)> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let port = socket.local_addr()?.port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let q = buf[..n].to_vec();
            log.lock().unwrap().push(q.clone());
            let end = question_end(&q);
            let qtype = u16::from_be_bytes([q[end - 4], q[end - 3]]);
            let rdata: Vec<u8> = match qtype {
                1 => vec![192, 0, 2, 7],
                28 => "2001:db8::7"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec(),
                _ => Vec::new(),
            };
            let mut r = q[..2].to_vec();
            r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, (!rdata.is_empty()) as u8, 0, 0, 0, 0]);
            r.extend_from_slice(&q[12..end]);
            if !rdata.is_empty() {
                r.extend_from_slice(&[0xc0, 12]);
                r.extend_from_slice(&qtype.to_be_bytes());
                r.extend_from_slice(&[0, 1, 0, 0, 0, 120]);
                r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                r.extend_from_slice(&rdata);
            }
            let _ = socket.send_to(&r, peer).await;
        }
    });
    Ok((port, seen))
}

async fn tcp_echo() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                tokio::io::copy(&mut r, &mut w).await.ok();
            });
        }
    });
    Ok(port)
}

/// One TCP round trip through the node to `host:port`.
async fn echo_through(node: u16, host: &str, port: u16) -> Result<()> {
    let mut s = vless(node, host, port, false).await?;
    s.write_all(b"through the node").await?;
    let mut back = [0u8; 18];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut back))
        .await
        .context("echo timeout")??;
    ensure!(
        back[..2] == [0, 0] && &back[2..] == b"through the node",
        "echo {back:?}"
    );
    Ok(())
}

fn dns_config(node: u16, fake: u16, access: &Path) -> Value {
    json!({
        "log": {"loglevel": "debug", "access": access.to_str().unwrap()},
        "dns": {
            "tag": "dns-module",
            "hosts": {"hosts.test": "10.1.2.3", "alias.test": "hosts.test", "nx.test": "#3",
                      "echo.test": "127.0.0.1"},
            "servers": [{"address": "127.0.0.1", "port": fake, "clientIp": "203.0.113.77"}]
        },
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": node, "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": "none"}}],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom",
             "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}},
            {"tag": "dns-out", "protocol": "dns", "settings": {"address": "127.0.0.1", "port": fake,
             "rules": [
                {"action": "return", "qType": 16, "rCode": 3},
                {"action": "drop", "domain": ["full:drop.test"]},
                {"action": "direct", "qType": 15}
             ]}},
            {"tag": "resolved", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4",
             "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}},
            {"tag": "blocked", "protocol": "blackhole"}
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            {"port": 53, "outboundTag": "dns-out"},
            {"inboundTag": ["dns-module"], "outboundTag": "direct"},
            {"domain": ["full:echo.test"], "outboundTag": "resolved"},
            {"ip": ["10.1.2.0/24"], "outboundTag": "blocked"}
        ]}
    })
}

/// The answers to each query over one VLESS UDP session to 1.1.1.1:53 (`None`: no answer).
async fn ask(node: u16, queries: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
    let mut s = vless(node, "1.1.1.1", 53, true).await?;
    let mut header = false;
    let mut answers = Vec::new();
    for q in queries {
        s.write_all(&(q.len() as u16).to_be_bytes()).await?;
        s.write_all(q).await?;
        let read = async {
            if !header {
                let mut h = [0u8; 2];
                s.read_exact(&mut h).await?;
                ensure!(h == [0, 0], "VLESS response header {h:?}");
                header = true;
            }
            let len = s.read_u16().await?;
            let mut m = vec![0u8; len as usize];
            s.read_exact(&mut m).await?;
            anyhow::Ok(m)
        };
        answers.push(
            match tokio::time::timeout(Duration::from_secs(2), read).await {
                Ok(m) => Some(m?),
                Err(_) => None,
            },
        );
    }
    Ok(answers)
}

fn queries() -> Vec<Vec<u8>> {
    vec![
        query(1, "hosts.test", 1),
        query(2, "alias.test", 1),
        query(3, "nx.test", 1),
        query(4, "up.test", 1),
        query(5, "up.test", 28),
        query(6, "Text.Test", 16),
        query(7, "mx.test", 15),
        query(8, "svc.test", 65),
        query(9, "hosts.test", 28),
        query(10, "drop.test", 1),
    ]
}

struct Run {
    answers: Vec<Option<Vec<u8>>>,
    access: String,
}

async fn run_dns(binary: &str, dir: &Path, name: &str, fake: u16, echo: u16) -> Result<Run> {
    let node = free_port();
    let access = dir.join(format!("{name}-access.log"));
    let _child = start(dir, name, binary, &dns_config(node, fake, &access), node).await?;
    let answers = ask(node, &queries()).await?;
    // sockopt/freedom domainStrategy resolves through the DNS module's hosts.
    echo_through(node, "echo.test", echo)
        .await
        .context("UseIPv4 freedom through DNS hosts")?;
    // IPIfNonMatch resolves through the DNS module before matching the IP rule.
    let mut blocked = vless(node, "hosts.test", 80, false).await?;
    blocked.write_all(b"x").await?;
    let mut buf = [0u8; 8];
    let _ = tokio::time::timeout(Duration::from_secs(2), blocked.read(&mut buf)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(Run {
        answers,
        access: std::fs::read_to_string(&access).unwrap_or_default(),
    })
}

fn rcode(m: &[u8]) -> u16 {
    u16::from_be_bytes([m[2], m[3]]) & 0xf
}

fn answer_ips(m: &[u8]) -> Vec<(Vec<u8>, u32)> {
    let mut off = question_end(m);
    let mut out = Vec::new();
    for _ in 0..u16::from_be_bytes([m[6], m[7]]) {
        let ttl = u32::from_be_bytes(m[off + 6..off + 10].try_into().unwrap());
        let len = u16::from_be_bytes([m[off + 10], m[off + 11]]) as usize;
        out.push((m[off + 12..off + 12 + len].to_vec(), ttl));
        off += 12 + len;
    }
    out
}

#[tokio::test]
async fn dns_module_and_outbound_answer_like_go() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir()?;
        let (fake, seen) = upstream().await?;
        let echo = tcp_echo().await?;
        let rust = run_dns(env!("CARGO_BIN_EXE_rcore"), dir.path(), "rcore", fake, echo).await?;
        let a = &rust.answers;
        let hosts = a[0].as_ref().context("hosts answer")?;
        ensure!(
            rcode(hosts) == 0 && answer_ips(hosts) == [(vec![10, 1, 2, 3], 10)],
            "hosts {hosts:?}"
        );
        ensure!(
            a[1] == Some([&[0, 2][..], &hosts[2..]].concat())
                .map(|m| {
                    // alias.test keeps its own question name.
                    let mut m = m;
                    m.splice(
                        12..question_end(&m),
                        query(2, "alias.test", 1)[12..].iter().copied(),
                    );
                    m
                })
                .or(a[1].clone()),
            "alias"
        );
        ensure!(answer_ips(a[1].as_ref().context("alias")?) == [(vec![10, 1, 2, 3], 10)]);
        ensure!(rcode(a[2].as_ref().context("nx")?) == 3, "hosts #3");
        let up = a[3].as_ref().context("upstream A")?;
        ensure!(
            answer_ips(up) == [(vec![192, 0, 2, 7], 120)],
            "upstream A {up:?}"
        );
        let up6 = answer_ips(a[4].as_ref().context("upstream AAAA")?);
        ensure!(
            up6.len() == 1 && up6[0].0[..4] == [0x20, 0x01, 0x0d, 0xb8],
            "AAAA {up6:?}"
        );
        ensure!(
            rcode(a[5].as_ref().context("TXT return")?) == 3,
            "TXT rCode"
        );
        ensure!(
            answer_ips(a[6].as_ref().context("MX direct")?).is_empty(),
            "MX passthrough"
        );
        let svc = a[7].as_ref().context("HTTPS default return")?;
        ensure!(
            rcode(svc) == 0 && answer_ips(svc).is_empty(),
            "type 65 returns NOERROR"
        );
        ensure!(
            rcode(a[8].as_ref().context("hosts AAAA")?) == 0,
            "hosts AAAA empty"
        );
        ensure!(a[9].is_none(), "drop.test must get no answer");
        // The module's queries carry EDNS client subnet 203.0.113.0/24.
        let ecs = [0, 8, 0, 7, 0, 1, 24, 0, 203, 0, 113];
        ensure!(
            seen.lock()
                .unwrap()
                .iter()
                .any(|q| q.windows(ecs.len()).any(|w| w == ecs)),
            "no ECS in upstream queries"
        );
        ensure!(
            rust.access
                .contains("accepted tcp:hosts.test:80 [in -> blocked]"),
            "{}",
            rust.access
        );
        ensure!(
            rust.access.contains("from DNS accepted udp:127.0.0.1:"),
            "{}",
            rust.access
        );
        if let Ok(xray) = std::env::var("XRAY_BINARY") {
            let go = run_dns(&xray, dir.path(), "go", fake, echo).await?;
            for (i, (r, g)) in rust.answers.iter().zip(&go.answers).enumerate() {
                ensure!(r == g, "answer {i} differs:\n rcore {r:?}\n go    {g:?}");
            }
            ensure!(
                go.access
                    .contains("accepted tcp:hosts.test:80 [in -> blocked]"),
                "{}",
                go.access
            );
        }
        if std::env::var_os("RCORE_KEEP_LOGS").is_some() {
            eprintln!("logs kept in {}", dir.keep().display());
        }
        Result::<()>::Ok(())
    })
    .await
    .context("DNS deadline")?
}

/// A probe target that answers 204 and counts requests.
async fn probe_target() -> Result<(u16, Arc<Mutex<usize>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let hits = Arc::new(Mutex::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                }
                *counter.lock().unwrap() += 1;
                let _ = s
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    Ok((port, hits))
}

fn balancer_config(node: u16, probe: u16, ping: u16, access: &Path) -> Value {
    json!({
        "log": {"loglevel": "debug", "access": access.to_str().unwrap()},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": node, "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": "none"}}],
        "outbounds": [
            {"tag": "bal-dead", "protocol": "blackhole"},
            {"tag": "bal-live", "protocol": "freedom",
             "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}},
            {"tag": "other", "protocol": "blackhole"}
        ],
        "observatory": {"subjectSelector": ["bal-"], "probeURL": format!("http://127.0.0.1:{probe}/generate_204"),
                        "probeInterval": "100ms"},
        "routing": {
            "balancers": [
                {"tag": "least", "selector": ["bal-"], "strategy": {"type": "leastPing"}},
                {"tag": "rr", "selector": ["bal-"], "strategy": {"type": "roundRobin"},
                 "fallbackTag": "bal-live"}
            ],
            "rules": [
                {"port": ping, "balancerTag": "least"},
                {"inboundTag": ["in"], "balancerTag": "rr"}
            ]
        }
    })
}

async fn run_balancer(binary: &str, dir: &Path, name: &str) -> Result<String> {
    let (probe, hits) = probe_target().await?;
    let (a, b) = (tcp_echo().await?, tcp_echo().await?);
    let node = free_port();
    let access = dir.join(format!("{name}-access.log"));
    let _child = start(
        dir,
        name,
        binary,
        &balancer_config(node, probe, a, &access),
        node,
    )
    .await?;
    // Two sequential probes 100 ms apart; give both outbounds time to be observed.
    for _ in 0..50 {
        if *hits.lock().unwrap() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    for _ in 0..3 {
        echo_through(node, "127.0.0.1", a)
            .await
            .context("leastPing")?;
        echo_through(node, "127.0.0.1", b)
            .await
            .context("roundRobin skips the dead one")?;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(std::fs::read_to_string(&access).unwrap_or_default())
}

#[tokio::test]
async fn balancers_follow_the_observatory_like_go() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir()?;
        let mut runs = vec![(
            "rcore",
            run_balancer(env!("CARGO_BIN_EXE_rcore"), dir.path(), "rcore").await?,
        )];
        if let Ok(xray) = std::env::var("XRAY_BINARY") {
            runs.push(("go", run_balancer(&xray, dir.path(), "go").await?));
        }
        for (name, access) in runs {
            ensure!(
                access.matches("[in -> bal-live]").count() == 6,
                "{name}: {access}"
            );
            ensure!(!access.contains("bal-dead"), "{name}: {access}");
        }
        if std::env::var_os("RCORE_KEEP_LOGS").is_some() {
            eprintln!("logs kept in {}", dir.keep().display());
        }
        Result::<()>::Ok(())
    })
    .await
    .context("balancer deadline")?
}

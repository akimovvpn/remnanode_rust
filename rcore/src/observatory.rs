//! Port of xray-core app/observatory (periodic GET probes through each outbound) and
//! app/observatory/burst (sampled health pings), which the balancers read.
use crate::app::{Instance, Internal};
use crate::config::{go_duration_ns, keys, string_list};
use crate::router::select;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// observatory.HealthPingMeasurementResult (durations in nanoseconds).
#[derive(Clone, Debug)]
pub struct Health {
    pub all: i64,
    pub fail: i64,
    pub deviation: i64,
    pub average: i64,
}

/// observatory.OutboundStatus (delay in milliseconds).
#[derive(Clone, Debug)]
pub struct OutboundStatus {
    pub tag: String,
    pub alive: bool,
    pub delay: i64,
    pub health: Option<Health>,
}

/// The extension.Observatory feature, if configured.
#[derive(Default)]
pub enum Observatory {
    #[default]
    None,
    Probe(Arc<Observer>),
    Burst(Arc<Burst>),
}

pub struct Observer {
    selectors: Vec<String>,
    probe_url: String,
    interval: Duration,
    concurrency: bool,
    status: Mutex<Vec<OutboundStatus>>,
}

#[derive(Clone, Copy, PartialEq)]
enum Rtt {
    Untested,
    Failed,
    Value(Duration),
}

/// HealthPingRTTS: a ring of the last `cap` samples, each valid for `validity`.
struct Rtts {
    idx: usize,
    validity: Duration,
    rtts: Vec<(Instant, Rtt)>,
}

impl Rtts {
    fn put(&mut self, rtt: Rtt) {
        self.idx = (self.idx + 1) % self.rtts.len();
        self.rtts[self.idx] = (Instant::now(), rtt);
    }

    /// getStatistics.
    fn stats(&self) -> Health {
        let (mut fail, mut sum) = (0i64, 0i64);
        let mut valid = Vec::new();
        for (at, rtt) in &self.rtts {
            match rtt {
                Rtt::Untested => continue,
                _ if at.elapsed() > self.validity => continue,
                Rtt::Failed => fail += 1,
                Rtt::Value(d) => {
                    let ns = d.as_nanos() as i64;
                    sum += ns;
                    valid.push(ns);
                }
            }
        }
        let cnt = valid.len() as i64;
        if cnt == 0 {
            return Health {
                all: fail,
                fail,
                deviation: 0,
                average: 0,
            };
        }
        let average = sum / cnt;
        let deviation = if cnt < 2 {
            average / 2
        } else {
            let variance: f64 = valid.iter().map(|v| ((v - average) as f64).powi(2)).sum();
            (variance / cnt as f64).sqrt() as i64
        };
        Health {
            all: cnt + fail,
            fail,
            deviation,
            average,
        }
    }
}

pub struct Burst {
    selectors: Vec<String>,
    destination: String,
    connectivity: String,
    interval: Duration,
    sampling: usize,
    timeout: Duration,
    method: String,
    results: Mutex<HashMap<String, Rtts>>,
    /// The scheduled round still allowed to record results (cancelPending).
    round: AtomicU64,
}

fn duration(v: &Value, path: &str) -> Result<Duration> {
    if v.is_null() {
        return Ok(Duration::ZERO);
    }
    let ns = go_duration_ns(v, path)?;
    Ok(Duration::from_nanos(ns.max(0) as u64))
}

impl Observatory {
    /// infra/conf ObservatoryConfig / BurstObservatoryConfig.
    pub fn parse(observatory: &Value, burst: &Value) -> Result<Self> {
        if !observatory.is_null() {
            keys(
                observatory,
                &[
                    "subjectSelector",
                    "probeURL",
                    "probeInterval",
                    "enableConcurrency",
                ],
                "observatory",
            )?;
            let interval = duration(&observatory["probeInterval"], "observatory.probeInterval")?;
            return Ok(Self::Probe(Arc::new(Observer {
                selectors: string_list(
                    &observatory["subjectSelector"],
                    "observatory.subjectSelector",
                )?,
                probe_url: observatory["probeURL"]
                    .as_str()
                    .filter(|u| !u.is_empty())
                    .unwrap_or("https://www.google.com/generate_204")
                    .to_owned(),
                interval: if interval.is_zero() {
                    Duration::from_secs(10)
                } else {
                    interval
                },
                concurrency: observatory["enableConcurrency"].as_bool().unwrap_or(false),
                status: Mutex::default(),
            })));
        }
        if burst.is_null() {
            return Ok(Self::None);
        }
        keys(
            burst,
            &["subjectSelector", "pingConfig"],
            "burstObservatory",
        )?;
        let ping = &burst["pingConfig"];
        if !ping.is_object() {
            bail!("BurstObservatory requires a valid pingConfig");
        }
        let p = "burstObservatory.pingConfig";
        keys(
            ping,
            &[
                "destination",
                "connectivity",
                "interval",
                "sampling",
                "timeout",
                "httpMethod",
            ],
            p,
        )?;
        let text = |k: &str| ping[k].as_str().unwrap_or_default().trim().to_owned();
        let mut interval = duration(&ping["interval"], &format!("{p}.interval"))?;
        if interval.is_zero() {
            interval = Duration::from_secs(60);
        } else if interval < Duration::from_secs(10) {
            tracing::warn!(
                "app/observatory/burst: health check interval is too small, 10s is applied"
            );
            interval = Duration::from_secs(10);
        }
        let timeout = duration(&ping["timeout"], &format!("{p}.timeout"))?;
        let method = text("httpMethod");
        Ok(Self::Burst(Arc::new(Burst {
            selectors: string_list(
                &burst["subjectSelector"],
                "burstObservatory.subjectSelector",
            )?,
            destination: Some(text("destination"))
                .filter(|d| !d.is_empty())
                .unwrap_or("https://connectivitycheck.gstatic.com/generate_204".into()),
            connectivity: text("connectivity"),
            interval,
            sampling: match ping["sampling"].as_i64() {
                Some(n) if n > 0 => n as usize,
                _ => 10,
            },
            timeout: if timeout.is_zero() {
                Duration::from_secs(5)
            } else {
                timeout
            },
            method: if method.is_empty() {
                "HEAD".into()
            } else {
                method
            },
            results: Mutex::default(),
            round: AtomicU64::new(0),
        })))
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// GetObservation.
    pub fn observation(&self) -> Option<Vec<OutboundStatus>> {
        match self {
            Self::None => None,
            Self::Probe(o) => Some(o.status.lock().unwrap().clone()),
            Self::Burst(b) => Some(b.result()),
        }
    }

    /// Start: probing runs only with a subjectSelector.
    pub fn start(&self, inst: &Arc<Instance>) {
        match self {
            Self::None => {}
            Self::Probe(o) if !o.selectors.is_empty() => {
                tokio::spawn(o.clone().background(inst.clone()));
            }
            Self::Burst(b) if !b.selectors.is_empty() => b.clone().start(inst.clone()),
            _ => {}
        }
    }
}

/// An HTTP/1.1 request through the outbound `tag` (tagged.Dialer), or directly without a tag,
/// returning the time until the response (and, for GET, its body) arrived.
async fn http_ping(
    inst: &Arc<Instance>,
    tag: Option<&str>,
    url: &str,
    method: &str,
    report: Option<Arc<Mutex<Option<String>>>>,
) -> Result<Duration> {
    let uri: http::Uri = url.parse().with_context(|| format!("parse \"{url}\""))?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        other => bail!(
            "unsupported protocol scheme \"{}\"",
            other.unwrap_or_default()
        ),
    };
    let host = uri.host().context("no Host in request URL")?.to_owned();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host)
        .to_owned();
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let start = Instant::now();
    let dest = crate::dns::parse_address(&host);
    let io: crate::transport::BoxIo = match tag {
        Some(tag) => inst.dial_internal(
            Internal {
                tag: String::new(),
                protocol: "",
                skip_dns: true,
                forced: Some(tag.to_owned()),
                access: None,
                report,
            },
            dest,
            port,
        ),
        None => Box::new(crate::app::dial_system(&dest, port).await?),
    };
    let io = if https {
        let client = crate::tls_client::Client {
            server_name: host.clone(),
            fingerprint: crate::tls_client::Fingerprint::Chrome,
            alpn: Vec::new(),
            reality: None,
        };
        crate::tls_client::connect(io, &client).await?.0
    } else {
        io
    };
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io)).await?;
    tokio::spawn(conn);
    let authority = uri
        .authority()
        .map(|a| a.as_str().to_owned())
        .unwrap_or(host);
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri.path_and_query().map_or("/", |p| p.as_str()))
        .header("Host", authority);
    for (k, v) in crate::browser::chrome_headers("nav", |_| false) {
        request = request.header(k, v);
    }
    if method != "HEAD" {
        request = request.header("Accept-Encoding", "gzip");
    }
    let request = request.body(http_body_util::Empty::<bytes::Bytes>::new())?;
    let response = sender.send_request(request).await?;
    if method == "GET" {
        http_body_util::BodyExt::collect(response.into_body()).await?;
    }
    Ok(start.elapsed())
}

impl Observer {
    async fn background(self: Arc<Self>, inst: Arc<Instance>) {
        loop {
            let mut outbounds = select(&inst, &self.selectors);
            self.status
                .lock()
                .unwrap()
                .retain(|s| outbounds.contains(&s.tag));
            if outbounds.is_empty() {
                tracing::warn!(
                    "app/observatory: no outbound matches subjectSelector [{}]",
                    self.selectors.join(" ")
                );
                tokio::time::sleep(self.interval).await;
                continue;
            }
            if !self.concurrency {
                outbounds.sort();
                for tag in outbounds {
                    let result = self.probe(&inst, &tag).await;
                    self.update(&tag, result);
                    tokio::time::sleep(self.interval).await;
                }
                continue;
            }
            let mut tasks = Vec::new();
            for tag in outbounds {
                let (me, inst) = (self.clone(), inst.clone());
                tasks.push(tokio::spawn(async move {
                    let result = me.probe(&inst, &tag).await;
                    me.update(&tag, result);
                }));
            }
            for task in tasks {
                let _ = task.await;
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    /// probe: a GET of the probe URL through the outbound, 5 s in all.
    async fn probe(&self, inst: &Arc<Instance>, tag: &str) -> Option<i64> {
        let report = Arc::new(Mutex::new(None));
        let ping = http_ping(
            inst,
            Some(tag),
            &self.probe_url,
            "GET",
            Some(report.clone()),
        );
        match tokio::time::timeout(Duration::from_secs(5), ping).await {
            Ok(Ok(elapsed)) => {
                tracing::info!(
                    "app/observatory: the outbound {tag} is alive:{}",
                    elapsed.as_secs_f64()
                );
                Some(elapsed.as_millis() as i64)
            }
            result => {
                let error = match result {
                    Ok(Err(e)) => format!("{e:#}"),
                    _ => {
                        "context deadline exceeded (Client.Timeout exceeded while awaiting headers)"
                            .into()
                    }
                };
                // errorCollector.UnderlyingError: what the outbound reported, if anything.
                let underlying = match report.lock().unwrap().take() {
                    Some(e) => format!("app/observatory: underlying connection error > {e}"),
                    None => "app/observatory: failed to produce report".into(),
                };
                tracing::info!(
                    "app/observatory: the outbound {tag} is dead: GET request failed:app/observatory: outbound failed to relay connection > Get \"{}\": {error}with outbound handler report underlying connection failed > {underlying}",
                    self.probe_url
                );
                None
            }
        }
    }

    /// updateStatusForResult.
    fn update(&self, tag: &str, delay: Option<i64>) {
        let mut status = self.status.lock().unwrap();
        let entry = match status.iter().position(|s| s.tag == tag) {
            Some(i) => &mut status[i],
            None => {
                status.push(OutboundStatus {
                    tag: tag.to_owned(),
                    alive: false,
                    delay: 0,
                    health: None,
                });
                status.last_mut().unwrap()
            }
        };
        entry.alive = delay.is_some();
        entry.delay = delay.unwrap_or(99_999_999);
    }
}

impl Burst {
    /// createResult.
    fn result(&self) -> Vec<OutboundStatus> {
        self.results
            .lock()
            .unwrap()
            .iter()
            .map(|(tag, rtts)| {
                let s = rtts.stats();
                OutboundStatus {
                    tag: tag.clone(),
                    alive: s.all != s.fail,
                    delay: s.average / 1_000_000,
                    health: Some(s),
                }
            })
            .collect()
    }

    /// StartScheduler: one immediate check, then rounds of `sampling` pings per outbound spread
    /// over each interval×sampling period.
    fn start(self: Arc<Self>, inst: Arc<Instance>) {
        let period = self.interval * self.sampling as u32;
        let (me, first) = (self.clone(), inst.clone());
        tokio::spawn(async move {
            let tags = select(&first, &me.selectors);
            if !tags.is_empty() {
                tracing::info!(
                    "app/observatory/burst: perform one-time health check for tags [{}]",
                    tags.join(" ")
                );
                me.check(&first, &tags, Duration::ZERO, 1, None);
            }
        });
        tokio::spawn(async move {
            loop {
                let tags = select(&inst, &self.selectors);
                let round = self.round.fetch_add(1, Ordering::AcqRel) + 1;
                self.check(&inst, &tags, period, self.sampling, Some(round));
                let (me, kept) = (self.clone(), tags.clone());
                tokio::spawn(async move {
                    tokio::time::sleep(period).await;
                    if me.round.load(Ordering::Acquire) == round {
                        me.cleanup(&kept);
                    }
                });
                tokio::time::sleep(period).await;
            }
        });
    }

    /// doCheck: `rounds` pings per tag, each after a random delay within `spread`.
    fn check(
        self: &Arc<Self>,
        inst: &Arc<Instance>,
        tags: &[String],
        spread: Duration,
        rounds: usize,
        round: Option<u64>,
    ) {
        for tag in tags {
            for _ in 0..rounds {
                let delay = if spread.is_zero() {
                    Duration::ZERO
                } else {
                    Duration::from_nanos(crate::dns::roll(spread.as_nanos() as usize) as u64)
                };
                let (me, inst, tag) = (self.clone(), inst.clone(), tag.clone());
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let current = || round.is_none_or(|r| me.round.load(Ordering::Acquire) == r);
                    if !current() {
                        return;
                    }
                    tracing::debug!("app/observatory/burst: checking {tag}");
                    let ping = http_ping(&inst, Some(&tag), &me.destination, &me.method, None);
                    let rtt = match tokio::time::timeout(me.timeout, ping).await {
                        Ok(Ok(d)) => Some(Rtt::Value(d)),
                        result => {
                            let error = match result {
                                Ok(Err(e)) => format!("{e:#}"),
                                _ => "context deadline exceeded (Client.Timeout exceeded while awaiting headers)".into(),
                            };
                            if !me.connectivity_ok(&inst).await {
                                tracing::warn!("app/observatory/burst: network is down");
                                None
                            } else {
                                tracing::warn!(
                                    "app/observatory/burst: error ping {} with {tag}: {} \"{}\": {error}",
                                    me.destination,
                                    capitalized(&me.method),
                                    me.destination
                                );
                                Some(Rtt::Failed)
                            }
                        }
                    };
                    if let Some(rtt) = rtt
                        && current()
                    {
                        me.put(&tag, rtt);
                    }
                });
            }
        }
    }

    /// checkConnectivity: a direct request to the connectivity URL, when one is set.
    async fn connectivity_ok(&self, inst: &Arc<Instance>) -> bool {
        if self.connectivity.is_empty() {
            return true;
        }
        let ping = http_ping(inst, None, &self.connectivity, &self.method, None);
        matches!(tokio::time::timeout(self.timeout, ping).await, Ok(Ok(_)))
    }

    /// PutResult.
    fn put(&self, tag: &str, rtt: Rtt) {
        let mut results = self.results.lock().unwrap();
        let validity = self.interval * self.sampling as u32 * 2;
        let entry = results.entry(tag.to_owned()).or_insert_with(|| Rtts {
            idx: self.sampling - 1,
            validity,
            rtts: vec![(Instant::now(), Rtt::Untested); self.sampling],
        });
        entry.put(rtt);
    }

    /// Cleanup: forgets outbounds the selector no longer picks.
    fn cleanup(&self, tags: &[String]) {
        self.results
            .lock()
            .unwrap()
            .retain(|tag, _| tags.contains(tag));
    }
}

/// net/http's method spelling in client errors ("Head", "Get").
fn capitalized(method: &str) -> String {
    let lower = method.to_lowercase();
    let mut chars = lower.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_stats_match_go() {
        let mut rtts = Rtts {
            idx: 2,
            validity: Duration::from_secs(60),
            rtts: vec![(Instant::now(), Rtt::Untested); 3],
        };
        rtts.put(Rtt::Value(Duration::from_millis(100)));
        let one = rtts.stats();
        assert_eq!(
            (one.all, one.fail, one.average, one.deviation),
            (1, 0, 100_000_000, 50_000_000)
        );
        rtts.put(Rtt::Value(Duration::from_millis(300)));
        rtts.put(Rtt::Failed);
        let s = rtts.stats();
        assert_eq!(
            (s.all, s.fail, s.average, s.deviation),
            (3, 1, 200_000_000, 100_000_000)
        );
        // The ring overwrites the oldest sample.
        rtts.put(Rtt::Failed);
        assert_eq!(rtts.stats().all, 3);
        assert_eq!(rtts.stats().fail, 2);
    }

    #[test]
    fn burst_defaults_and_limits() {
        let Observatory::Burst(b) = Observatory::parse(
            &Value::Null,
            &serde_json::json!({"subjectSelector": ["px"], "pingConfig": {"interval": "1s"}}),
        )
        .unwrap() else {
            panic!("expected burst");
        };
        assert_eq!(b.interval, Duration::from_secs(10));
        assert_eq!((b.sampling, b.timeout), (10, Duration::from_secs(5)));
        assert_eq!(b.method, "HEAD");
        assert!(
            Observatory::parse(&Value::Null, &serde_json::json!({"subjectSelector": ["x"]}))
                .is_err()
        );
    }
}

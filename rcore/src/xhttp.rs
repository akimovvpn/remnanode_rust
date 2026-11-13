//! Port of xray-core transport/internet/splithttp server side (XHTTP, Xray 26.11.9): plain
//! HTTP/1.1 and h2c on TCP (optionally under REALITY) in the packet-up, stream-up and
//! stream-one modes, with the obfuscation options (padding placements, uplink data in
//! headers or cookies, session/seq placements).
use crate::{app::Instance, transport::BoxIo};
use anyhow::{Result, bail, ensure};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWriteExt, DuplexStream, ReadBuf},
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
};

/// splithttp.Config after infra/conf's Build defaults.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub host: String,
    pub path: String,
    pub mode: String,
    pub padding: (i64, i64),
    pub obfs: bool,
    pub padding_key: String,
    pub padding_header: String,
    pub padding_placement: String,
    pub padding_method: String,
    pub session_placement: String,
    pub session_key: String,
    pub seq_placement: String,
    pub seq_key: String,
    pub data_placement: String,
    pub data_key: String,
    pub no_sse_header: bool,
    pub max_each_post: usize,
    pub max_buffered_posts: usize,
    pub stream_up_server_secs: (i64, i64),
    pub max_header_bytes: usize,
}

const KEYS: &[&str] = &[
    "host",
    "path",
    "mode",
    "headers",
    "xPaddingBytes",
    "xPaddingObfsMode",
    "xPaddingKey",
    "xPaddingHeader",
    "xPaddingPlacement",
    "xPaddingMethod",
    "uplinkHTTPMethod",
    "sessionIDPlacement",
    "sessionIDKey",
    "sessionIDTable",
    "sessionIDLength",
    "seqPlacement",
    "seqKey",
    "uplinkDataPlacement",
    "uplinkDataKey",
    "uplinkChunkSize",
    "noGRPCHeader",
    "noSSEHeader",
    "scMaxEachPostBytes",
    "scMinPostsIntervalMs",
    "scMaxBufferedPosts",
    "scStreamUpServerSecs",
    "serverMaxHeaderBytes",
    "xmux",
    "downloadSettings",
    "h2Params",
    "extra",
];

/// encoding/json into SplitHTTPConfig: keys match the fields case-insensitively and names that
/// are not fields are dropped, as Go ignores them.
fn go_fields(v: &Value) -> Value {
    let Some(object) = v.as_object() else {
        return v.clone();
    };
    let mut out = serde_json::Map::new();
    for (key, value) in object {
        let Some(field) = KEYS.iter().find(|f| f.eq_ignore_ascii_case(key)) else {
            continue;
        };
        // shortcut: Go keeps the last of two case variants in document order; serde_json
        // does not keep that order, so the exact spelling wins here.
        if key == field || !out.contains_key(*field) {
            out.insert((*field).to_owned(), value.clone());
        }
    }
    Value::Object(out)
}

/// conf.Int32Range: an integer or "from-to" string (also "-1--5"), ordered.
fn range(v: &Value, path: &str) -> Result<(i64, i64)> {
    let (a, b) = match v {
        Value::Null => (0, 0),
        Value::Number(n) => {
            let n = n
                .as_i64()
                .filter(|n| i32::try_from(*n).is_ok())
                .ok_or_else(|| anyhow::anyhow!("{path}: invalid integer range"))?;
            (n, n)
        }
        Value::String(s) if s.is_empty() => (0, 0),
        Value::String(s) => {
            if let Ok(n) = s.parse::<i32>() {
                (n as i64, n as i64)
            } else {
                let (l, r) = match s.strip_prefix('-') {
                    Some(rest) => rest
                        .split_once('-')
                        .map(|(l, r)| (format!("-{l}"), r.to_owned())),
                    None => s.split_once('-').map(|(l, r)| (l.to_owned(), r.to_owned())),
                }
                .ok_or_else(|| anyhow::anyhow!("{path}: invalid range string: {s}"))?;
                match (l.parse::<i32>(), r.parse::<i32>()) {
                    (Ok(l), Ok(r)) => (l as i64, r as i64),
                    _ => bail!("{path}: invalid range string: {s}"),
                }
            }
        }
        _ => bail!(
            "{path}: Invalid integer range, expected either string of form \"1-2\" or plain integer."
        ),
    };
    Ok((a.min(b), a.max(b)))
}

impl Config {
    /// SplitHTTPConfig.Build plus the server-side Get* normalizations.
    pub fn parse(settings: &Value, path: &str) -> Result<Self> {
        let settings = &go_fields(settings);
        for key in ["host", "path", "mode"] {
            ensure!(
                settings[key].is_null() || settings[key].is_string(),
                "{path}.{key} must be a string"
            );
        }
        let extra = &go_fields(&settings["extra"]);
        let c = if extra.is_null() { settings } else { extra };
        let s = |key: &str| -> Result<String> {
            match &c[key] {
                Value::Null => Ok(String::new()),
                Value::String(s) => Ok(s.clone()),
                _ => bail!("{path}.{key} must be a string"),
            }
        };
        // host, path and mode always come from the outer object.
        let outer = |key: &str| settings[key].as_str().unwrap_or_default().to_owned();
        let mode = match outer("mode").as_str() {
            "" => "auto".to_owned(),
            m @ ("auto" | "packet-up" | "stream-up" | "stream-one") => m.to_owned(),
            m => bail!("{path}: unsupported mode: {m}"),
        };
        for key in ["xPaddingObfsMode", "noSSEHeader", "noGRPCHeader"] {
            ensure!(
                c[key].is_null() || c[key].is_boolean(),
                "{path}.{key} must be a boolean"
            );
        }
        ensure!(
            c["headers"].is_null() || c["headers"].is_object(),
            "{path}.headers must be an object"
        );
        for (k, value) in c["headers"].as_object().into_iter().flatten() {
            ensure!(value.is_string(), "{path}.headers.{k} must be a string");
            http::HeaderName::from_bytes(k.as_bytes())?;
            HeaderValue::from_str(value.as_str().unwrap())?;
            ensure!(
                !k.eq_ignore_ascii_case("host"),
                "{path}: \"headers\" can't contain \"host\""
            );
        }
        let padding = range(&c["xPaddingBytes"], &format!("{path}.xPaddingBytes"))?;
        ensure!(
            padding == (0, 0) || (padding.0 > 0 && padding.1 > 0),
            "{path}: xPaddingBytes cannot be disabled"
        );
        let or = |v: String, default: &str| if v.is_empty() { default.to_owned() } else { v };
        let padding_placement = or(s("xPaddingPlacement")?, "queryInHeader");
        ensure!(
            matches!(
                padding_placement.as_str(),
                "cookie" | "header" | "query" | "queryInHeader"
            ),
            "{path}: unsupported padding placement: {padding_placement}"
        );
        let padding_method = or(s("xPaddingMethod")?, "repeat-x");
        ensure!(
            matches!(padding_method.as_str(), "repeat-x" | "tokenish"),
            "{path}: unsupported padding method: {padding_method}"
        );
        let data_placement = or(s("uplinkDataPlacement")?, "auto");
        match data_placement.as_str() {
            "auto" | "body" => {}
            "cookie" | "header" => ensure!(
                mode == "packet-up",
                "{path}: UplinkDataPlacement can be {data_placement} only in packet-up mode"
            ),
            other => bail!("{path}: unsupported uplink data placement: {other}"),
        }
        let method = or(s("uplinkHTTPMethod")?, "POST").to_uppercase();
        ensure!(
            method != "GET" || mode == "packet-up",
            "{path}: uplinkHTTPMethod can be GET only in packet-up mode"
        );
        let placement = |key: &str| -> Result<String> {
            let p = or(s(key)?, "path");
            ensure!(
                matches!(p.as_str(), "path" | "cookie" | "header" | "query"),
                "{path}: unsupported {} placement: {p}",
                if key == "seqPlacement" {
                    "seq"
                } else {
                    "session"
                }
            );
            Ok(p)
        };
        let session_placement = placement("sessionIDPlacement")?;
        let seq_placement = placement("seqPlacement")?;
        let key_for = |placement: &str, key: String, cookie: &str, header: &str| {
            if !key.is_empty() {
                key
            } else {
                match placement {
                    "cookie" | "query" => cookie.to_owned(),
                    "header" => header.to_owned(),
                    _ => String::new(),
                }
            }
        };
        let session_key = key_for(
            &session_placement,
            s("sessionIDKey")?,
            "x_session",
            "X-Session",
        );
        let seq_key = key_for(&seq_placement, s("seqKey")?, "x_seq", "X-Seq");
        // sessionIDTable/sessionIDLength only shape client IDs, but Go validates them on load.
        let table = s("sessionIDTable")?;
        if !table.is_empty() {
            let size = match table.as_str() {
                "ALPHABET" | "alphabet" => 26,
                "Alphabet" => 52,
                "BASE36" | "base36" => 36,
                "Base62" => 62,
                "HEX" | "hex" => 16,
                "number" => 10,
                custom => {
                    ensure!(
                        custom.is_ascii(),
                        "{path}: sessionIDTable must contain only ASCII characters"
                    );
                    custom.len() as u128
                }
            };
            let (from, to) = range(&c["sessionIDLength"], &format!("{path}.sessionIDLength"))?;
            // roomSize: the number of possible IDs must reach 2^31.
            let mut room = 0u128;
            for k in from..=to {
                let term = if k <= 0 { 1 } else { size.checked_pow(k as u32).unwrap_or(u128::MAX) };
                room = room.saturating_add(term);
                if room >= 2 << 30 {
                    break;
                }
            }
            ensure!(
                room >= 2 << 30,
                "{path}: sessionIDTable or sessionIDLength is too small"
            );
            ensure!(from > 0, "{path}: sessionIDLength.from must be greater than 0");
        }
        let data_key = match (data_placement.as_str(), s("uplinkDataKey")?) {
            ("body", _) => String::new(),
            (_, k) if !k.is_empty() => k,
            ("cookie", _) => "x_data".to_owned(),
            _ => "X-Data".to_owned(),
        };
        let integer = |key: &str| -> Result<i64> {
            if c[key].is_null() {
                return Ok(0);
            }
            c[key]
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("{path}.{key} must be an integer"))
        };
        let max_header = integer("serverMaxHeaderBytes")?;
        ensure!(
            (0..=i32::MAX as i64).contains(&max_header),
            "{path}: invalid maxHeaderBytes"
        );
        let xmux = &c["xmux"];
        ensure!(
            !(range(&xmux["maxConnections"], path)?.1 > 0
                && range(&xmux["maxConcurrency"], path)?.1 > 0),
            "{path}: maxConnections cannot be specified together with maxConcurrency"
        );
        ensure!(
            c["h2Params"].is_null(),
            "{}",
            crate::config::unsupported(&format!("{path}.h2Params"))
        );
        let max_each = range(&c["scMaxEachPostBytes"], path)?;
        ensure!(
            max_each.0 >= 0 && max_each.1 <= MAX_QUEUED_PAYLOAD as i64,
            "{path}: scMaxEachPostBytes must be between 0 and {MAX_QUEUED_PAYLOAD}"
        );
        let max_buffered = integer("scMaxBufferedPosts")?;
        ensure!(
            max_buffered <= Semaphore::MAX_PERMITS as i64,
            "{path}: scMaxBufferedPosts is too large"
        );
        let stream_up = range(&c["scStreamUpServerSecs"], path)?;
        let mut route = outer("path");
        route = route.split('?').next().unwrap_or_default().to_owned();
        if !route.starts_with('/') {
            route.insert(0, '/');
        }
        if (session_placement == "path" || seq_placement == "path") && !route.ends_with('/') {
            route.push('/');
        }
        Ok(Self {
            host: outer("host"),
            path: route,
            mode,
            padding: if padding.1 == 0 { (100, 1000) } else { padding },
            obfs: c["xPaddingObfsMode"] == true,
            padding_key: or(s("xPaddingKey")?, "x_padding"),
            padding_header: or(s("xPaddingHeader")?, "X-Padding"),
            padding_placement,
            padding_method,
            session_placement,
            session_key,
            seq_placement,
            seq_key,
            data_placement,
            data_key,
            no_sse_header: c["noSSEHeader"] == true,
            max_each_post: if max_each.1 == 0 {
                1_000_000
            } else {
                max_each.1 as usize
            },
            max_buffered_posts: match max_buffered {
                n if n <= 0 => 30,
                n => n as usize,
            },
            stream_up_server_secs: if stream_up.1 == 0 {
                (20, 80)
            } else {
                stream_up
            },
            max_header_bytes: if max_header <= 0 {
                8192
            } else {
                max_header as usize
            },
        })
    }
}

fn rand_between((from, to): (i64, i64)) -> i64 {
    if to <= from {
        return from;
    }
    let mut b = [0u8; 8];
    let _ = SystemRandom::new().fill(&mut b);
    from + (u64::from_le_bytes(b) % ((to - from) as u64)) as i64
}

/// RFC 7541 Appendix B code lengths (hpack.HuffmanEncodeLength).
const HUFFMAN_BITS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

fn huffman_len(s: &str) -> i64 {
    let bits: u64 = s.bytes().map(|b| HUFFMAN_BITS[b as usize] as u64).sum();
    bits.div_ceil(8) as i64
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// GeneratePadding: X/Z have 8-bit Huffman codes, so HPACK/QPACK keep the padding length.
fn generate_padding(method: &str, length: i64) -> String {
    if length <= 0 {
        return String::new();
    }
    if method != "tokenish" {
        return "X".repeat(length as usize);
    }
    // GenerateTokenishPaddingBase62: random base62 adjusted to the target Huffman length.
    let n = ((length as f64) / 0.8).ceil().max(1.0) as usize;
    let mut bytes = vec![0u8; n];
    let mut filled = 0;
    let mut random = [0u8; 256];
    while filled < n {
        if SystemRandom::new().fill(&mut random).is_err() {
            return "X".repeat(length as usize);
        }
        for b in random {
            if b < 248 && filled < n {
                bytes[filled] = BASE62[b as usize % 62];
                filled += 1;
            }
        }
    }
    let mut s = String::from_utf8(bytes).unwrap_or_default();
    let mut adjust = 'X';
    for _ in 0..150 {
        let diff = huffman_len(&s) - length;
        if diff.abs() <= 2 {
            break;
        }
        if diff < 0 {
            s.push(adjust);
            adjust = if adjust == 'X' { 'Z' } else { 'X' };
        } else if s.len() > 1 {
            s.pop();
        } else {
            break;
        }
    }
    s
}

fn padding_valid(value: &str, (from, to): (i64, i64), method: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    if method == "tokenish" {
        let n = huffman_len(value);
        return n >= (from - 2).max(0) && n <= to + 2;
    }
    let n = value.len() as i64;
    n >= from && n <= to
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
}

/// url.Values.Get on a raw query string.
fn query_get(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        if pair.contains(';') {
            return None;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let decode = |s: &str| {
            let bytes = s.as_bytes();
            for (i, b) in bytes.iter().enumerate() {
                if *b == b'%'
                    && !bytes
                        .get(i + 1..i + 3)
                        .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
                {
                    return None;
                }
            }
            percent_encoding::percent_decode_str(&s.replace('+', " "))
                .decode_utf8()
                .ok()
                .map(|s| s.into_owned())
        };
        (decode(k)? == key).then(|| decode(v)).flatten()
    })
}

/// The query of a URL string (url.Parse(...).Query()).
fn url_query(url: &str) -> &str {
    let url = url.split('#').next().unwrap_or_default();
    url.split_once('?').map(|(_, q)| q).unwrap_or_default()
}

/// http.Request.Cookie: the first cookie named `name` across Cookie headers.
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then(|| v.trim_matches('"').to_owned())
        })
}

impl Config {
    /// ExtractXPaddingFromRequest: the padding value (empty when absent) and where it was found.
    fn extract_padding(&self, req: &Request<Incoming>) -> (String, String) {
        let headers = req.headers();
        let query = req.uri().query().unwrap_or_default();
        if !self.obfs {
            if let Some(referer) = header(headers, "Referer") {
                return (
                    query_get(url_query(referer), "x_padding").unwrap_or_default(),
                    "queryInHeader=Referer, key=x_padding".into(),
                );
            }
            return (
                query_get(query, "x_padding").unwrap_or_default(),
                "query, key=x_padding".into(),
            );
        }
        let key = &self.padding_key;
        if let Some(value) = cookie(headers, key).filter(|v| !v.is_empty()) {
            return (value, format!("cookie, key={key}"));
        }
        if let Some(value) = header(headers, &self.padding_header) {
            let name = &self.padding_header;
            if self.padding_placement == "header" {
                return (value.to_owned(), format!("header={name}"));
            }
            return (
                query_get(url_query(value), key).unwrap_or_default(),
                format!("queryInHeader={name}, key={key}"),
            );
        }
        match query_get(query, key).filter(|v| !v.is_empty()) {
            Some(value) => (value, format!("query, key={key}")),
            None => Default::default(),
        }
    }

    /// ExtractMetaFromRequest: (session ID, seq), empty when absent.
    fn extract_meta(&self, req: &Request<Incoming>, path: &str) -> (String, String) {
        let headers = req.headers();
        let query = req.uri().query().unwrap_or_default();
        let rest = path.get(self.path.len()..).unwrap_or_default();
        let mut subpath = rest.split('/');
        let mut take = |placement: &str, key: &str| -> String {
            match placement {
                "path" => subpath.next().unwrap_or_default().to_owned(),
                "query" => query_get(query, key).unwrap_or_default(),
                "header" => header(headers, key).unwrap_or_default().to_owned(),
                "cookie" => cookie(headers, key).unwrap_or_default(),
                _ => String::new(),
            }
        };
        let session = take(&self.session_placement, &self.session_key);
        let seq = take(&self.seq_placement, &self.seq_key);
        (session, seq)
    }

    /// WriteResponseHeader (CORS) and ApplyXPaddingToResponse.
    fn response_headers(&self, req: &Request<Incoming>, out: &mut HeaderMap) {
        let headers = req.headers();
        let set = |out: &mut HeaderMap, k: &'static str, v: &str| {
            if let Ok(v) = HeaderValue::from_str(v) {
                out.insert(k, v);
            }
        };
        set(
            out,
            "access-control-allow-origin",
            header(headers, "Origin").unwrap_or("*"),
        );
        if [
            &self.session_placement,
            &self.seq_placement,
            &self.padding_placement,
            &self.data_placement,
        ]
        .iter()
        .any(|p| *p == "cookie")
        {
            set(out, "access-control-allow-credentials", "true");
        }
        if req.method() == Method::OPTIONS {
            set(
                out,
                "access-control-allow-methods",
                header(headers, "Access-Control-Request-Method").unwrap_or("*"),
            );
            set(
                out,
                "access-control-allow-headers",
                header(headers, "Access-Control-Request-Headers").unwrap_or("*"),
            );
        }
        let length = rand_between(self.padding);
        let (placement, name, method) = if self.obfs {
            (
                self.padding_placement.as_str(),
                self.padding_header.as_str(),
                self.padding_method.as_str(),
            )
        } else {
            ("header", "X-Padding", "repeat-x")
        };
        let value = generate_padding(method, length);
        match placement {
            "header" => {
                if let (Ok(k), Ok(v)) = (
                    http::HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(&value),
                ) {
                    out.insert(k, v);
                }
            }
            "queryInHeader" => {
                if let (Ok(k), Ok(v)) = (
                    http::HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(&format!("?{}={value}", self.padding_key)),
                ) {
                    out.insert(k, v);
                }
            }
            "cookie" if !value.is_empty() => {
                if let Ok(v) =
                    HeaderValue::from_str(&format!("{}={value}; Path=/", self.padding_key))
                {
                    out.append("set-cookie", v);
                }
            }
            _ => {}
        }
    }
}

enum Upload {
    Packet(u64, Vec<u8>, OwnedSemaphorePermit),
    Stream(Incoming),
}

/// httpSession with its uploadQueue.
struct Session {
    queue: mpsc::Sender<Upload>,
    receiver: Mutex<Option<mpsc::Receiver<Upload>>>,
    stream_up: AtomicBool,
    connected: AtomicBool,
    closed: watch::Sender<bool>,
}

impl Session {
    fn close(&self) {
        self.closed.send_replace(true);
        self.receiver.lock().unwrap().take();
    }

    async fn closed(&self) {
        let mut closed = self.closed.subscribe();
        let _ = closed.wait_for(|c| *c).await;
    }

    /// uploadQueue.Push.
    async fn push(&self, upload: Upload) -> Result<()> {
        if self.stream_up.load(Ordering::Acquire)
            || (matches!(upload, Upload::Stream(_)) && self.stream_up.swap(true, Ordering::AcqRel))
        {
            bail!("h.reader already exists");
        }
        tokio::select! {
            sent = self.queue.send(upload) => {
                ensure!(sent.is_ok() && !*self.closed.borrow(), "packet queue closed");
                Ok(())
            }
            _ = self.closed() => bail!("packet queue closed"),
        }
    }
}

/// uploadQueue.Read: reorders packet-up posts by seq (or copies the stream-up body) into the
/// VLESS side of the connection.
async fn uplink(
    session: Arc<Session>,
    mut uploads: mpsc::Receiver<Upload>,
    mut out: DuplexStream,
    max: usize,
) -> Result<()> {
    let mut heap: BTreeMap<u64, (Vec<u8>, OwnedSemaphorePermit)> = BTreeMap::new();
    let mut next = 0u64;
    loop {
        while let Some((seq, _)) = heap.first_key_value() {
            if *seq > next {
                // The reassembly buffer is too large: tear down and let the application retry.
                ensure!(heap.len() - 1 <= max, "packet queue is too large");
                break;
            }
            let Some((seq, (data, _budget))) = heap.pop_first() else {
                break;
            };
            if seq == next {
                tokio::select! {
                    result = out.write_all(&data) => result?,
                    _ = session.closed() => return Ok(()),
                }
                next += 1;
            }
        }
        let upload = tokio::select! {
            upload = uploads.recv() => upload,
            _ = session.closed() => None,
        };
        match upload {
            None => return Ok(()),
            Some(Upload::Packet(seq, data, budget)) => {
                heap.entry(seq).or_insert((data, budget));
            }
            Some(Upload::Stream(mut body)) => loop {
                let frame = tokio::select! {
                    frame = body.frame() => frame,
                    _ = session.closed() => None,
                };
                match frame {
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            tokio::select! {
                                result = out.write_all(&data) => result?,
                                _ = session.closed() => return Ok(()),
                            }
                        }
                    }
                    Some(Err(error)) => return Err(error.into()),
                    None => return Ok(()),
                }
            },
        }
    }
}

/// Response body copied from a pipe; `on_drop` runs when hyper is done with it.
struct Down {
    pipe: Option<DuplexStream>,
    buf: Box<[u8; 16384]>,
    on_drop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl Down {
    fn empty() -> Self {
        Self {
            pipe: None,
            buf: Box::new([0; 16384]),
            on_drop: None,
        }
    }
    fn pipe(pipe: DuplexStream, on_drop: Box<dyn FnOnce() + Send + Sync>) -> Self {
        Self {
            pipe: Some(pipe),
            buf: Box::new([0; 16384]),
            on_drop: Some(on_drop),
        }
    }
}

impl Drop for Down {
    fn drop(&mut self) {
        if let Some(f) = self.on_drop.take() {
            f();
        }
    }
}

impl Body for Down {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = &mut *self;
        let Some(pipe) = this.pipe.as_mut() else {
            return Poll::Ready(None);
        };
        let mut buf = ReadBuf::new(&mut this.buf[..]);
        match ready!(Pin::new(pipe).poll_read(cx, &mut buf)) {
            Ok(()) if buf.filled().is_empty() => {
                this.pipe = None;
                Poll::Ready(None)
            }
            Ok(()) => Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(buf.filled()))))),
            Err(error) => Poll::Ready(Some(Err(error))),
        }
    }
    fn is_end_stream(&self) -> bool {
        self.pipe.is_none()
    }
}

struct Server {
    me: Arc<Instance>,
    index: usize,
    config: Arc<Config>,
    trusted_xff: Vec<String>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    payload_budget: Arc<Semaphore>,
}

// Bound unauthenticated session IDs independently of the per-session upload queue.
const MAX_SESSIONS: usize = 1024;
const MAX_QUEUED_PAYLOAD: usize = 64 * 1024 * 1024;
// Charge a minimum per upload so empty packets cannot create unbounded blocked tasks.
const MIN_UPLOAD_RESERVATION: usize = 64 * 1024;

fn status(code: StatusCode, mut headers: HeaderMap) -> Response<Down> {
    let mut response = Response::new(Down::empty());
    *response.status_mut() = code;
    headers.insert("content-length", HeaderValue::from_static("0"));
    *response.headers_mut() = headers;
    response
}

impl Server {
    /// upsertSession: a session not joined by its GET within 30 s is reaped.
    fn upsert(self: &Arc<Self>, id: &str) -> Option<Arc<Session>> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(s) = sessions.get(id) {
            return Some(s.clone());
        }
        if sessions.len() >= MAX_SESSIONS {
            return None;
        }
        let (queue, receiver) = mpsc::channel(self.config.max_buffered_posts);
        let session = Arc::new(Session {
            queue,
            receiver: Mutex::new(Some(receiver)),
            stream_up: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            closed: watch::channel(false).0,
        });
        sessions.insert(id.to_owned(), session.clone());
        let (me, id, reaped) = (self.clone(), id.to_owned(), session.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if !reaped.connected.load(Ordering::Acquire) {
                let mut sessions = me.sessions.lock().unwrap();
                if sessions.get(&id).is_some_and(|s| Arc::ptr_eq(s, &reaped)) {
                    sessions.remove(&id);
                }
                reaped.close();
            }
        });
        Some(session)
    }

    async fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Response<Down> {
        let c = &self.config;
        let host = req
            .uri()
            .authority()
            .map(|a| a.as_str().to_owned())
            .or_else(|| header(req.headers(), "host").map(str::to_owned))
            .unwrap_or_default();
        if !c.host.is_empty() && !crate::transport::valid_host(&host, &c.host) {
            tracing::info!(
                "transport/internet/splithttp: failed to validate host, request:{host}, config:{}",
                c.host
            );
            return status(StatusCode::NOT_FOUND, HeaderMap::new());
        }
        let path = percent_encoding::percent_decode_str(req.uri().path())
            .decode_utf8_lossy()
            .into_owned();
        if !path.starts_with(&c.path) {
            tracing::info!(
                "transport/internet/splithttp: failed to validate path, request:{path}, config:{}",
                c.path
            );
            return status(StatusCode::NOT_FOUND, HeaderMap::new());
        }
        let mut headers = HeaderMap::new();
        c.response_headers(&req, &mut headers);
        // A real CORS preflight always carries Access-Control-Request-Method.
        if req.method() == Method::OPTIONS
            && header(req.headers(), "Access-Control-Request-Method").is_some()
        {
            return status(StatusCode::OK, headers);
        }
        let (padding, placement) = c.extract_padding(&req);
        if !padding_valid(&padding, c.padding, &c.padding_method) {
            tracing::info!(
                "transport/internet/splithttp: invalid padding ({placement}) length:{}",
                padding.len()
            );
            return status(StatusCode::BAD_REQUEST, headers);
        }
        let obfs_padding = c.obfs && !padding.is_empty();
        let (session_id, seq) = c.extract_meta(&req, &path);
        if session_id.is_empty() && !matches!(c.mode.as_str(), "auto" | "stream-one" | "stream-up")
        {
            tracing::info!("transport/internet/splithttp: stream-one mode is not allowed");
            return status(StatusCode::BAD_REQUEST, headers);
        }
        let remote = crate::transport::forwarded_for(
            header(req.headers(), "X-Forwarded-For"),
            |t| req.headers().contains_key(t),
            &self.trusted_xff,
            peer,
        );
        let uplink = req.method() != Method::GET || !seq.is_empty();
        if !session_id.is_empty() && uplink {
            let allowed = if seq.is_empty() {
                "stream-up"
            } else {
                "packet-up"
            };
            if c.mode != "auto" && c.mode != allowed {
                return status(StatusCode::BAD_REQUEST, headers);
            }
            if !seq.is_empty() {
                return self.packet(req, &session_id, &seq, headers).await;
            }
        }
        let session = if session_id.is_empty() {
            None
        } else {
            match self.upsert(&session_id) {
                Some(session) => Some(session),
                None => return status(StatusCode::SERVICE_UNAVAILABLE, headers),
            }
        };
        match session {
            Some(session) if uplink && seq.is_empty() => {
                let referer = header(req.headers(), "Referer").is_some();
                if let Err(error) = session.push(Upload::Stream(req.into_body())).await {
                    tracing::info!(
                        "transport/internet/splithttp: failed to upload (PushReader) > {error}"
                    );
                    return status(StatusCode::CONFLICT, headers);
                }
                headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
                headers.insert("cache-control", HeaderValue::from_static("no-store"));
                let (mut tx, rx) = tokio::io::duplex(4096);
                let secs = c.stream_up_server_secs;
                let (config, waiting) = (c.clone(), session.clone());
                let padding_task = tokio::spawn(async move {
                    if (referer || obfs_padding) && secs.1 > 0 {
                        loop {
                            let padding = "X".repeat(rand_between(config.padding) as usize);
                            tokio::select! {
                                result = tx.write_all(padding.as_bytes()) => if result.is_err() { return; },
                                _ = waiting.closed() => return,
                            }
                            let pause = Duration::from_secs(rand_between(secs).max(0) as u64);
                            tokio::select! {
                                _ = tokio::time::sleep(pause) => {}
                                _ = waiting.closed() => return,
                            }
                        }
                    }
                    waiting.closed().await;
                });
                let mut response =
                    Response::new(Down::pipe(rx, Box::new(move || padding_task.abort())));
                *response.headers_mut() = headers;
                response
            }
            session if req.method() == Method::GET || session.is_none() => {
                self.download(req, session, session_id, remote, local, headers)
            }
            _ => {
                tracing::info!(
                    "transport/internet/splithttp: unsupported method: {}",
                    req.method()
                );
                status(StatusCode::METHOD_NOT_ALLOWED, headers)
            }
        }
    }

    async fn packet(
        self: &Arc<Self>,
        req: Request<Incoming>,
        session_id: &str,
        seq: &str,
        mut headers: HeaderMap,
    ) -> Response<Down> {
        let c = &self.config;
        let Some(seq) = seq
            .parse::<u64>()
            .ok()
            .filter(|_| seq.bytes().all(|b| b.is_ascii_digit()))
        else {
            return status(StatusCode::INTERNAL_SERVER_ERROR, headers);
        };
        let Ok(mut budget) = self
            .payload_budget
            .clone()
            .try_acquire_many_owned(c.max_each_post.max(MIN_UPLOAD_RESERVATION) as u32)
        else {
            return status(StatusCode::SERVICE_UNAVAILABLE, headers);
        };
        let placement = c.data_placement.as_str();
        let decode = |chunks: Vec<String>| {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(chunks.concat())
        };
        let mut payload = Vec::new();
        if matches!(placement, "auto" | "header") {
            let chunks = (0..)
                .map_while(|i| {
                    header(req.headers(), &format!("{}-{i}", c.data_key)).map(str::to_owned)
                })
                .collect();
            match decode(chunks) {
                Ok(data) => payload.extend(data),
                Err(error) => {
                    tracing::info!(
                        "transport/internet/splithttp: Invalid base64 in header's payload: {error}"
                    );
                    return status(StatusCode::BAD_REQUEST, headers);
                }
            }
        }
        if matches!(placement, "auto" | "cookie") {
            let chunks = (0..)
                .map_while(|i| cookie(req.headers(), &format!("{}_{i}", c.data_key)))
                .collect();
            match decode(chunks) {
                Ok(data) => payload.extend(data),
                Err(error) => {
                    tracing::info!(
                        "transport/internet/splithttp: Invalid base64 in cookies' payload: {error}"
                    );
                    return status(StatusCode::BAD_REQUEST, headers);
                }
            }
        }
        let mut body_len = 0;
        if matches!(placement, "auto" | "body") {
            let length =
                header(req.headers(), "content-length").and_then(|v| v.parse::<u64>().ok());
            if length.is_some_and(|l| l > c.max_each_post as u64) {
                tracing::info!(
                    "transport/internet/splithttp: Too large upload. scMaxEachPostBytes is set to {}but request size exceed it. Adjust scMaxEachPostBytes on the server to be at least as large as client.",
                    c.max_each_post
                );
                return status(StatusCode::PAYLOAD_TOO_LARGE, headers);
            }
            let limit = length.map_or(c.max_each_post + 1, |l| l as usize);
            let mut body = req.into_body();
            let mut data = Vec::new();
            while data.len() < limit {
                match body.frame().await {
                    Some(Ok(frame)) => {
                        if let Ok(chunk) = frame.into_data() {
                            data.extend_from_slice(&chunk);
                        }
                    }
                    Some(Err(error)) => {
                        tracing::info!(
                            "transport/internet/splithttp: failed to read body payload > {error}"
                        );
                        return status(StatusCode::BAD_REQUEST, headers);
                    }
                    None => break,
                }
            }
            data.truncate(limit);
            if length.is_some_and(|l| (data.len() as u64) < l) {
                tracing::info!(
                    "transport/internet/splithttp: failed to read body payload > unexpected EOF"
                );
                return status(StatusCode::BAD_REQUEST, headers);
            }
            body_len = data.len();
            payload.extend(data);
        }
        if payload.len() > c.max_each_post {
            tracing::info!(
                "transport/internet/splithttp: Too large upload. scMaxEachPostBytes is set to {}but request size exceed it. Adjust scMaxEachPostBytes on the server to be at least as large as client.",
                c.max_each_post
            );
            return status(StatusCode::PAYLOAD_TOO_LARGE, headers);
        }
        let Some(session) = self.upsert(session_id) else {
            return status(StatusCode::SERVICE_UNAVAILABLE, headers);
        };
        let payload_budget = budget
            .split(payload.len().max(MIN_UPLOAD_RESERVATION))
            .unwrap();
        drop(budget);
        if let Err(error) = session
            .push(Upload::Packet(seq, payload, payload_budget))
            .await
        {
            tracing::info!(
                "transport/internet/splithttp: failed to upload (PushPayload) > {error}"
            );
            return status(StatusCode::INTERNAL_SERVER_ERROR, headers);
        }
        if body_len == 0 {
            // Methods without a body are usually cached by default.
            headers.insert("cache-control", HeaderValue::from_static("no-store"));
        }
        status(StatusCode::OK, headers)
    }

    /// stream-down (GET with a session) or stream-one (no session): one VLESS connection.
    fn download(
        self: &Arc<Self>,
        req: Request<Incoming>,
        session: Option<Arc<Session>>,
        session_id: String,
        remote: SocketAddr,
        local: SocketAddr,
        mut headers: HeaderMap,
    ) -> Response<Down> {
        if let Some(session) = &session
            && (session.connected.swap(true, Ordering::AcqRel) || *session.closed.borrow())
        {
            return status(StatusCode::CONFLICT, headers);
        }
        let lifetime = session.clone().unwrap_or_else(standalone_session);
        let (up_read, up_write) = tokio::io::duplex(512 * 1024);
        let (down_read, down_write) = tokio::io::duplex(512 * 1024);
        let on_drop: Box<dyn FnOnce() + Send + Sync> = match session {
            Some(session) => {
                // After the GET is joined, the session lives exactly as long as it.
                let uploads = session.receiver.lock().unwrap().take();
                match uploads {
                    Some(uploads) => {
                        let max = self.config.max_buffered_posts;
                        tokio::spawn(uplink(session.clone(), uploads, up_write, max));
                    }
                    // A second GET for the same session gets no uplink.
                    None => drop(up_write),
                }
                let me = self.clone();
                Box::new(move || {
                    let mut sessions = me.sessions.lock().unwrap();
                    if sessions
                        .get(&session_id)
                        .is_some_and(|s| Arc::ptr_eq(s, &session))
                    {
                        sessions.remove(&session_id);
                    }
                    session.close();
                })
            }
            None => {
                let body = req.into_body();
                let session = lifetime.clone();
                tokio::spawn(async move {
                    let (queue, uploads) = mpsc::channel(1);
                    let _ = queue.send(Upload::Stream(body)).await;
                    drop(queue);
                    uplink(session, uploads, up_write, 0).await
                });
                let session = lifetime.clone();
                Box::new(move || session.close())
            }
        };
        let conn: BoxIo = Box::new(tokio::io::join(up_read, down_write));
        let (me, index) = (self.me.clone(), self.index);
        tokio::spawn(async move {
            let id = crate::app::session_id();
            tokio::select! {
                result = me.vless_conn(index, conn, remote, local, None, None, id) => {
                    if let Err(error) = result {
                        tracing::info!("{id}app/proxyman/inbound: connection ends > {error:#}");
                    }
                }
                _ = lifetime.closed() => {}
            }
        });
        headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
        headers.insert("cache-control", HeaderValue::from_static("no-store"));
        if !self.config.no_sse_header {
            headers.insert(
                "content-type",
                HeaderValue::from_static("text/event-stream"),
            );
        }
        let mut response = Response::new(Down::pipe(down_read, on_drop));
        *response.headers_mut() = headers;
        response
    }
}

/// A session handle for stream-one, whose uplink is the request body itself.
fn standalone_session() -> Arc<Session> {
    Arc::new(Session {
        queue: mpsc::channel(1).0,
        receiver: Mutex::new(None),
        stream_up: AtomicBool::new(true),
        connected: AtomicBool::new(true),
        closed: watch::channel(false).0,
    })
}

/// ListenXH for TCP: HTTP/1.1 and h2c (prior knowledge) on every accepted connection.
pub async fn serve(me: Arc<Instance>, index: usize, listener: TcpListener) {
    let inbound = &me.config.inbounds[index];
    let crate::transport::Transport::Xhttp(config) = &inbound.transport else {
        return;
    };
    let server = Arc::new(Server {
        me: me.clone(),
        index,
        config: config.clone(),
        trusted_xff: inbound.trusted_xff.clone(),
        sessions: Mutex::default(),
        payload_budget: Arc::new(Semaphore::new(MAX_QUEUED_PAYLOAD)),
    });
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let server = server.clone();
        tokio::spawn(async move {
            stream.set_nodelay(true).ok();
            let Ok(local) = stream.local_addr() else {
                return;
            };
            let inbound = &server.me.config.inbounds[server.index];
            let max_header = config_header_limit(&inbound.transport);
            let handshake = server.me.config.policy.level(0).handshake;
            let io: BoxIo = match (&inbound.tls, &inbound.reality) {
                (Some(tls), _) => {
                    match tokio::time::timeout(handshake, tls.accept(stream, true)).await {
                        Ok(Ok(accepted)) => accepted.io,
                        Ok(Err(error)) if error.is::<crate::vless::EmptyRequest>() => return,
                        Ok(Err(error)) => {
                            tracing::info!("transport/internet/splithttp: {error:#}");
                            return;
                        }
                        Err(_) => return,
                    }
                }
                (None, Some(reality)) => {
                    match crate::reality::accept(reality, stream, handshake).await {
                        Ok((io, _)) => io,
                        Err(error) => {
                            tracing::info!("transport/internet/splithttp: {error:#}");
                            return;
                        }
                    }
                }
                (None, None) => Box::new(stream),
            };
            let service = hyper::service::service_fn(move |req| {
                let server = server.clone();
                async move { Ok::<_, Infallible>(server.handle(req, peer, local).await) }
            });
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            // No header_read_timeout: hyper would also apply it to idle keep-alive waits, which
            // net/http never times out (ReadHeaderTimeout starts with the next request's bytes),
            // and closing an idle upload connection breaks a Go client's next packet-up POST.
            builder.http1().max_buf_size((max_header + 4096).max(8192));
            // net/http pads MaxHeaderBytes for HTTP/2 by ten 32-byte field overheads.
            builder
                .http2()
                .max_header_list_size((max_header + 320) as u32);
            let _ = builder
                .serve_connection(hyper_util::rt::TokioIo::new(io), service)
                .await;
        });
    }
}

fn config_header_limit(transport: &crate::transport::Transport) -> usize {
    match transport {
        crate::transport::Transport::Xhttp(c) => c.max_header_bytes,
        _ => 8192,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn packet(seq: u64, data: Vec<u8>) -> Upload {
        Upload::Packet(
            seq,
            data,
            Arc::new(Semaphore::new(0))
                .try_acquire_many_owned(0)
                .unwrap(),
        )
    }

    fn server() -> Arc<Server> {
        let config = crate::config::Config::parse(&json!({
            "inbounds": [{"tag": "test", "port": 12345, "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/x", "xPaddingBytes": 1}}}]
        }).to_string()).unwrap();
        let me = Instance::new(config).unwrap();
        let crate::transport::Transport::Xhttp(config) = &me.config.inbounds[0].transport else {
            unreachable!()
        };
        Arc::new(Server {
            config: config.clone(),
            me,
            index: 0,
            trusted_xff: vec![],
            sessions: Mutex::default(),
            payload_budget: Arc::new(Semaphore::new(MAX_QUEUED_PAYLOAD)),
        })
    }

    async fn request(server: Arc<Server>, method: Method, path: &str) -> Response<Incoming> {
        request_body(server, method, path, Bytes::new()).await
    }

    async fn request_body(
        server: Arc<Server>,
        method: Method,
        path: &str,
        body: Bytes,
    ) -> Response<Incoming> {
        request_protocol(server, method, path, body, false).await
    }

    async fn request_protocol(
        server: Arc<Server>,
        method: Method,
        path: &str,
        body: Bytes,
        h2: bool,
    ) -> Response<Incoming> {
        let (client, io) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let server = server.clone();
                async move {
                    Ok::<_, Infallible>(
                        server
                            .handle(
                                req,
                                "127.0.0.1:1".parse().unwrap(),
                                "127.0.0.1:2".parse().unwrap(),
                            )
                            .await,
                    )
                }
            });
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(hyper_util::rt::TokioIo::new(io), service)
                .await
                .ok();
        });
        let request = Request::builder()
            .method(method)
            .uri(format!("http://example.com{path}"))
            .header("host", "example.com")
            .body(http_body_util::Full::new(body))
            .unwrap();
        if h2 {
            let (mut sender, connection) = hyper::client::conn::http2::handshake(
                hyper_util::rt::TokioExecutor::new(),
                hyper_util::rt::TokioIo::new(client),
            )
            .await
            .unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });
            return sender.send_request(request).await.unwrap();
        }
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(client))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        sender.send_request(request).await.unwrap()
    }

    #[tokio::test]
    async fn malformed_http1_and_h2_requests_do_not_allocate_sessions() {
        for h2 in [false, true] {
            let server = server();
            for (path, expected) in [
                ("/wrong/session?x_padding=X", StatusCode::NOT_FOUND),
                ("/x/session?x_padding=XX", StatusCode::BAD_REQUEST),
                ("/x/session?x_padding=%XX", StatusCode::BAD_REQUEST),
                (
                    "/x/session/+1?x_padding=X",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ),
                (
                    "/x/session/18446744073709551616?x_padding=X",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ),
            ] {
                let response =
                    request_protocol(server.clone(), Method::POST, path, Bytes::new(), h2).await;
                assert_eq!(response.status(), expected, "{path}, h2={h2}");
                assert!(server.sessions.lock().unwrap().is_empty());
            }
        }
    }

    #[tokio::test]
    async fn unauthenticated_vless_upload_does_not_dial_its_target() {
        for h2 in [false, true] {
            let server = server();
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut wire = vec![0; 18]; // Version, unknown UUID, empty addons.
            wire.push(1);
            wire.extend_from_slice(&target.local_addr().unwrap().port().to_be_bytes());
            wire.extend_from_slice(&[1, 127, 0, 0, 1]);
            let response = request_protocol(
                server.clone(),
                Method::POST,
                "/x/auth/0?x_padding=X",
                Bytes::from(wire),
                h2,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let response =
                request_protocol(server, Method::GET, "/x/auth?x_padding=X", Bytes::new(), h2)
                    .await;
            let body = tokio::time::timeout(Duration::from_secs(1), response.into_body().collect())
                .await
                .unwrap()
                .unwrap();
            assert!(body.to_bytes().is_empty());
            assert!(
                tokio::time::timeout(Duration::from_millis(20), target.accept())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn duplicate_download_does_not_close_original_session() {
        let server = server();
        let first = request(server.clone(), Method::GET, "/x/session?x_padding=X").await;
        assert_eq!(first.status(), StatusCode::OK);
        let session = server.sessions.lock().unwrap()["session"].clone();
        let second = request(server.clone(), Method::GET, "/x/session?x_padding=X").await;
        assert_eq!(second.status(), StatusCode::CONFLICT);
        drop(second);
        assert!(!*session.closed.borrow());
        drop(first);
    }

    #[tokio::test]
    async fn invalid_sequence_does_not_allocate_session() {
        let server = server();
        let response = request(
            server.clone(),
            Method::POST,
            "/x/session/not-a-number?x_padding=X",
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(server.sessions.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn session_capacity_rejects_new_ids_but_keeps_existing_uploads() {
        let server = server();
        for i in 0..1024 {
            server.upsert(&format!("s{i}"));
        }
        let response = request(server.clone(), Method::GET, "/x/new?x_padding=X").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let response = request(server.clone(), Method::POST, "/x/s0/0?x_padding=X").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(server.sessions.lock().unwrap().len(), 1024);
    }

    #[tokio::test]
    async fn aggregate_payload_budget_rejects_uploads_until_queued_data_is_released() {
        let server = server();
        let payload = Bytes::from(vec![1; 1_000_000]);
        for i in 0..67 {
            let response = request_body(
                server.clone(),
                Method::POST,
                &format!("/x/s{i}/0?x_padding=X"),
                payload.clone(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
        }
        let response = request_body(
            server.clone(),
            Method::POST,
            "/x/overflow/0?x_padding=X",
            payload.clone(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        server
            .sessions
            .lock()
            .unwrap()
            .remove("s0")
            .unwrap()
            .close();
        let response = request_body(
            server.clone(),
            Method::POST,
            "/x/overflow/0?x_padding=X",
            payload,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn builds_config_like_go() {
        let c = Config::parse(
            &json!({"mode": "packet-up", "path": "/files/download", "extra": {
                "xmux": {"cMaxReuseTimes": 0, "maxConcurrency": "8-16"}, "seqKey": "id",
                "headers": {"X-Code": "x"}, "xPaddingBytes": "50-80", "xPaddingObfsMode": true,
                "uplinkHTTPMethod": "GET", "uplinkDataPlacement": "header", "path": "/ignored"}}),
            "x",
        )
        .unwrap();
        assert_eq!(c.path, "/files/download/");
        assert_eq!(
            (c.mode.as_str(), c.padding, c.obfs),
            ("packet-up", (50, 80), true)
        );
        assert_eq!(
            (
                c.padding_placement.as_str(),
                c.padding_key.as_str(),
                c.padding_header.as_str()
            ),
            ("queryInHeader", "x_padding", "X-Padding")
        );
        assert_eq!(
            (c.data_placement.as_str(), c.data_key.as_str()),
            ("header", "X-Data")
        );
        assert_eq!(
            (c.seq_placement.as_str(), c.seq_key.as_str()),
            ("path", "id")
        );
        let defaults = Config::parse(&json!({}), "x").unwrap();
        assert_eq!(
            (
                defaults.mode.as_str(),
                defaults.padding,
                defaults.data_placement.as_str()
            ),
            ("auto", (100, 1000), "auto")
        );
        assert_eq!(defaults.path, "/");
        for bad in [
            json!({"mode": "x"}),
            json!({"xPaddingBytes": "0-10"}),
            json!({"uplinkDataPlacement": "header"}),
            json!({"uplinkHTTPMethod": "get", "mode": "stream-up"}),
            json!({"headers": {"Host": "a"}}),
            json!({"xmux": {"maxConnections": 2, "maxConcurrency": 2}}),
            json!({"xPaddingBytes": "a-b"}),
            json!({"sessionIDTable": "hex", "sessionIDLength": 4}),
            json!({"sessionidtable": "number", "sessionIDLength": "0-12"}),
            json!({"sessionIDTable": "абв", "sessionIDLength": 30}),
            json!({"scMaxEachPostBytes": -1}),
            json!({"scMaxEachPostBytes": 67_108_865}),
            json!({"serverMaxHeaderBytes": 4_294_967_296u64}),
            json!({"scMaxBufferedPosts": 9_223_372_036_854_775_807u64}),
            json!({"host": []}),
            json!({"scMaxBufferedPosts": "30"}),
            json!({"xPaddingObfsMode": "true"}),
            json!({"noSSEHeader": 1}),
            json!({"headers": []}),
            json!({"headers": {"X-Test": false}}),
        ] {
            assert!(Config::parse(&bad, "x").is_err(), "{bad}");
        }
        // Keys match case-insensitively; names that are not Go fields (older spellings
        // included) are ignored, as encoding/json does.
        let lenient = Config::parse(
            &json!({"SessionIDTable": "Base62", "sessionIDLength": "20", "sessionKey": "auth",
                    "sessionPlacement": "query", "scMaxPacketPayload": 15000, "SEQKEY": "n",
                    "seqPlacement": "query"}),
            "x",
        )
        .unwrap();
        assert_eq!(
            (lenient.session_placement.as_str(), lenient.seq_key.as_str()),
            ("path", "n")
        );
        assert_eq!(range(&json!("-5--1"), "r").unwrap(), (-5, -1));
        assert_eq!(range(&json!("80-50"), "r").unwrap(), (50, 80));
    }

    #[test]
    fn padding_and_query_helpers() {
        assert!(padding_valid("XXXXX", (5, 5), "repeat-x"));
        assert!(!padding_valid("", (0, 5), "repeat-x"));
        for _ in 0..20 {
            let token = generate_padding("tokenish", 300);
            assert!(padding_valid(&token, (300, 300), "tokenish"), "{token}");
            assert!(token.bytes().all(|b| b.is_ascii_alphanumeric()));
        }
        assert_eq!(huffman_len("XZ"), 2);
        assert_eq!(
            query_get(url_query("https://a/b?c=1&x_padding=XX%41"), "x_padding").as_deref(),
            Some("XXA")
        );
        assert_eq!(url_query("?x_padding=X"), "x_padding=X");
        assert_eq!(query_get("key=%XX", "key"), None);
        assert_eq!(query_get("key=x;y", "key"), None);
        assert_eq!(query_get("key=%XX&key=ok", "key").as_deref(), Some("ok"));
    }

    #[tokio::test]
    async fn empty_uploads_also_have_a_bounded_aggregate_queue() {
        let mut server = server();
        Arc::make_mut(&mut Arc::get_mut(&mut server).unwrap().config).max_each_post = 1;
        for i in 0..1024 {
            let response = request(
                server.clone(),
                Method::POST,
                &format!("/x/s{i}/0?x_padding=X"),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
        }
        let response = request(server, Method::POST, "/x/s0/1?x_padding=X").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test(start_paused = true)]
    async fn abandoned_sessions_expire_and_release_payload_while_joined_sessions_survive() {
        let server = server();
        let abandoned = server.upsert("abandoned").unwrap();
        let joined = server.upsert("joined").unwrap();
        joined.connected.store(true, Ordering::Release);
        let budget = server
            .payload_budget
            .clone()
            .try_acquire_many_owned(3)
            .unwrap();
        abandoned
            .push(Upload::Packet(0, vec![1; 3], budget))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(!*abandoned.closed.borrow());
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(*abandoned.closed.borrow());
        assert!(!*joined.closed.borrow());
        assert_eq!(server.sessions.lock().unwrap().len(), 1);
        assert_eq!(
            server.payload_budget.available_permits(),
            MAX_QUEUED_PAYLOAD
        );
    }

    #[tokio::test]
    async fn closing_session_cancels_a_blocked_uplink_write() {
        let session = standalone_session();
        let (queue, uploads) = mpsc::channel(1);
        let (mut reader, writer) = tokio::io::duplex(1);
        queue.send(packet(0, vec![1; 32])).await.unwrap();
        let task = tokio::spawn(uplink(session.clone(), uploads, writer, 1));
        let mut byte = [0];
        tokio::io::AsyncReadExt::read_exact(&mut reader, &mut byte)
            .await
            .unwrap();
        session.close();
        tokio::time::timeout(Duration::from_millis(100), task)
            .await
            .expect("blocked write ignored session cancellation")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn uplink_reorders_packets_and_drops_duplicates() {
        let session = standalone_session();
        let (queue, uploads) = mpsc::channel(8);
        let (mut reader, writer) = tokio::io::duplex(1024);
        let task = tokio::spawn(uplink(session, uploads, writer, 4));
        for (seq, data) in [(2, "c"), (0, "a"), (0, "x"), (1, "b"), (3, "d")] {
            queue
                .send(packet(seq, data.as_bytes().to_vec()))
                .await
                .unwrap();
        }
        drop(queue);
        let mut out = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut reader, &mut out)
            .await
            .unwrap();
        assert_eq!(out, "abcd");
        task.await.unwrap().unwrap();
        let session = standalone_session();
        let (queue, uploads) = mpsc::channel(8);
        let (_reader, writer) = tokio::io::duplex(1024);
        for seq in 1..=4 {
            queue.send(packet(seq, vec![1])).await.unwrap();
        }
        let error = uplink(session, uploads, writer, 2).await.unwrap_err();
        assert!(error.to_string().contains("too large"), "{error}");
    }
}

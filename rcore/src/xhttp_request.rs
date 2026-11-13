//! Xray 26.11.9 XHTTP outbound configuration and request formatting.
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_separate_download_stream_settings() {
        assert!(Config::parse(&json!({"path":"/upload", "downloadSettings":{
            "address":"127.0.0.1", "port":8443, "network":"xhttp", "security":"tls",
            "tlsSettings":{"serverName":"download.test"}, "xhttpSettings":{"path":"/download"}
        }}), "x").is_ok());
    }

    #[test]
    fn defaults_keep_go_xmux_bundle_and_packet_ranges() {
        let c = Config::parse(&json!({}), "x").unwrap();
        assert_eq!(c.post_size, (1_000_000, 1_000_000));
        assert_eq!(c.post_interval, (30, 30));
        assert_eq!(c.xmux.max_connections, (3, 3));
        assert_eq!(c.xmux.requests, (600, 900));
        assert_eq!(c.xmux.seconds, (1800, 3000));
        assert_eq!(rand_between((1, 2)), 1);
        let c = Config::parse(&json!({"xmux":{"hKeepAlivePeriod":-1}}), "x").unwrap();
        assert_eq!(c.xmux.max_connections, (0, 0));
        assert_eq!(c.xmux.requests, (0, 0));
        assert_eq!(c.xmux.keep_alive, -1);
    }

    #[test]
    fn stream_and_packet_request_wire_shape() {
        let c = Config::parse(
            &json!({"path":"x?z=hello%20world&b=2", "xPaddingBytes":3,
            "headers":{"User-Agent":"custom"}}),
            "x",
        )
        .unwrap();
        let (r, body) = c
            .request("http", "example.com", "id", Some(0), Some(b"abc"), false)
            .unwrap();
        assert_eq!(r.method(), Method::POST);
        assert_eq!(r.uri(), "http://example.com/x/id/0?z=hello%20world&b=2");
        assert_eq!(
            r.headers()["referer"],
            "http://example.com/x/?x_padding=XXX"
        );
        assert_eq!(r.headers()["content-length"], "3");
        assert!(!r.headers().contains_key("content-type"));
        assert_eq!(body, "abc");
        let (r, _) = c
            .request("https", "example.com", "", None, None, true)
            .unwrap();
        assert_eq!(r.headers()["content-type"], "application/grpc");
        assert_eq!(r.uri(), "https://example.com/x/?z=hello%20world&b=2");
        let (r, _) = c
            .request("http", "example.com", "id", None, None, false)
            .unwrap();
        assert_eq!(r.method(), Method::GET);
    }

    #[test]
    fn query_metadata_is_sorted_and_padding_precedes_session() {
        let c = Config::parse(
            &json!({"path":"/x?z=a%20b&a=old&a=other", "xPaddingBytes":2,
            "xPaddingObfsMode":true,"xPaddingPlacement":"query", "sessionIDPlacement":"query",
            "seqPlacement":"header"}),
            "x",
        )
        .unwrap();
        let (r, _) = c
            .request("http", "host", "one two", Some(4), Some(b"a"), false)
            .unwrap();
        assert_eq!(
            r.uri(),
            "http://host/x?a=old&a=other&x_padding=XX&x_session=one+two&z=a+b"
        );
        assert_eq!(r.headers()["x-seq"], "4");
        let mut query = "bad=%FF&bad=%fe&skip=%xx&semi=a;b".to_owned();
        set_query(&mut query, "key", "~ /+");
        assert_eq!(query, "bad=%FF&bad=%FE&key=~+%2F%2B");
    }

    #[test]
    fn chunked_data_and_custom_session_ids() {
        for placement in ["header", "cookie"] {
            let c = Config::parse(
                &json!({"mode":"packet-up", "uplinkDataPlacement":placement,
                "uplinkChunkSize":1,"sessionIDTable":"hex","sessionIDLength":12}),
                "x",
            )
            .unwrap();
            assert_eq!(c.chunk_size, (64, 64));
            let id = c.session_id().unwrap();
            assert_eq!(id.len(), 12);
            assert!(
                id.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            let (r, body) = c
                .request("http", "host", &id, Some(0), Some(&[255; 49]), false)
                .unwrap();
            assert!(body.is_empty());
            if placement == "header" {
                assert_eq!(r.headers()["x-data-0"].as_bytes().len(), 64);
                assert_eq!(r.headers()["x-data-1"], "_w");
            } else {
                assert!(
                    r.headers()["cookie"]
                        .to_str()
                        .unwrap()
                        .contains("x_data_1=_w")
                );
            }
        }
        let c = Config::parse(&json!({}), "x").unwrap();
        assert_eq!(c.session_id().unwrap().len(), 36);
        assert!(Config::parse(&json!({"downloadSettings":{}}), "x").is_err());
        assert!(Config::parse(&json!({"scMaxEachPostBytes":-1}), "x").is_err());
    }
    #[test]
    fn fetch_headers_and_user_agent_aliases() {
        let c = Config::parse(&json!({}), "x").unwrap();
        let (r, _) = c.request("http", "host", "", None, None, false).unwrap();
        assert_eq!(r.headers()["sec-fetch-mode"], "cors");
        assert_eq!(r.headers()["priority"], "u=1, i");
        for (agent, prefix) in [
            ("edge", "Mozilla/5.0"),
            ("firefox", "Mozilla/5.0"),
            ("curl", "curl/"),
            ("golang", "Go-http-client/1.1"),
            ("custom", "custom"),
        ] {
            let c = Config::parse(&json!({"headers":{"User-Agent":agent}}), "x").unwrap();
            let (r, _) = c.request("http", "host", "", None, None, false).unwrap();
            assert!(
                r.headers()["user-agent"]
                    .to_str()
                    .unwrap()
                    .starts_with(prefix)
            );
            if agent == "edge" {
                assert!(
                    r.headers()["sec-ch-ua"]
                        .to_str()
                        .unwrap()
                        .contains("Microsoft Edge")
                );
            }
            if agent == "firefox" {
                assert_eq!(r.headers()["priority"], "u=4");
            }
            if agent == "curl" || agent == "custom" || agent == "golang" {
                assert!(!r.headers().contains_key("sec-fetch-mode"));
            }
        }
    }
}

use crate::xhttp::{generate_padding, go_fields, rand_between, range};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(crate) struct Xmux {
    pub max_connections: (i64, i64),
    pub max_concurrency: (i64, i64),
    pub reuse: (i64, i64),
    pub requests: (i64, i64),
    pub seconds: (i64, i64),
    pub keep_alive: i64,
}

#[derive(Clone)]
pub(crate) struct Config {
    pub server: crate::xhttp::Config,
    pub query: String,
    pub method: Method,
    pub post_size: (i64, i64),
    pub post_interval: (i64, i64),
    pub chunk_size: (i64, i64),
    pub xmux: Xmux,
    pub download: Option<std::sync::Arc<crate::xhttp_client::Download>>,
    headers: HeaderMap,
    no_grpc: bool,
    session_table: Vec<u8>,
    session_length: (i64, i64),
}

impl Config {
    pub(crate) fn parse(settings: &Value, path: &str) -> Result<Self> {
        let server = crate::xhttp::Config::parse(settings, path)?;
        let outer = go_fields(settings);
        let extra = go_fields(&outer["extra"]);
        let c = if outer.get("extra").is_none() {
            &outer
        } else {
            &extra
        };
        let download = if c["downloadSettings"].is_null() {
            None
        } else {
            Some(std::sync::Arc::new(crate::config::parse_xhttp_download(
                &c["downloadSettings"],
                &format!("{path}.downloadSettings"),
            )?))
        };
        let normalized = |key: &str, default: (i64, i64)| -> Result<(i64, i64)> {
            let r = range(&c[key], &format!("{path}.{key}"))?;
            Ok(if r.1 == 0 { default } else { r })
        };
        let post_size = normalized("scMaxEachPostBytes", (1_000_000, 1_000_000))?;
        ensure!(
            post_size.0 > 0,
            "{path}: `scMaxEachPostBytes` should be bigger than 0"
        );
        let post_interval = normalized("scMinPostsIntervalMs", (30, 30))?;
        let chunk = range(&c["uplinkChunkSize"], path)?;
        let chunk_size = if chunk.1 == 0 {
            match server.data_placement.as_str() {
                "cookie" => (2048, 3072),
                "header" => (3000, 4000),
                _ => post_size,
            }
        } else if chunk.0 < 64 {
            (64, chunk.1.max(64))
        } else {
            chunk
        };
        let mut headers = HeaderMap::new();
        for (k, v) in c["headers"].as_object().into_iter().flatten() {
            headers.append(
                HeaderName::from_bytes(k.as_bytes())?,
                HeaderValue::from_str(v.as_str().unwrap())?,
            );
        }
        default_headers(&mut headers)?;
        let method = c["uplinkHTTPMethod"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or("POST")
            .to_uppercase()
            .parse()?;
        let table = c["sessionIDTable"].as_str().unwrap_or_default();
        let session_table = match table {
            "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "HEX" => "0123456789ABCDEF",
            "alphabet" => "abcdefghijklmnopqrstuvwxyz",
            "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
            "hex" => "0123456789abcdef",
            "number" => "0123456789",
            t => t,
        }
        .as_bytes()
        .to_vec();
        let xm = &c["xmux"];
        ensure!(
            xm.is_null() || xm.is_object(),
            "{path}.xmux must be an object"
        );
        let field = |key: &str| {
            xm.as_object()
                .and_then(|o| {
                    o.iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(key))
                        .map(|(_, v)| v)
                })
                .unwrap_or(&Value::Null)
        };
        let mut xmux = Xmux {
            max_connections: range(field("maxConnections"), path)?,
            max_concurrency: range(field("maxConcurrency"), path)?,
            reuse: range(field("cMaxReuseTimes"), path)?,
            requests: range(field("hMaxRequestTimes"), path)?,
            seconds: range(field("hMaxReusableSecs"), path)?,
            keep_alive: if field("hKeepAlivePeriod").is_null() {
                0
            } else {
                field("hKeepAlivePeriod").as_i64().ok_or_else(|| {
                    anyhow::anyhow!("{path}.xmux.hKeepAlivePeriod must be an integer")
                })?
            },
        };
        ensure!(
            xmux.max_connections.1 <= 0 || xmux.max_concurrency.1 <= 0,
            "{path}: maxConnections cannot be specified together with maxConcurrency"
        );
        if xmux.max_connections == (0, 0)
            && xmux.max_concurrency == (0, 0)
            && xmux.reuse == (0, 0)
            && xmux.requests == (0, 0)
            && xmux.seconds == (0, 0)
            && xmux.keep_alive == 0
        {
            xmux.max_connections = (3, 3);
            xmux.requests = (600, 900);
            xmux.seconds = (1800, 3000);
        }
        Ok(Self {
            server,
            query: outer["path"]
                .as_str()
                .unwrap_or_default()
                .split_once('?')
                .map(|(_, q)| q.to_owned())
                .unwrap_or_default(),
            method,
            post_size,
            post_interval,
            chunk_size,
            xmux,
            download,
            headers,
            no_grpc: c["noGRPCHeader"] == true,
            session_table,
            session_length: range(&c["sessionIDLength"], path)?,
        })
    }

    pub(crate) fn session_id(&self) -> Result<String> {
        let n = rand_between(self.session_length);
        if !self.session_table.is_empty() && n > 0 {
            let mut out = String::with_capacity(n as usize);
            let size = self.session_table.len() as u64;
            // Reject the incomplete final interval, as Go's rand.N does.
            let limit = u64::MAX - u64::MAX % size;
            while out.len() < n as usize {
                let mut b = [0; 8];
                SystemRandom::new()
                    .fill(&mut b)
                    .map_err(|_| anyhow::anyhow!("random session ID failed"))?;
                let x = u64::from_le_bytes(b);
                if x < limit {
                    out.push(self.session_table[(x % size) as usize] as char);
                }
            }
            Ok(out)
        } else {
            let mut id = [0; 16];
            SystemRandom::new()
                .fill(&mut id)
                .map_err(|_| anyhow::anyhow!("random session ID failed"))?;
            id[6] = (id[6] & 0x0f) | 0x40;
            id[8] = (id[8] & 0x3f) | 0x80;
            Ok(crate::vless::uuid_string(id))
        }
    }

    pub(crate) fn request(
        &self,
        scheme: &str,
        authority: &str,
        session: &str,
        seq: Option<u64>,
        data: Option<&[u8]>,
        streaming: bool,
    ) -> Result<(Request<()>, Bytes)> {
        let c = &self.server;
        let mut headers = self.headers.clone();
        let mut path = c.path.clone();
        let mut query = self.query.clone();
        let raw_url = url(scheme, authority, &path, &query);
        let body = if let Some(data) = data {
            if matches!(c.data_placement.as_str(), "auto" | "body") {
                headers.insert(
                    "content-length",
                    HeaderValue::from_str(&data.len().to_string())?,
                );
                Bytes::copy_from_slice(data)
            } else {
                let encoded = URL_SAFE_NO_PAD.encode(data);
                let mut offset = 0;
                let mut i = 0;
                while offset < encoded.len() {
                    let end = (offset + rand_between(self.chunk_size) as usize).min(encoded.len());
                    let chunk = &encoded[offset..end];
                    if c.data_placement == "header" {
                        headers.insert(
                            HeaderName::from_bytes(format!("{}-{i}", c.data_key).as_bytes())?,
                            HeaderValue::from_str(chunk)?,
                        );
                    } else {
                        add_cookie(&mut headers, &format!("{}_{i}", c.data_key), chunk)?;
                    }
                    offset = end;
                    i += 1;
                }
                Bytes::new()
            }
        } else {
            Bytes::new()
        };
        let length = rand_between(c.padding);
        let padding = generate_padding(
            if c.obfs {
                &c.padding_method
            } else {
                "repeat-x"
            },
            length,
        );
        let (placement, key, header) = if c.obfs {
            (
                c.padding_placement.as_str(),
                c.padding_key.as_str(),
                c.padding_header.as_str(),
            )
        } else {
            ("queryInHeader", "x_padding", "Referer")
        };
        match placement {
            "header" => {
                headers.insert(
                    HeaderName::from_bytes(header.as_bytes())?,
                    HeaderValue::from_str(&padding)?,
                );
            }
            "queryInHeader" => {
                let referer = format!("{}?{key}={padding}", raw_url.split('?').next().unwrap());
                headers.insert(
                    HeaderName::from_bytes(header.as_bytes())?,
                    HeaderValue::from_str(&referer)?,
                );
            }
            "cookie" => add_cookie(&mut headers, key, &padding)?,
            "query" => {
                if !key.is_empty() && !padding.is_empty() {
                    set_query(&mut query, key, &padding);
                }
            }
            _ => unreachable!(),
        }
        apply_meta(
            &mut path,
            &mut query,
            &mut headers,
            &c.session_placement,
            &c.session_key,
            session,
        )?;
        if data.is_some()
            && let Some(seq) = seq
        {
            apply_meta(
                &mut path,
                &mut query,
                &mut headers,
                &c.seq_placement,
                &c.seq_key,
                &seq.to_string(),
            )?;
        }
        if data.is_none() && streaming && !self.no_grpc {
            headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        }
        let method = if data.is_some() || streaming {
            self.method.clone()
        } else {
            Method::GET
        };
        let mut request = Request::builder()
            .method(method)
            .uri(url(scheme, authority, &path, &query))
            .body(())?;
        *request.headers_mut() = headers;
        Ok((request, body))
    }
}

const PATH_ESCAPE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b',')
    .remove(b'/')
    .remove(b':')
    .remove(b';')
    .remove(b'=')
    .remove(b'@');
const QUERY_ESCAPE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn url(scheme: &str, authority: &str, path: &str, query: &str) -> String {
    let escaped = percent_encoding::utf8_percent_encode(path, PATH_ESCAPE).to_string();
    format!(
        "{scheme}://{authority}{escaped}{}{query}",
        if query.is_empty() { "" } else { "?" }
    )
}

fn query_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                if i + 2 >= b.len() {
                    return None;
                }
                let n = std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|v| u8::from_str_radix(v, 16).ok())?;
                out.push(n);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            v => {
                out.push(v);
                i += 1;
            }
        }
    }
    Some(out)
}

fn set_query(query: &mut String, key: &str, value: &str) {
    let mut values: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
    for segment in query
        .split('&')
        .filter(|s| !s.is_empty() && !s.contains(';'))
    {
        let (k, v) = segment.split_once('=').unwrap_or((segment, ""));
        if let (Some(k), Some(v)) = (query_decode(k), query_decode(v)) {
            values.entry(k).or_default().push(v);
        }
    }
    values.insert(key.as_bytes().to_vec(), vec![value.as_bytes().to_vec()]);
    let encode = |s: &[u8]| {
        percent_encoding::percent_encode(s, QUERY_ESCAPE)
            .to_string()
            .replace("%20", "+")
    };
    *query = values
        .into_iter()
        .flat_map(|(k, vs)| vs.into_iter().map(move |v| (k.clone(), v)))
        .map(|(k, v)| format!("{}={}", encode(&k), encode(&v)))
        .collect::<Vec<_>>()
        .join("&");
}

fn apply_meta(
    path: &mut String,
    query: &mut String,
    headers: &mut HeaderMap,
    placement: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    match placement {
        "path" => {
            if !path.ends_with('/') {
                path.push('/');
            }
            path.push_str(value);
        }
        "query" => set_query(query, key, value),
        "header" => {
            headers.insert(
                HeaderName::from_bytes(key.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
        "cookie" => add_cookie(headers, key, value)?,
        _ => unreachable!(),
    }
    Ok(())
}

fn add_cookie(headers: &mut HeaderMap, name: &str, value: &str) -> Result<()> {
    if name.is_empty()
        || name
            .bytes()
            .any(|b| !b.is_ascii_graphic() || b"()<>@,;:\\\"/[]?={}".contains(&b))
    {
        return Ok(());
    }
    let value: String = value
        .bytes()
        .filter(|b| (0x20..0x7f).contains(b) && !b"\";\\".contains(b))
        .map(char::from)
        .collect();
    let value = if value.contains([' ', ',']) {
        format!("\"{value}\"")
    } else {
        value
    };
    let prefix = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(|v| format!("{v}; "))
        .unwrap_or_default();
    headers.insert(
        "cookie",
        HeaderValue::from_str(&format!("{prefix}{name}={value}"))?,
    );
    Ok(())
}

fn default_headers(headers: &mut HeaderMap) -> Result<()> {
    let agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    match agent.as_deref() {
        None | Some("chrome") => {
            for (k, v) in crate::browser::chrome_headers("fetch", |k| {
                headers.get(k).is_some_and(|v| !v.is_empty())
            }) {
                headers.insert(
                    HeaderName::from_bytes(k.as_bytes())?,
                    HeaderValue::from_str(&v)?,
                );
            }
        }
        Some("golang") => {
            headers.insert("user-agent", HeaderValue::from_static("Go-http-client/1.1"));
        }
        Some("edge" | "firefox" | "safari" | "curl") => {
            masquerade(headers, agent.as_deref().unwrap())?
        }
        _ => {}
    }
    Ok(())
}

fn masquerade(headers: &mut HeaderMap, browser: &str) -> Result<()> {
    use chrono::{Datelike, TimeZone};
    use std::sync::LazyLock;
    static FIREFOX: LazyLock<i64> = LazyLock::new(|| {
        let random = random_fraction();
        let today = chrono::Utc::now().timestamp() / 86400;
        (today
            - chrono::Utc
                .with_ymd_and_hms(2024, 7, 29, 0, 0, 0)
                .unwrap()
                .timestamp()
                / 86400
            - 25
            - (random.powi(2) * 50.0).floor() as i64)
            / 30
            + 128
    });
    static CURL: LazyLock<String> = LazyLock::new(|| {
        let today = chrono::Utc::now().timestamp() / 86400;
        format!(
            "8.{}.0",
            (today
                - chrono::Utc
                    .with_ymd_and_hms(2023, 3, 20, 0, 0, 0)
                    .unwrap()
                    .timestamp()
                    / 86400
                - 60
                - (random_fraction().powi(2) * 165.0).floor() as i64)
                / 57
        )
    });
    static SAFARI: LazyLock<Option<String>> = LazyLock::new(|| {
        let now = chrono::Utc::now();
        let mut year = now.year();
        let mut split = chrono::Utc
            .with_ymd_and_hms(year, 9, 23, 0, 0, 0)
            .unwrap()
            .timestamp()
            + (random_fraction().powi(3) * 75.0).floor() as i64 * 86400;
        if now.timestamp() < split {
            year -= 1;
            split = chrono::Utc
                .with_ymd_and_hms(year, 9, 23, 0, 0, 0)
                .unwrap()
                .timestamp()
                + (random_fraction().powi(3) * 75.0).floor() as i64 * 86400;
        }
        let minor = [
            0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
        ]
        .get(((now.timestamp() - split) / 1296000) as usize)?;
        Some(format!("{}.{minor}", year - 1999))
    });
    let mut put = |k: &str, v: String| -> Result<()> {
        headers.insert(
            HeaderName::from_bytes(k.as_bytes())?,
            HeaderValue::from_str(&v)?,
        );
        Ok(())
    };
    match browser {
        "edge" => {
            for (k, mut v) in crate::browser::chrome_headers("fetch", |_| true) {
                if k == "User-Agent" {
                    let major = v
                        .split("Chrome/")
                        .nth(1)
                        .and_then(|v| v.split('.').next())
                        .unwrap_or_default();
                    v = format!("{v}Edg/{major}.0.0.0");
                } else if k == "Sec-CH-UA" {
                    v = v.replace("Google Chrome", "Microsoft Edge");
                }
                put(&k, v)?;
            }
        }
        "firefox" => {
            put(
                "User-Agent",
                format!(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{}.0) Gecko/20100101 Firefox/{}.0",
                    *FIREFOX, *FIREFOX
                ),
            )?;
            put("DNT", "1".into())?;
            put("Accept-Language", "en-US,en;q=0.5".into())?;
        }
        "safari" => {
            put(
                "User-Agent",
                format!(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{} Safari/605.1.15",
                    SAFARI.as_ref().ok_or_else(|| anyhow::anyhow!(
                        "Go Safari User-Agent release index is outside its minor-version table"
                    ))?
                ),
            )?;
            put("Accept-Language", "en-US,en;q=0.9".into())?;
        }
        "curl" => {
            put("User-Agent", format!("curl/{}", *CURL))?;
            return Ok(());
        }
        _ => unreachable!(),
    }
    for (k, v) in [
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Site", "same-origin"),
    ] {
        headers.insert(
            HeaderName::from_bytes(k.as_bytes())?,
            HeaderValue::from_static(v),
        );
    }
    for (k, v) in [
        (
            "Priority",
            match browser {
                "edge" => "u=1, i",
                "firefox" => "u=4",
                _ => "u=3, i",
            },
        ),
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
        ("Accept", "*/*"),
    ] {
        if headers.get(k).is_none_or(|v| v.is_empty()) {
            headers.insert(
                HeaderName::from_bytes(k.as_bytes())?,
                HeaderValue::from_static(v),
            );
        }
    }
    Ok(())
}

fn random_fraction() -> f64 {
    let mut b = [0; 8];
    let _ = SystemRandom::new().fill(&mut b);
    (u64::from_le_bytes(b) >> 11) as f64 / (1u64 << 53) as f64
}

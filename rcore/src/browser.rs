//! Port of xray-core common/utils/browser.go: the Chrome headers Xray sends by default
//! (TryDefaultHeadersWith with no User-Agent set) for WebSocket upgrades and REALITY spiders.
use std::sync::LazyLock;

/// ChromeVersion: Chrome 144 (2026-01-13) plus one release per 35 days, minus a random lag.
static CHROME_VERSION: LazyLock<i64> = LazyLock::new(|| {
    let mut b = [0u8; 8];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    let random = (u64::from_le_bytes(b) >> 11) as f64 / (1u64 << 53) as f64;
    let start = 20466; // 2026-01-13 in days since the Unix epoch
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
        / 86400;
    let diff = today - start - 35 - (random.powi(2) * 105.0).floor() as i64;
    144 + diff / 35
});

const GREASE_NA: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
const VERSION_NA: [&str; 3] = ["8", "99", "24"];
const SHUFFLE3: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

fn chrome_ua() -> String {
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36",
        *CHROME_VERSION
    )
}

/// getGreasedChUa(version, "chrome").
fn chrome_ua_ch() -> String {
    let v = *CHROME_VERSION;
    let seed = v.max(0) as usize;
    let brands = [
        format!(
            "\"Not{}A{}Brand\";v=\"{}\"",
            GREASE_NA[seed % 11],
            GREASE_NA[(seed + 1) % 11],
            VERSION_NA[seed % 3]
        ),
        format!("\"Chromium\";v=\"{v}\""),
        format!("\"Google Chrome\";v=\"{v}\""),
    ];
    let mut shuffled = [""; 3];
    for (i, e) in SHUFFLE3[seed % 6].iter().enumerate() {
        shuffled[*e] = &brands[i];
    }
    shuffled.join(", ")
}

/// applyMasqueradedHeaders(header, "chrome", variant) for the variants rcore uses.
/// Returns (name, value) pairs; `existing` reports headers the user already set.
pub fn chrome_headers(variant: &str, existing: impl Fn(&str) -> bool) -> Vec<(String, String)> {
    let mut h: Vec<(&str, String)> = vec![
        ("Sec-CH-UA", chrome_ua_ch()),
        ("Sec-CH-UA-Mobile", "?0".into()),
        ("Sec-CH-UA-Platform", "\"Windows\"".into()),
        ("DNT", "1".into()),
        ("User-Agent", chrome_ua()),
        ("Accept-Language", "en-US,en;q=0.9".into()),
    ];
    match variant {
        "nav" => {
            if !existing("Cache-Control") {
                h.push(("Cache-Control", "max-age=0".into()));
            }
            h.push(("Upgrade-Insecure-Requests", "1".into()));
            if !existing("Accept") {
                h.push(("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".into()));
            }
            h.push(("Sec-Fetch-Site", "none".into()));
            h.push(("Sec-Fetch-Mode", "navigate".into()));
            h.push(("Sec-Fetch-User", "?1".into()));
            h.push(("Sec-Fetch-Dest", "document".into()));
            h.push(("Priority", "u=0, i".into()));
        }
        "ws" => {
            h.push(("Sec-Fetch-Mode", "websocket".into()));
            h.push(("Sec-Fetch-Dest", "empty".into()));
            h.push(("Sec-Fetch-Site", "same-origin".into()));
            for (k, v) in [
                ("Cache-Control", "no-cache"),
                ("Pragma", "no-cache"),
                ("Accept", "*/*"),
            ] {
                if !existing(k) {
                    h.push((k, v.into()));
                }
            }
        }
        _ => {}
    }
    h.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn chrome_client_hints_match_go_shape() {
        let ch = super::chrome_ua_ch();
        assert!(ch.contains("\"Chromium\";v=\"") && ch.contains("\"Google Chrome\";v=\""));
        assert_eq!(ch.matches(", ").count(), 2);
        assert!(*super::CHROME_VERSION >= 144);
        let ws = super::chrome_headers("ws", |k| k == "Pragma");
        assert!(
            ws.iter()
                .any(|(k, v)| k == "Sec-Fetch-Mode" && v == "websocket")
        );
        assert!(!ws.iter().any(|(k, _)| k == "Pragma"));
    }
}

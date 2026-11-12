//! Port of xray-core TCP sniffers (common/protocol/{http,tls,bittorrent}) in dispatcher order.

#[derive(Debug, PartialEq)]
pub enum Sniff {
    /// (protocol, domain) — domain is empty for bittorrent.
    Found(&'static str, String),
    /// ErrNoClue / ErrProtoNeedMoreData: read more and retry.
    NeedMore,
    NotMatched,
}

pub fn sniff_tcp(b: &[u8]) -> Sniff {
    let mut pending = false;
    for sniffer in [http, tls, bittorrent] {
        match sniffer(b) {
            Sniff::Found(p, d) => return Sniff::Found(p, d),
            Sniff::NeedMore => pending = true,
            Sniff::NotMatched => {}
        }
    }
    if pending {
        Sniff::NeedMore
    } else {
        Sniff::NotMatched
    }
}

fn http(b: &[u8]) -> Sniff {
    let mut method_ok = false;
    for m in ["get", "post", "head", "put", "delete", "options", "connect"] {
        if b.len() >= m.len() && b[..m.len()].eq_ignore_ascii_case(m.as_bytes()) {
            method_ok = true;
            break;
        }
        if b.len() < m.len() {
            return Sniff::NeedMore;
        }
    }
    if !method_ok {
        return Sniff::NotMatched;
    }
    let mut host = String::new();
    for header in b.split(|c| *c == b'\n').skip(1) {
        if header.is_empty() {
            break;
        }
        let Some(colon) = header.iter().position(|c| *c == b':') else {
            continue;
        };
        if String::from_utf8_lossy(&header[..colon]).to_lowercase() == "host" {
            let raw = String::from_utf8_lossy(&header[colon + 1..])
                .trim()
                .to_lowercase();
            // ParseHost: strip the port; bracketed IPv6 keeps its address only.
            let h = if let Some(rest) = raw.strip_prefix('[') {
                rest.split(']').next().unwrap_or_default().to_owned()
            } else if raw.matches(':').count() == 1 {
                raw.split(':').next().unwrap_or_default().to_owned()
            } else {
                raw
            };
            if h.is_empty() {
                return Sniff::NotMatched;
            }
            host = h;
        }
    }
    if host.is_empty() {
        Sniff::NeedMore
    } else {
        Sniff::Found("http1", host)
    }
}

fn tls(b: &[u8]) -> Sniff {
    if b.len() < 5 {
        return Sniff::NeedMore;
    }
    if b[0] != 0x16 || !(b[1] == 3 && b[2] <= 4) {
        return Sniff::NotMatched;
    }
    let len = u16::from_be_bytes([b[3], b[4]]) as usize;
    if 5 + len > b.len() {
        return Sniff::NeedMore;
    }
    client_hello(&b[5..5 + len])
}

fn client_hello(mut d: &[u8]) -> Sniff {
    let u16at = |d: &[u8], i: usize| ((d[i] as usize) << 8) | d[i + 1] as usize;
    if d.len() < 42 {
        return Sniff::NeedMore;
    }
    let sid = d[38] as usize;
    if sid > 32 || d.len() < 39 + sid {
        return Sniff::NeedMore;
    }
    d = &d[39 + sid..];
    if d.len() < 2 {
        return Sniff::NeedMore;
    }
    let ciphers = u16at(d, 0);
    if ciphers % 2 == 1 || d.len() < 2 + ciphers {
        return Sniff::NotMatched;
    }
    d = &d[2 + ciphers..];
    if d.is_empty() {
        return Sniff::NeedMore;
    }
    let comp = d[0] as usize;
    if d.len() < 1 + comp {
        return Sniff::NeedMore;
    }
    d = &d[1 + comp..];
    if d.len() < 2 {
        return Sniff::NotMatched;
    }
    let ext_len = u16at(d, 0);
    d = &d[2..];
    if ext_len != d.len() {
        return Sniff::NotMatched;
    }
    while !d.is_empty() {
        if d.len() < 4 {
            return Sniff::NotMatched;
        }
        let (ext, len) = (u16at(d, 0), u16at(d, 2));
        d = &d[4..];
        if d.len() < len {
            return Sniff::NotMatched;
        }
        if ext == 0 {
            let mut s = &d[..len];
            if s.len() < 2 || u16at(s, 0) != s.len() - 2 {
                return Sniff::NotMatched;
            }
            s = &s[2..];
            while !s.is_empty() {
                if s.len() < 3 {
                    return Sniff::NotMatched;
                }
                let (kind, n) = (s[0], u16at(s, 1));
                s = &s[3..];
                if s.len() < n {
                    return Sniff::NotMatched;
                }
                if kind == 0 {
                    let name = &s[..n];
                    if n == 0 {
                        return Sniff::NotMatched;
                    }
                    if name.iter().any(|c| *c <= b' ') {
                        return Sniff::NeedMore;
                    }
                    if name[n - 1] == b'.' {
                        return Sniff::NotMatched;
                    }
                    return Sniff::Found("tls", String::from_utf8_lossy(name).into_owned());
                }
                s = &s[n..];
            }
        }
        d = &d[len..];
    }
    Sniff::NotMatched
}

fn bittorrent(b: &[u8]) -> Sniff {
    if b.len() < 20 {
        return Sniff::NeedMore;
    }
    if b[0] == 19 && &b[1..20] == b"BitTorrent protocol" {
        Sniff::Found("bittorrent", String::new())
    } else {
        Sniff::NotMatched
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sniffs_http_tls_and_bittorrent() {
        assert_eq!(
            sniff_tcp(b"GET / HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\n"),
            Sniff::Found("http1", "example.com".into())
        );
        let mut bt = vec![19];
        bt.extend_from_slice(b"BitTorrent protocol");
        bt.extend_from_slice(&[0; 48]);
        assert_eq!(sniff_tcp(&bt), Sniff::Found("bittorrent", String::new()));
        assert_eq!(sniff_tcp(b"GE"), Sniff::NeedMore);
        assert_eq!(sniff_tcp(&[0xff; 64]), Sniff::NotMatched);
        // Minimal TLS 1.2 ClientHello with SNI "a.io".
        let sni = [0u8, 0, 0, 9, 0, 7, 0, 0, 4, b'a', b'.', b'i', b'o'];
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        hello.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        hello.extend_from_slice(&sni);
        let mut body = vec![1, 0, 0, hello.len() as u8];
        body.extend_from_slice(&hello);
        let mut record = vec![0x16, 3, 1];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        assert_eq!(sniff_tcp(&record), Sniff::Found("tls", "a.io".into()));
    }
}

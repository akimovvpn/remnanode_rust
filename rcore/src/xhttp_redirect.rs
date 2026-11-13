//! net/http.Client.Do redirect rules used by the pinned Go XHTTP client.
//! Go-derived portions retain the BSD notice in LICENSE-Go.
use super::*;

pub(super) async fn start(
    client: &Arc<HttpClient>,
    dial: &Dial,
    request: Request<Upload>,
    keep_alive: i64,
) -> Result<(ResponseFuture, Option<Active>)> {
    let original = url::Url::parse(&request.uri().to_string())?;
    let headers = request.headers().clone();
    let replay = match request.body() {
        Upload::Packet { data, .. } => Some(data.clone().unwrap_or_default()),
        _ => None,
    };
    let mut method = request.method().clone();
    let (response, active) = client.request_once(dial, request, keep_alive).await?;
    let (client, dial) = (client.clone(), dial.clone());
    Ok((
        Box::pin(async move {
            let mut response = response.await?;
            let mut current = original.clone();
            let mut include_body = true;
            let mut sensitive = true;
            for count in 1.. {
                let keep_body = match response.status().as_u16() {
                    301..=303 => false,
                    307 | 308 if replay.is_some() => true,
                    _ => return Ok(response),
                };
                let Some(location) = response.headers().get("location").filter(|h| !h.is_empty())
                else {
                    return Ok(response);
                };
                let next = current.join(location.to_str()?)?;
                ensure!(
                    matches!(next.scheme(), "http" | "https"),
                    "unsupported redirect protocol {}",
                    next.scheme()
                );
                if !keep_body {
                    include_body = false;
                    if method != http::Method::GET && method != http::Method::HEAD {
                        method = http::Method::GET;
                    }
                }
                let host = next.host_str().unwrap_or_default();
                let initial = original.host_str().unwrap_or_default();
                sensitive &= host == initial
                    || (!host.contains(':') && host.ends_with(&format!(".{initial}")));
                let mut copied = headers.clone();
                if !sensitive {
                    for name in [
                        "authorization",
                        "www-authenticate",
                        "cookie",
                        "cookie2",
                        "proxy-authorization",
                        "proxy-authenticate",
                    ] {
                        copied.remove(name);
                    }
                }
                if !include_body {
                    for name in [
                        "content-encoding",
                        "content-language",
                        "content-location",
                        "content-type",
                    ] {
                        copied.remove(name);
                    }
                }
                if !(current.scheme() == "https" && next.scheme() == "http")
                    && copied.get("referer").is_none_or(|h| h.is_empty())
                {
                    let mut referer = current.clone();
                    let _ = referer.set_username("");
                    let _ = referer.set_password(None);
                    copied.insert("referer", referer.as_str().parse()?);
                }
                let length = response
                    .headers()
                    .get("content-length")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|h| h.parse::<usize>().ok());
                if length.is_none_or(|n| n <= 2048) {
                    let mut read = 0;
                    while read < 2048 {
                        let Some(Ok(frame)) = response.body_mut().frame().await else {
                            break;
                        };
                        if let Ok(bytes) = frame.into_data() {
                            read += bytes.len();
                        }
                    }
                }
                drop(response);
                ensure!(count < 10, "stopped after 10 redirects");
                let body = if include_body {
                    replay.clone().unwrap_or_default()
                } else {
                    Bytes::new()
                };
                let mut request = Request::builder()
                    .method(method.clone())
                    .uri(next.as_str())
                    .body(Upload::packet(body, None))?;
                *request.headers_mut() = copied;
                let (future, _) = client.request_once(&dial, request, keep_alive).await?;
                response = future.await?;
                current = next;
            }
            unreachable!()
        }),
        active,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::TcpListener;

    async fn check(status: u16, post: bool, foreign: bool, limit: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dial = Dial {
            address: Address::Ip("127.0.0.1".parse().unwrap()),
            port: listener.local_addr().unwrap().port(),
            security: Security::None,
            socket: Default::default(),
            h2: false,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let peer = tokio::spawn(async move {
            loop {
                let (io, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(io),
                            service_fn(move |request: Request<Incoming>| {
                                let n = seen.fetch_add(1, Ordering::SeqCst);
                                async move {
                                    if n == 0 || limit {
                                        assert_eq!(
                                            request.into_body().collect().await.unwrap().to_bytes(),
                                            if post { "packet" } else { "" }
                                        );
                                        Ok::<_, io::Error>(
                                            Response::builder()
                                                .status(status)
                                                .header(
                                                    "location",
                                                    if foreign {
                                                        "http://other.example/next?q=1"
                                                    } else {
                                                        "next?q=1"
                                                    },
                                                )
                                                .body(Full::new(Bytes::new()))
                                                .unwrap(),
                                        )
                                    } else {
                                        assert_eq!(request.uri(), "/next?q=1");
                                        assert_eq!(
                                            request.method(),
                                            if post && status == 307 { "POST" } else { "GET" }
                                        );
                                        assert_eq!(
                                            request.headers().contains_key("authorization"),
                                            !foreign
                                        );
                                        assert_eq!(request.headers()["referer"], "explicit");
                                        if post && status != 307 {
                                            assert!(
                                                !request.headers().contains_key("content-type")
                                            );
                                        }
                                        let bytes =
                                            request.into_body().collect().await.unwrap().to_bytes();
                                        assert_eq!(
                                            bytes,
                                            if post && status == 307 { "packet" } else { "" }
                                        );
                                        Ok(Response::new(Full::new(Bytes::from_static(b"ok"))))
                                    }
                                }
                            }),
                        )
                        .await;
                });
            }
        });
        let client = Client::new(Config::parse(&json!({}), "x").unwrap()).select();
        let request = Request::builder()
            .uri("http://initial.example/start")
            .method(if post { "POST" } else { "GET" })
            .header("authorization", "fixture")
            .header("referer", "explicit")
            .header("content-type", "fixture/type")
            .body(Upload::packet(
                Bytes::from_static(if post { b"packet" } else { b"" }),
                None,
            ))
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let (response, _) = start(&client, &dial, request, -1).await?;
            response.await
        })
        .await
        .unwrap();
        if limit {
            assert!(result.err().unwrap().to_string().contains("10 redirects"));
            assert_eq!(calls.load(Ordering::SeqCst), 10);
        } else {
            assert_eq!(result.unwrap().status(), StatusCode::OK);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
        peer.abort();
    }

    #[tokio::test]
    async fn redirect_url_credentials_become_basic_auth_without_userinfo_in_host() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dial = Dial {
            address: Address::Ip("127.0.0.1".parse().unwrap()),
            port: listener.local_addr().unwrap().port(),
            security: Security::None,
            socket: Default::default(),
            h2: false,
        };
        let peer = tokio::spawn(async move {
            for n in 0..2 {
                let (mut io, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    io.read_exact(&mut byte).await.unwrap();
                    request.extend(byte);
                }
                if n == 0 {
                    io.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://user:p%40ss@initial.example/next\r\nContent-Length: 0\r\n\r\n").await.unwrap();
                } else {
                    let head = String::from_utf8(request).unwrap();
                    assert!(head.contains("Host: initial.example\r\n"), "{head}");
                    assert!(
                        head.contains("Authorization: Basic dXNlcjpwQHNz\r\n"),
                        "{head}"
                    );
                    io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                }
            }
        });
        let client = Client::new(Config::parse(&json!({}), "x").unwrap()).select();
        let request = Request::builder()
            .uri("http://initial.example/start")
            .body(Upload::packet(Bytes::new(), None))
            .unwrap();
        let (response, _) = start(&client, &dial, request, -1).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .unwrap();
        peer.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn follows_relative_download_redirect() {
        check(301, false, false, false).await;
    }
    #[tokio::test]
    async fn post_redirect_drops_body_headers_and_foreign_credentials() {
        check(302, true, true, false).await;
    }
    #[tokio::test]
    async fn preserves_replayable_packet_on_307() {
        check(307, true, false, false).await;
    }
    #[tokio::test]
    async fn stops_after_ten_requests_in_redirect_loop() {
        check(301, false, false, true).await;
    }
}

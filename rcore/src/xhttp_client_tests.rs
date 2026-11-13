use super::*;
use http_body_util::{Full, StreamBody};
use hyper::service::service_fn;
use serde_json::json;
use tokio::{net::TcpListener, sync::Notify, time::timeout};

const DEADLINE: Duration = Duration::from_secs(2);

#[tokio::test]
async fn http11_accepts_more_than_one_hundred_response_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = local_server(listener.local_addr().unwrap().port());
    let peer = tokio::spawn(async move {
        let (mut io, _) = listener.accept().await.unwrap();
        let mut request = [0; 8192];
        assert!(io.read(&mut request).await.unwrap() > 0);
        let mut response =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n".to_owned();
        for n in 0..256 {
            response.push_str(&format!("Header-{n}: value\r\n"));
        }
        response.push_str("\r\nok");
        io.write_all(response.as_bytes()).await.unwrap();
    });
    let mut connection = client(json!({"mode":"stream-one"}))
        .connect(&server, &Default::default())
        .await
        .unwrap();
    let mut bytes = [0; 2];
    timeout(DEADLINE, connection.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"ok");
    peer.await.unwrap();
}

fn local_server(port: u16) -> Server {
    Server {
        address: Address::Ip("127.0.0.1".parse().unwrap()),
        port,
        id: [0; 16],
        flow: String::new(),
        level: 0,
        network: crate::vless_out::Network::Raw,
        security: Security::None,
    }
}

fn client(value: serde_json::Value) -> Arc<Client> {
    Arc::new(Client::new(Config::parse(&value, "xhttp").unwrap()))
}

async fn body_bytes(mut body: Incoming, length: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    while bytes.len() < length {
        let frame = body.frame().await.expect("upload ended early").unwrap();
        if let Ok(data) = frame.into_data() {
            bytes.extend_from_slice(&data);
        }
    }
    bytes
}

#[tokio::test]
async fn stream_one_returns_before_response_and_streams_caller_upload() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = local_server(listener.local_addr().unwrap().port());
    let payload = vec![0x5a; BUFFER_SIZE * 4];
    let expected = payload.clone();
    let peer = tokio::spawn(async move {
        let (io, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                hyper_util::rt::TokioIo::new(io),
                service_fn(move |request: Request<Incoming>| {
                    let expected = expected.clone();
                    async move {
                        assert_eq!(request.method(), http::Method::POST);
                        assert_eq!(
                            body_bytes(request.into_body(), expected.len()).await,
                            expected
                        );
                        Ok::<_, io::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                    }
                }),
            )
            .await
            .unwrap();
    });
    let client = client(json!({"mode":"stream-one"}));
    let mut connection = timeout(DEADLINE, client.connect(&server, &Default::default()))
        .await
        .expect("connect waited for response headers before caller could upload")
        .unwrap();
    timeout(DEADLINE, connection.write_all(&payload))
        .await
        .unwrap()
        .unwrap();
    let mut response = [0; 2];
    timeout(DEADLINE, connection.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"ok");
    drop(connection);
    timeout(DEADLINE, peer).await.unwrap().unwrap();
}

#[tokio::test]
async fn stream_up_closes_upload_only_after_draining_early_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = local_server(listener.local_addr().unwrap().port());
    let payload = vec![0x3c; BUFFER_SIZE * 8];
    let expected = payload.clone();
    let uploaded = Arc::new(Notify::new());
    let seen = uploaded.clone();
    let stop = Arc::new(Notify::new());
    let finish = stop.clone();
    let stop_down = Arc::new(Notify::new());
    let finish_down = stop_down.clone();
    let responded = Arc::new(Notify::new());
    let response_started = responded.clone();
    let peer = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let (io, _) = listener.accept().await.unwrap();
            let (expected, seen, finish) = (expected.clone(), seen.clone(), finish.clone());
            let response_started = response_started.clone();
            let finish_down = finish_down.clone();
            connections.spawn(async move {
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(io),
                        service_fn(move |request: Request<Incoming>| {
                            let (expected, seen, finish) =
                                (expected.clone(), seen.clone(), finish.clone());
                            let response_started = response_started.clone();
                            let finish_down = finish_down.clone();
                            async move {
                                let (tx, rx) =
                                    tokio::sync::mpsc::channel::<io::Result<Frame<Bytes>>>(2);
                                let upload = request.method() == http::Method::POST;
                                if upload {
                                    tx.send(Ok(Frame::data(Bytes::from_static(b"ack"))))
                                        .await
                                        .unwrap();
                                    tokio::spawn(async move {
                                        assert_eq!(
                                            body_bytes(request.into_body(), expected.len()).await,
                                            expected
                                        );
                                        seen.notify_one();
                                        finish.notified().await;
                                        drop(tx);
                                    });
                                } else {
                                    tokio::spawn(async move {
                                        finish_down.notified().await;
                                        drop(tx);
                                    });
                                }
                                Ok::<_, io::Error>(Response::new(StreamBody::new(
                                    tokio_stream::StreamExt::map(
                                        tokio_stream::wrappers::ReceiverStream::new(rx),
                                        move |frame| {
                                            if upload {
                                                response_started.notify_one();
                                            }
                                            frame
                                        },
                                    ),
                                )))
                            }
                        }),
                    )
                    .await
                    .unwrap();
            });
        }
        while let Some(result) = connections.join_next().await {
            result.unwrap();
        }
    });
    let client = client(json!({"mode":"stream-up"}));
    let mut connection = timeout(DEADLINE, client.connect(&server, &Default::default()))
        .await
        .unwrap()
        .unwrap();
    timeout(DEADLINE, responded.notified())
        .await
        .expect("upload response did not start before request data");
    timeout(DEADLINE, connection.write_all(&payload))
        .await
        .unwrap()
        .unwrap();
    timeout(DEADLINE, uploaded.notified())
        .await
        .expect("early upload response interrupted the request body");
    stop.notify_waiters();
    let failed_write = timeout(DEADLINE, connection.write_all(&vec![0x7d; BUFFER_SIZE * 8]))
        .await
        .expect("upload writer remained open after response drain completed");
    assert!(
        failed_write.is_err(),
        "upload writer accepted data after response drain"
    );
    let mut byte = [0];
    assert!(
        timeout(Duration::from_millis(20), connection.read(&mut byte))
            .await
            .is_err(),
        "upload completion closed the held download stream"
    );
    stop_down.notify_waiters();
    drop(connection);
    timeout(DEADLINE, peer).await.unwrap().unwrap();
}

#[tokio::test]
async fn non_200_download_fails_without_poisoning_shared_client() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = local_server(listener.local_addr().unwrap().port());
    let peer = tokio::spawn(async move {
        let (io, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                hyper_util::rt::TokioIo::new(io),
                service_fn(|_: Request<Incoming>| async {
                    Ok::<_, io::Error>(
                        Response::builder()
                            .status(503)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                }),
            )
            .await
            .ok();
    });
    let client = client(json!({"mode":"stream-one", "xmux":{"hKeepAlivePeriod":-1}}));
    let mut connection = timeout(DEADLINE, client.connect(&server, &Default::default()))
        .await
        .unwrap()
        .unwrap();
    let selected = client.manager.lock().unwrap().clients[0].clone();
    let error = timeout(DEADLINE, connection.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(
        !selected.closed.load(Ordering::Acquire),
        "HTTP status poisoned the reusable transport client"
    );
    assert!(Arc::ptr_eq(&selected, &client.select()));
    drop(connection);
    peer.abort();
}

#[tokio::test]
async fn gzip_is_negotiated_and_decoded_only_when_header_is_automatic() {
    let payload = vec![0x5b; BUFFER_SIZE * 3];
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &payload).unwrap();
    let compressed = encoder.finish().unwrap();
    for explicit in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = local_server(listener.local_addr().unwrap().port());
        let response = compressed.clone();
        let peer = tokio::spawn(async move {
            let (io, _) = listener.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(io),
                    service_fn(move |request: Request<Incoming>| {
                        let response = response.clone();
                        async move {
                            assert_eq!(
                                request
                                    .headers()
                                    .get("accept-encoding")
                                    .and_then(|value| value.to_str().ok()),
                                Some("gzip")
                            );
                            assert_eq!(body_bytes(request.into_body(), 7).await, b"request");
                            Ok::<_, io::Error>(
                                Response::builder()
                                    .header("Content-Encoding", "gzip")
                                    .body(Full::new(Bytes::from(response)))
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let mut config = json!({"mode":"stream-one"});
        if explicit {
            config["headers"] = json!({"Accept-Encoding":"gzip"});
        }
        let client = client(config);
        let mut connection = timeout(DEADLINE, client.connect(&server, &Default::default()))
            .await
            .unwrap()
            .unwrap();
        connection.write_all(b"request").await.unwrap();
        let mut got = Vec::new();
        timeout(DEADLINE, connection.read_to_end(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            got,
            if explicit {
                compressed.clone()
            } else {
                payload.clone()
            }
        );
        drop(connection);
        timeout(DEADLINE, peer).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn h2_packet_failure_interrupts_upload_without_another_payload() {
    for reset in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = local_server(listener.local_addr().unwrap().port());
        let (received, wait_received) = oneshot::channel();
        let received = Arc::new(Mutex::new(Some(received)));
        let release = Arc::new(Notify::new());
        let respond = release.clone();
        let peer = tokio::spawn(async move {
            let (io, _) = listener.accept().await.unwrap();
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(
                    hyper_util::rt::TokioIo::new(io),
                    service_fn(move |request: Request<Incoming>| {
                        let (received, respond) = (received.clone(), respond.clone());
                        async move {
                            assert_eq!(body_bytes(request.into_body(), 6).await, b"packet");
                            received.lock().unwrap().take().unwrap().send(()).unwrap();
                            respond.notified().await;
                            if reset {
                                return Err(io::Error::other("reset upload stream"));
                            }
                            Ok(Response::builder()
                                .status(503)
                                .body(Full::new(Bytes::new()))
                                .unwrap())
                        }
                    }),
                )
                .await
                .ok();
        });
        let client = client(json!({"mode":"packet-up", "scMaxEachPostBytes":64,
            "xmux":{"hKeepAlivePeriod":-1}}));
        let selected = client.select();
        let dial = Dial {
            address: server.address,
            port: server.port,
            security: Security::None,
            socket: Default::default(),
            h2: true,
        };
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut pump = tokio::spawn(async move {
            client
                .packets(
                    reader,
                    64,
                    selected,
                    dial,
                    ("http", "localhost", "session"),
                    Arc::new(Mutex::new(Vec::new())),
                )
                .await
        });
        writer.write_all(b"packet").await.unwrap();
        timeout(DEADLINE, wait_received).await.unwrap().unwrap();
        assert!(
            timeout(Duration::from_millis(20), &mut pump).await.is_err(),
            "packet dispatch waited for neither more input nor its delayed response"
        );
        release.notify_one();
        let result = timeout(DEADLINE, &mut pump)
            .await
            .expect("failed response left packet upload waiting for another payload")
            .unwrap();
        assert!(result.is_err(), "failed response did not fail the upload");
        assert!(
            writer.write_all(b"later").await.is_err(),
            "upload writer stayed open after the failed response"
        );
        peer.abort();
    }
}

#[tokio::test(start_paused = true)]
async fn xmux_fills_reuses_and_retires_clients_with_running_and_expiry_limits() {
    let manager = client(json!({"xmux":{"maxConnections":2,"cMaxReuseTimes":3}}));
    let first = manager.select();
    let second = manager.select();
    assert!(!Arc::ptr_eq(&first, &second));
    let reused = manager.select();
    assert!(Arc::ptr_eq(&reused, &first) || Arc::ptr_eq(&reused, &second));
    assert_eq!(manager.manager.lock().unwrap().clients.len(), 2);
    assert_eq!(
        first.uses.load(Ordering::Acquire) + second.uses.load(Ordering::Acquire),
        3
    );

    let manager = client(json!({"xmux":{"cMaxReuseTimes":2}}));
    let first = manager.select();
    assert!(Arc::ptr_eq(&first, &manager.select()));
    assert!(!Arc::ptr_eq(&first, &manager.select()));
    assert_eq!(manager.manager.lock().unwrap().clients.len(), 1);

    let manager = client(json!({"xmux":{"maxConcurrency":1}}));
    let first = manager.select();
    first.running.fetch_add(1, Ordering::AcqRel);
    let running = Running(first.clone());
    let second = manager.select();
    second.running.fetch_add(1, Ordering::AcqRel);
    let _second_running = Running(second.clone());
    assert!(!Arc::ptr_eq(&first, &second));
    drop(running);
    assert!(Arc::ptr_eq(&first, &manager.select()));

    let manager = client(json!({"xmux":{"hMaxRequestTimes":1,"hMaxReusableSecs":5}}));
    let first = manager.select();
    assert!(Arc::ptr_eq(&first, &manager.select()));
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(Arc::ptr_eq(&first, &manager.select()));
    tokio::time::advance(Duration::from_nanos(1)).await;
    let replacement = manager.select();
    assert!(!Arc::ptr_eq(&first, &replacement));
    replacement.requests.fetch_sub(1, Ordering::AcqRel);
    assert!(!Arc::ptr_eq(&replacement, &manager.select()));
}

#[tokio::test]
async fn raw_pool_steals_shared_items_but_keeps_foreign_private_item() {
    let selected = client(json!({})).select();
    let owner = selected.clone();
    let (private, mut private_peer) = tokio::io::duplex(1);
    let (shared, mut shared_peer) = tokio::io::duplex(1);
    let (ready, wait_ready) = std::sync::mpsc::channel();
    let (reclaim, wait_reclaim) = std::sync::mpsc::channel();
    let (claimed, wait_claimed) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        owner.put_raw(Box::new(private));
        owner.put_raw(Box::new(shared));
        ready.send(()).unwrap();
        wait_reclaim.recv().unwrap();
        claimed
            .send(owner.take_raw().expect("owner lost its private item"))
            .unwrap();
    });
    wait_ready.recv_timeout(DEADLINE).unwrap();
    let mut stolen = selected
        .take_raw()
        .expect("foreign shared item was not stealable");
    shared_peer.write_all(b"s").await.unwrap();
    let mut marker = [0];
    stolen.read_exact(&mut marker).await.unwrap();
    assert_eq!(&marker, b"s");
    assert!(
        selected.take_raw().is_none(),
        "foreign private item was stolen"
    );
    reclaim.send(()).unwrap();
    let mut reclaimed = wait_claimed.recv_timeout(DEADLINE).unwrap();
    private_peer.write_all(b"p").await.unwrap();
    reclaimed.read_exact(&mut marker).await.unwrap();
    assert_eq!(&marker, b"p");
    worker.join().unwrap();
}

#[test]
fn raw_request_matches_go_post_header_order_and_empty_body_length() {
    for header_payload in [false, true] {
        let mut request = Request::builder()
            .method("POST")
            .uri("http://example.com:8080/x/session/0?z=1")
            .header("z-last", "z")
            .header("user-agent", "fixture/1")
            .header("a-first", "a")
            .header("transfer-encoding", "chunked")
            .header("content-length", "999")
            .header("trailer", "X-Later");
        let payload_header = if header_payload {
            request = request.header("x-data-0", "YWJj");
            "X-Data-0: YWJj\r\n"
        } else {
            request = request.header("cookie", "data_0=YWJj");
            "Cookie: data_0=YWJj\r\n"
        };
        let bytes = raw_request(request.body(()).unwrap(), Bytes::new()).unwrap();
        let expected = format!(
            "POST /x/session/0?z=1 HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: fixture/1\r\nContent-Length: 0\r\nA-First: a\r\n{payload_header}Z-Last: z\r\n\r\n"
        );
        assert_eq!(String::from_utf8(bytes).unwrap(), expected);
    }
}

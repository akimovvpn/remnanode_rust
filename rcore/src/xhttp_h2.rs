//! Pinned Go HTTP/2 connection pooling and request lifecycle for XHTTP.
//! Go-derived portions retain the BSD notice in LICENSE-Go.
use super::{Active, Dial, IDLE, ResponseBody, ResponseFuture, Upload};
use anyhow::Result;
use bytes::Bytes;
use http::{Request, Version};
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex as AsyncMutex, Notify},
    task::JoinHandle,
    time::Instant,
};

#[derive(Clone)]
pub(super) struct Pool {
    connections: Arc<AsyncMutex<Vec<Connection>>>,
}
struct Connection {
    sender: h2::client::SendRequest<Bytes>,
    state: Arc<State>,
}
struct State {
    usage: Mutex<Usage>,
    changed: Notify,
    closed: AtomicBool,
}
struct Usage {
    active: usize,
    idle_at: Instant,
    read_at: Instant,
}
struct Running(Arc<State>);
impl Drop for Running {
    fn drop(&mut self) {
        let mut usage = self.0.usage.lock().unwrap();
        usage.active -= 1;
        if usage.active == 0 {
            usage.idle_at = Instant::now();
        }
        self.0.changed.notify_one();
    }
}
type Attempt = (
    h2::client::ResponseFuture,
    h2::SendStream<Bytes>,
    Arc<Running>,
);

fn keepalive_period(seconds: i64) -> Option<Duration> {
    match seconds.wrapping_mul(1_000_000_000) {
        0 => Some(Duration::from_secs(45)),
        nanos if nanos > 0 => Some(Duration::from_nanos(nanos as u64)),
        _ => None,
    }
}

impl Pool {
    pub(super) fn new() -> Self {
        Self {
            connections: Arc::new(AsyncMutex::new(Vec::new())),
        }
    }

    async fn open(
        &self,
        dial: &Dial,
        request: Request<()>,
        end: bool,
        keep_alive: i64,
    ) -> Result<Attempt> {
        let mut connections = self.connections.lock().await;
        connections.retain(|c| !c.state.closed.load(Ordering::Acquire));
        let mut selected = None;
        for (i, connection) in connections.iter_mut().enumerate() {
            let ready =
                std::future::poll_fn(|cx| Poll::Ready(connection.sender.poll_ready(cx))).await;
            match ready {
                Poll::Ready(Err(_)) => {
                    connection.state.closed.store(true, Ordering::Release);
                }
                Poll::Ready(Ok(()))
                    if connection.state.usage.lock().unwrap().active
                        < connection.sender.current_max_send_streams() =>
                {
                    selected = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let i = match selected {
            Some(i) => i,
            None => {
                let io = dial.connect().await?;
                let now = Instant::now();
                let state = Arc::new(State {
                    usage: Mutex::new(Usage {
                        active: 0,
                        idle_at: now,
                        read_at: now,
                    }),
                    changed: Notify::new(),
                    closed: AtomicBool::new(false),
                });
                let (sender, mut connection) = h2::client::Builder::new()
                    .initial_window_size(4 << 20)
                    .initial_connection_window_size((1 << 30) + 65535)
                    .initial_max_send_streams(100)
                    .max_frame_size(1 << 20)
                    .max_header_list_size(10 << 20)
                    .enable_push(false)
                    .handshake(ObservedIo {
                        io,
                        state: state.clone(),
                    })
                    .await?;
                let mut ping = connection.ping_pong().unwrap();
                let watched = state.clone();
                tokio::spawn(async move {
                    let health = async {
                        loop {
                            let (active, idle_at, read_at) = {
                                let usage = watched.usage.lock().unwrap();
                                (usage.active, usage.idle_at, usage.read_at)
                            };
                            let period = keepalive_period(keep_alive);
                            tokio::select! {
                                _ = tokio::time::sleep_until(idle_at + IDLE), if active == 0 => break,
                                _ = watched.changed.notified() => {},
                                _ = tokio::time::sleep_until(read_at + period.unwrap_or_default()), if period.is_some() => {
                                    if Instant::now() < watched.usage.lock().unwrap().read_at + period.unwrap() { continue; }
                                    if !matches!(tokio::time::timeout(Duration::from_secs(15), ping.ping(h2::Ping::opaque())).await, Ok(Ok(_))) { break; }
                                }
                            }
                        }
                    };
                    tokio::select! { _ = connection => {}, _ = health => {} }
                    watched.closed.store(true, Ordering::Release);
                });
                connections.push(Connection { sender, state });
                connections.len() - 1
            }
        };
        let connection = &mut connections[i];
        let (response, stream) = connection.sender.send_request(request, end)?;
        connection.state.usage.lock().unwrap().active += 1;
        connection.state.changed.notify_one();
        Ok((
            response,
            stream,
            Arc::new(Running(connection.state.clone())),
        ))
    }

    pub(super) async fn start(
        &self,
        dial: &Dial,
        request: Request<Upload>,
        keep_alive: i64,
    ) -> Result<(ResponseFuture, Option<Active>)> {
        let (parts, body) = request.into_parts();
        let mut head = Request::from_parts(parts, ());
        *head.version_mut() = Version::HTTP_2;
        let replay = match &body {
            Upload::Packet { data, .. } => Some(data.clone().unwrap_or_default()),
            _ => None,
        };
        if let Some(bytes) = &replay
            && (!bytes.is_empty()
                || matches!(
                    *head.method(),
                    http::Method::POST | http::Method::PUT | http::Method::PATCH
                ))
        {
            head.headers_mut()
                .insert("content-length", bytes.len().to_string().parse()?);
        }
        let end = replay.as_ref().is_some_and(|bytes| bytes.is_empty());
        let mut attempt = self.open(dial, head.clone(), end, keep_alive).await?;
        let pool = self.clone();
        let dial = dial.clone();
        let body = Arc::new(AsyncMutex::new(body));
        Ok((
            Box::pin(async move {
                for retry in 0.. {
                    let (mut response, stream, running) = attempt;
                    let stream_id = stream.stream_id().as_u32();
                    let mut upload = Task {
                        task: Some(tokio::spawn(pump(
                            stream,
                            body.clone(),
                            running.clone(),
                            end,
                        ))),
                        detach: false,
                    };
                    let result: Result<_> = tokio::select! {
                        biased;
                        response = &mut response => response.map_err(Into::into),
                        result = upload.task.as_mut().unwrap() => {
                            upload.task.take();
                            match result {
                                Ok(Ok(())) => response.await.map_err(Into::into),
                                Ok(Err(error)) => Err(error),
                                Err(error) => Err(error.into()),
                            }
                        }
                    };
                    match result {
                        Ok(response) => {
                            return Ok(response.map(|recv| {
                                ResponseBody::H2(Body {
                                    recv,
                                    upload,
                                    _running: running,
                                    trailers: false,
                                })
                            }));
                        }
                        Err(error) => {
                            upload.stop().await;
                            let retryable =
                                error.downcast_ref::<h2::Error>().is_some_and(|error| {
                                    (error.is_reset()
                                        && error.reason() == Some(h2::Reason::REFUSED_STREAM))
                                        || (error.is_remote()
                                            && error.is_go_away()
                                            && (stream_id != 1
                                                || error.reason() == Some(h2::Reason::NO_ERROR)))
                                });
                            if error
                                .downcast_ref::<h2::Error>()
                                .is_some_and(h2::Error::is_go_away)
                            {
                                running.0.closed.store(true, Ordering::Release);
                            }
                            drop(running);
                            if !retryable || replay.is_none() || retry > 6 {
                                return Err(error);
                            }
                            *body.lock().await =
                                Upload::packet(replay.as_ref().unwrap().clone(), None);
                            if retry > 0 {
                                let seconds = (1u64 << (retry - 1)) as f64;
                                let jitter =
                                    crate::xhttp::rand_between((0, 1_000_000)) as f64 / 1_000_000.0;
                                tokio::time::sleep(Duration::from_secs_f64(
                                    seconds * (1.0 + 0.1 * jitter),
                                ))
                                .await;
                            }
                            attempt = pool.open(&dial, head.clone(), end, keep_alive).await?;
                        }
                    }
                }
                unreachable!()
            }),
            None,
        ))
    }
}

struct Task {
    task: Option<JoinHandle<Result<()>>>,
    detach: bool,
}
impl Task {
    async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}
impl Drop for Task {
    fn drop(&mut self) {
        if !self.detach
            && let Some(task) = &self.task
        {
            task.abort();
        }
    }
}

async fn pump(
    mut stream: h2::SendStream<Bytes>,
    body: Arc<AsyncMutex<Upload>>,
    _running: Arc<Running>,
    end: bool,
) -> Result<()> {
    let written = match &mut *body.lock().await {
        Upload::Packet { sent, .. } => sent.take(),
        _ => None,
    };
    loop {
        let frame = body.lock().await.frame().await.transpose()?;
        let Some(frame) = frame else {
            if !end {
                stream.send_data(Bytes::new(), true)?;
            }
            if let Some(written) = written {
                let _ = written.send(());
            }
            return Ok(());
        };
        let Ok(mut data) = frame.into_data() else {
            continue;
        };
        while !data.is_empty() {
            stream.reserve_capacity(data.len());
            let capacity = std::future::poll_fn(|cx| {
                // Upload-only responses can stop the request while its flow-control window is closed.
                let mut body = body.try_lock().unwrap();
                if let Upload::Stream { reader, stop } = &mut *body
                    && let Some(stopped) = stop
                {
                    match Pin::new(stopped).poll(cx) {
                        Poll::Ready(Ok(())) => {
                            reader.take();
                            return Poll::Ready(Ok(0));
                        }
                        Poll::Ready(Err(_)) => {
                            *stop = None;
                        }
                        Poll::Pending => {}
                    }
                }
                match ready!(stream.poll_capacity(cx)) {
                    Some(result) => Poll::Ready(result.map_err(anyhow::Error::from)),
                    None => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "HTTP/2 upload closed",
                    )
                    .into())),
                }
            })
            .await?;
            if capacity == 0 {
                stream.send_data(Bytes::new(), true)?;
                return Ok(());
            }
            let n = capacity.min(data.len());
            stream.send_data(data.split_to(n), false)?;
        }
    }
}

pub(super) struct Body {
    recv: h2::RecvStream,
    upload: Task,
    _running: Arc<Running>,
    trailers: bool,
}
impl HttpBody for Body {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if !self.trailers {
            match ready!(self.recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    if let Err(error) = self.recv.flow_control().release_capacity(data.len()) {
                        return Poll::Ready(Some(Err(io::Error::other(error))));
                    }
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
                Some(Err(error)) => return Poll::Ready(Some(Err(io::Error::other(error)))),
                None => self.trailers = true,
            }
        }
        match ready!(self.recv.poll_trailers(cx)) {
            Ok(Some(trailers)) => Poll::Ready(Some(Ok(Frame::trailers(trailers)))),
            Ok(None) => Poll::Ready(None),
            Err(error) => Poll::Ready(Some(Err(io::Error::other(error)))),
        }
    }
    fn is_end_stream(&self) -> bool {
        self.recv.is_end_stream()
    }
}
impl Drop for Body {
    fn drop(&mut self) {
        if self.recv.is_end_stream() {
            self.upload.detach = true;
        }
    }
}

struct ObservedIo {
    io: crate::transport::BoxIo,
    state: Arc<State>,
}
impl AsyncRead for ObservedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        ready!(Pin::new(&mut self.io).poll_read(cx, out))?;
        if out.filled().len() > before {
            self.state.usage.lock().unwrap().read_at = Instant::now();
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for ObservedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{vless::Address, vless_out::Security};
    use h2::{RecvStream, server::SendResponse};
    use http::{Response, StatusCode};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::{
        net::TcpListener,
        task::JoinHandle,
        time::{Duration, timeout},
    };

    #[test]
    fn keepalive_seconds_use_go_duration_arithmetic() {
        assert_eq!(keepalive_period(0), Some(Duration::from_secs(45)));
        assert_eq!(keepalive_period(3), Some(Duration::from_secs(3)));
        assert_eq!(keepalive_period(-1), None);
        assert_eq!(keepalive_period(i64::MAX), None);
        assert_eq!(keepalive_period(i64::MIN), Some(Duration::from_secs(45)));
    }

    async fn peer<F, Fut>(max: u32, service: F) -> (Dial, JoinHandle<()>)
    where
        F: Fn(Request<RecvStream>, SendResponse<Bytes>, usize) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dial = Dial {
            address: Address::Ip("127.0.0.1".parse().unwrap()),
            port: listener.local_addr().unwrap().port(),
            security: Security::None,
            socket: Default::default(),
            h2: true,
        };
        let service = Arc::new(service);
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            for number in 0usize..=usize::MAX {
                let (io, _) = listener.accept().await.unwrap();
                let service = service.clone();
                connections.spawn(async move {
                    let mut connection = h2::server::Builder::new()
                        .max_concurrent_streams(max)
                        .handshake::<_, Bytes>(io)
                        .await
                        .unwrap();
                    let mut requests = tokio::task::JoinSet::new();
                    while let Some(Ok((request, response))) = connection.accept().await {
                        requests.spawn(service(request, response, number));
                    }
                });
            }
        });
        (dial, server)
    }

    fn request(method: &str, bytes: &'static [u8]) -> Request<Upload> {
        Request::builder()
            .method(method)
            .uri("https://localhost/x")
            .body(Upload::packet(Bytes::from_static(bytes), None))
            .unwrap()
    }

    async fn payload(mut body: RecvStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        while let Some(data) = body.data().await {
            let data = data.unwrap();
            body.flow_control().release_capacity(data.len()).unwrap();
            bytes.extend_from_slice(&data);
        }
        bytes
    }

    #[tokio::test]
    async fn opens_another_connection_when_download_fills_peer_stream_capacity() {
        let (dial, server) = peer(1, |request, mut response, number| async move {
            if request.method() == http::Method::GET {
                let _body = response
                    .send_response(
                        Response::builder()
                            .header("peer", number.to_string())
                            .body(())
                            .unwrap(),
                        false,
                    )
                    .unwrap();
                std::future::pending::<()>().await;
            } else {
                assert_eq!(payload(request.into_body()).await, b"packet");
                response
                    .send_response(
                        Response::builder()
                            .header("peer", number.to_string())
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
            }
        })
        .await;
        let pool = Pool::new();
        let (download, _) = pool.start(&dial, request("GET", b""), -1).await.unwrap();
        let download = timeout(Duration::from_secs(2), download)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(download.headers()["peer"], "0");
        let (upload, _) = pool
            .start(&dial, request("POST", b"packet"), -1)
            .await
            .unwrap();
        let upload = timeout(Duration::from_secs(2), upload)
            .await
            .expect("upload waited for the held download stream")
            .unwrap();
        assert_eq!(upload.headers()["peer"], "1");
        drop(download);
        server.abort();
    }

    #[tokio::test]
    async fn accepts_response_headers_larger_than_hyper_default() {
        let (dial, server) = peer(100, |_, mut response, _| async move {
            response
                .send_response(
                    Response::builder()
                        .header("large", "x".repeat(20_000))
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
        })
        .await;
        let (response, _) = Pool::new()
            .start(&dial, request("GET", b""), -1)
            .await
            .unwrap();
        let response = timeout(Duration::from_secs(2), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["large"].as_bytes().len(), 20_000);
        server.abort();
    }

    #[tokio::test]
    async fn wrote_request_waits_for_upload_flow_control() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dial = Dial {
            address: Address::Ip("127.0.0.1".parse().unwrap()),
            port: listener.local_addr().unwrap().port(),
            security: Security::None,
            socket: Default::default(),
            h2: true,
        };
        let (opened, received) = tokio::sync::oneshot::channel();
        let release = Arc::new(Notify::new());
        let window = release.clone();
        let peer = tokio::spawn(async move {
            let (io, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::Builder::new()
                .initial_window_size(0)
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let (probe, mut response) = connection.accept().await.unwrap().unwrap();
            assert_eq!(probe.method(), http::Method::GET);
            response.send_response(Response::new(()), true).unwrap();
            let (request, mut response) = connection.accept().await.unwrap().unwrap();
            opened.send(()).unwrap();
            tokio::select! { _ = window.notified() => {}, _ = connection.accept() => panic!("unexpected second request") }
            connection.set_initial_window_size(65535).unwrap();
            let reader = tokio::spawn(async move {
                assert_eq!(payload(request.into_body()).await, b"packet");
                response.send_response(Response::new(()), true).unwrap();
            });
            while let Some(request) = connection.accept().await {
                assert!(request.is_ok());
            }
            reader.await.unwrap();
        });
        let pool = Pool::new();
        let (probe, _) = pool.start(&dial, request("GET", b""), -1).await.unwrap();
        assert_eq!(probe.await.unwrap().status(), StatusCode::OK);
        let (sent, mut written) = tokio::sync::oneshot::channel();
        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/x")
            .body(Upload::packet(Bytes::from_static(b"packet"), Some(sent)))
            .unwrap();
        let (response, _) = pool.start(&dial, request, -1).await.unwrap();
        let response = tokio::spawn(response);
        received.await.unwrap();
        assert!(
            timeout(Duration::from_millis(20), &mut written)
                .await
                .is_err(),
            "WroteRequest fired before the peer allowed upload bytes"
        );
        release.notify_one();
        timeout(Duration::from_secs(2), written)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.await.unwrap().unwrap().status(), StatusCode::OK);
        peer.abort();
    }

    #[tokio::test]
    async fn retries_refused_packet_with_the_original_payload() {
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let (dial, server) = peer(100, move |request, mut response, _| {
            let seen = seen.clone();
            async move {
                assert_eq!(payload(request.into_body()).await, b"packet");
                if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                    response.send_reset(h2::Reason::REFUSED_STREAM);
                } else {
                    response.send_response(Response::new(()), true).unwrap();
                }
            }
        })
        .await;
        let (response, _) = Pool::new()
            .start(&dial, request("POST", b"packet"), -1)
            .await
            .unwrap();
        let response = timeout(Duration::from_secs(2), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(count.load(Ordering::SeqCst), 2);
        server.abort();
    }

    async fn check_first_stream_goaway(reason: h2::Reason) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dial = Dial {
            address: Address::Ip("127.0.0.1".parse().unwrap()),
            port: listener.local_addr().unwrap().port(),
            security: Security::None,
            socket: Default::default(),
            h2: true,
        };
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let peer = tokio::spawn(async move {
            loop {
                let (mut io, _) = listener.accept().await.unwrap();
                let number = seen.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    if number == 0 {
                        let mut preface = [0; 24];
                        io.read_exact(&mut preface).await.unwrap();
                        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
                        io.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
                        loop {
                            let mut header = [0; 9];
                            io.read_exact(&mut header).await.unwrap();
                            let length =
                                u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
                            io.read_exact(&mut vec![0; length]).await.unwrap();
                            if header[3] == 1 {
                                break;
                            }
                        }
                        let mut frame = vec![0, 0, 8, 7, 0, 0, 0, 0, 0];
                        frame.extend_from_slice(&0u32.to_be_bytes());
                        frame.extend_from_slice(&u32::from(reason).to_be_bytes());
                        io.write_all(&frame).await.unwrap();
                        let mut bytes = [0; 1024];
                        while io.read(&mut bytes).await.is_ok_and(|n| n > 0) {}
                    } else {
                        let mut connection = h2::server::handshake(io).await.unwrap();
                        let (request, mut response) = connection.accept().await.unwrap().unwrap();
                        tokio::spawn(async move {
                            assert_eq!(payload(request.into_body()).await, b"packet");
                            response.send_response(Response::new(()), true).unwrap();
                        });
                        while connection.accept().await.is_some() {}
                    }
                });
            }
        });
        let (response, _) = Pool::new()
            .start(&dial, request("POST", b"packet"), -1)
            .await
            .unwrap();
        let response = timeout(Duration::from_millis(200), response)
            .await
            .expect("first-stream GOAWAY entered an unexpected retry backoff");
        if reason == h2::Reason::NO_ERROR {
            assert_eq!(response.unwrap().status(), StatusCode::OK);
            assert_eq!(count.load(Ordering::SeqCst), 2);
        } else {
            assert!(
                response.is_err(),
                "fatal first-stream GOAWAY was retried successfully"
            );
            assert_eq!(
                count.load(Ordering::SeqCst),
                1,
                "fatal first-stream GOAWAY opened another connection"
            );
        }
        peer.abort();
    }

    #[tokio::test]
    async fn fatal_first_stream_goaway_is_not_retried() {
        check_first_stream_goaway(h2::Reason::PROTOCOL_ERROR).await;
    }

    #[tokio::test]
    async fn graceful_first_stream_goaway_retries_packet() {
        check_first_stream_goaway(h2::Reason::NO_ERROR).await;
    }
}

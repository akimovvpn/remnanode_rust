//! Separate XHTTP upload/download endpoints against one real Go Xray session store.
//! Run with XRAY_BINARY=/path/to/xray cargo test -p rcore --test download_interop.
mod common;

use anyhow::{Context, Result, ensure};
use base64::Engine;
use http::{HeaderMap, Method, Request, Response, Uri, Version};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    process::{Child, Command},
};

const ID: &str = "6b1f2b9e-2f7e-4f43-9d2a-1c1d2e3f4a5b";
const SNI: &str = "target.test";

#[derive(Clone, Copy, PartialEq)]
enum Security {
    Plain,
    Tls,
    Reality,
}

fn reality_keys() -> (String, String) {
    let private: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(5));
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    (b64.encode(private), b64.encode(public.as_bytes()))
}

fn security_settings(stream: &mut Value, security: Security) {
    match security {
        Security::Plain => {}
        Security::Tls => {
            stream["security"] = json!("tls");
            stream["tlsSettings"] = json!({"serverName": SNI, "alpn": ["h2"]});
        }
        Security::Reality => {
            stream["security"] = json!("reality");
            stream["realitySettings"] = json!({"serverName": SNI, "publicKey": reality_keys().1,
                "shortId": "0123abcd", "fingerprint": "chrome"});
        }
    }
}

fn reserve_port(reserved: &mut HashMap<u16, std::net::TcpListener>) -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    reserved.insert(port, listener);
    Ok(port)
}

async fn wait_port(port: u16, child: &mut Child, log: &Path) -> Result<()> {
    for _ in 0..100 {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("process for port {port} exited: {status}");
        }
        // A concurrent fork can briefly inherit a reservation: require this child's startup too.
        if std::fs::read_to_string(log)?.contains("[Warning] core: Xray ")
            && TcpStream::connect(("127.0.0.1", port)).await.is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("port {port} never opened")
}

fn spawn_logged(command: &mut Command, dir: &Path, name: &str) -> Result<Child> {
    let log = std::fs::File::create(dir.join(format!("{name}.log")))?;
    command.stderr(Stdio::from(log.try_clone()?));
    command.stdout(Stdio::from(log));
    Ok(command.kill_on_drop(true).spawn()?)
}

async fn openssl(args: &[&str], dir: &Path) -> Result<()> {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .await?;
    ensure!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// A CA and a leaf certificate for `SNI` (webpki needs a CA:FALSE leaf under a real anchor).
async fn certificates(dir: &Path) -> Result<()> {
    std::fs::write(
        dir.join("leaf.ext"),
        format!(
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{SNI}\n"
        ),
    )?;
    openssl(
        &[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            "ca.key",
        ],
        dir,
    )
    .await?;
    openssl(
        &[
            "req",
            "-x509",
            "-new",
            "-key",
            "ca.key",
            "-days",
            "2",
            "-subj",
            "/CN=rcore test CA",
            "-out",
            "ca.pem",
        ],
        dir,
    )
    .await?;
    openssl(
        &[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            "leaf.key",
        ],
        dir,
    )
    .await?;
    openssl(
        &[
            "req",
            "-new",
            "-key",
            "leaf.key",
            "-subj",
            &format!("/CN={SNI}"),
            "-out",
            "leaf.csr",
        ],
        dir,
    )
    .await?;
    openssl(
        &[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            "leaf.ext",
            "-out",
            "leaf.pem",
        ],
        dir,
    )
    .await?;
    Ok(())
}

#[derive(Clone, Debug)]
struct Seen {
    download: bool,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    version: Version,
}

impl Seen {
    fn query(&self) -> HashMap<String, String> {
        url::form_urlencoded::parse(self.uri.query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect()
    }

    fn session(&self) -> Result<String> {
        if self.download {
            self.query()
                .remove("download-session")
                .context("download session")
        } else {
            Ok(self
                .headers
                .get("x-upload-session")
                .context("upload session")?
                .to_str()?
                .to_owned())
        }
    }
}

/// Both frontends forward to this SAME listener: Go's XHTTP session map is per inbound.
async fn forward(
    mut request: Request<Incoming>,
    download: bool,
    backend: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
) -> Result<Response<Incoming>> {
    let snapshot = Seen {
        download,
        method: request.method().clone(),
        uri: request.uri().clone(),
        headers: request.headers().clone(),
        version: request.version(),
    };
    seen.lock().unwrap().push(snapshot.clone());
    let session = snapshot.session()?;
    let seq = snapshot.query().remove("upload-seq");
    let path = match seq {
        Some(seq) => format!("/backend/{session}/{seq}"),
        None => format!("/backend/{session}"),
    };
    *request.uri_mut() = path.parse()?;
    *request.version_mut() = Version::HTTP_11;
    let headers = request.headers_mut();
    headers.remove("connection");
    headers.remove("transfer-encoding");
    headers.insert("host", "backend.test".parse()?);
    // The frontends normalize leg-specific metadata and padding to the shared backend.
    headers.insert(
        "referer",
        "http://backend.test/backend/?x_padding=XXXXXXXX".parse()?,
    );
    let stream = TcpStream::connect(("127.0.0.1", backend)).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut response = sender.send_request(request).await?;
    response.headers_mut().remove("connection");
    response.headers_mut().remove("transfer-encoding");
    Ok(response)
}

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

async fn frontend(
    backend: u16,
    download: bool,
    tls: bool,
    dir: &Path,
    seen: Arc<Mutex<Vec<Seen>>>,
) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let acceptor = if tls {
        let open = |name| std::fs::File::open(dir.join(name)).map(std::io::BufReader::new);
        let certs = rustls_pemfile::certs(&mut open("leaf.pem")?).collect::<Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut open("leaf.key")?)?.context("leaf key")?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
    } else {
        None
    };
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let io: Box<dyn Io> = if let Some(acceptor) = acceptor {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    Box::new(tls)
                } else {
                    Box::new(stream)
                };
                let service = hyper::service::service_fn(move |request| {
                    forward(request, download, backend, seen.clone())
                });
                if let Err(error) =
                    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(io), service)
                        .await
                {
                    eprintln!(
                        "{} frontend: {error:#}",
                        if download { "download" } else { "upload" }
                    );
                }
            });
        }
    });
    Ok(port)
}

fn stream_settings(
    mode: &str,
    down: u16,
    upload_security: Security,
    download_security: Security,
) -> Value {
    let mut download = json!({"address": "127.0.0.1", "port": down, "network": "xhttp",
        "xhttpSettings": {"host": "download.test", "path": "/download/?download=own", "extra": {
            "headers": {"X-Download-Only": "down"}, "xPaddingObfsMode": true,
            "xPaddingBytes": 17, "xPaddingPlacement": "query", "xPaddingKey": "download-pad",
            "sessionIDPlacement": "query", "sessionIDKey": "download-session",
            "sessionIDTable": "number", "sessionIDLength": 10,
            "seqPlacement": "header", "seqKey": "X-Download-Seq"}}});
    security_settings(&mut download, download_security);
    let mut upload = json!({"network": "xhttp", "xhttpSettings": {
        "host": "upload.test", "path": "/upload/?upload=own", "mode": mode, "extra": {
            "headers": {"X-Upload-Only": "up"}, "xPaddingObfsMode": true,
            "xPaddingBytes": 13, "xPaddingPlacement": "header", "xPaddingHeader": "X-Upload-Pad",
            "sessionIDPlacement": "header", "sessionIDKey": "X-Upload-Session",
            "sessionIDTable": "hex", "sessionIDLength": 12,
            "seqPlacement": "query", "seqKey": "upload-seq",
            "scMaxEachPostBytes": 32768, "scMinPostsIntervalMs": 1, "downloadSettings": download}}});
    security_settings(&mut upload, upload_security);
    upload
}

async fn setup(
    dir: &Path,
    xray: &str,
    mode: &str,
    upload_security: Security,
    download_security: Security,
    seen: Arc<Mutex<Vec<Seen>>>,
) -> Result<(Vec<Child>, u16)> {
    certificates(dir).await?;
    let mut reserved = HashMap::new();
    let backend = reserve_port(&mut reserved)?;
    let mut up = frontend(
        backend,
        false,
        upload_security == Security::Tls,
        dir,
        seen.clone(),
    )
    .await?;
    let mut down = frontend(backend, true, download_security == Security::Tls, dir, seen).await?;
    let (rcore_port, socks_port) = (reserve_port(&mut reserved)?, reserve_port(&mut reserved)?);
    // Disable Go's stream-up response keepalives: HTTP/1 response flushing drains the
    // request body and would block the reverse proxy's streaming upload.
    let mut server = json!({"log": {"loglevel": "debug"},
        "inbounds": [{"listen": "127.0.0.1", "port": backend, "protocol": "vless",
            "settings": {"clients": [{"id": ID}], "decryption": "none"},
            "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/backend/", "xPaddingBytes": 8, "scStreamUpServerSecs": -1}}}],
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]});
    if upload_security == Security::Reality || download_security == Security::Reality {
        let target = frontend(backend, false, true, dir, Arc::new(Mutex::new(Vec::new()))).await?;
        for (security, endpoint) in [(upload_security, &mut up), (download_security, &mut down)] {
            if security == Security::Reality {
                let port = reserve_port(&mut reserved)?;
                server["inbounds"].as_array_mut().unwrap().push(json!({
                    "listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door",
                    "settings": {"address": "127.0.0.1", "port": *endpoint, "network": "tcp"},
                    "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                        "target": format!("127.0.0.1:{target}"), "serverNames": [SNI],
                        "privateKey": reality_keys().0, "shortIds": ["0123abcd"]}}
                }));
                *endpoint = port;
            }
        }
    }
    let rcore = json!({"log": {"loglevel": "debug"},
        "inbounds": [{"listen": "127.0.0.1", "port": rcore_port, "protocol": "vless",
            "settings": {"clients": [{"id": ID}], "decryption": "none"}, "streamSettings": {"network": "raw"}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": up,
            "users": [{"id": ID, "encryption": "none"}]}]}, "streamSettings": stream_settings(mode, down, upload_security, download_security)}]});
    let client = json!({"log": {"loglevel": "debug"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": true, "ip": "127.0.0.1"}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": rcore_port,
            "users": [{"id": ID, "encryption": "none"}]}]}, "streamSettings": {"network": "raw"}}]});
    let mut children = Vec::new();
    for (name, config, port) in [
        ("server", server, backend),
        ("rcore", rcore, rcore_port),
        ("client", client, socks_port),
    ] {
        let file = format!("{name}.json");
        std::fs::write(dir.join(&file), config.to_string())?;
        let validation = Command::new(xray)
            .args(["run", "-test", "-config", &file])
            .current_dir(dir)
            .output()
            .await?;
        ensure!(
            validation.status.success(),
            "Go rejected {name} fixture: {} {}",
            String::from_utf8_lossy(&validation.stdout),
            String::from_utf8_lossy(&validation.stderr)
        );
        let executable = if name == "rcore" {
            env!("CARGO_BIN_EXE_rcore")
        } else {
            xray
        };
        let mut command = Command::new(executable);
        command
            .args(["run", "-config", &file])
            .env("SSL_CERT_FILE", dir.join("ca.pem"))
            .current_dir(dir);
        // Go's raw dokodemo REALITY tunnel otherwise splices plaintext past TLS on Linux.
        if name == "server"
            && (upload_security == Security::Reality || download_security == Security::Reality)
        {
            command.env("xray.buf.splice", "disable");
        }
        // Keep ports out of the ephemeral pool until their owning process starts.
        for inbound in config["inbounds"].as_array().unwrap() {
            reserved.remove(&(inbound["port"].as_u64().unwrap() as u16));
        }
        children.push(spawn_logged(&mut command, dir, name)?);
        wait_port(
            port,
            children.last_mut().unwrap(),
            &dir.join(format!("{name}.log")),
        )
        .await?;
    }
    Ok((children, socks_port))
}

fn assert_requests(
    seen: &[Seen],
    mode: &str,
    upload_security: Security,
    download_security: Security,
) -> Result<()> {
    let mut upload_sessions = HashSet::new();
    let mut download_sessions = HashSet::new();
    for request in seen {
        let download = request.download;
        ensure!(
            request.method == if download { Method::GET } else { Method::POST },
            "method sent to wrong endpoint: {request:?}"
        );
        ensure!(
            request.version
                == if if download {
                    download_security
                } else {
                    upload_security
                } != Security::Plain
                {
                    Version::HTTP_2
                } else {
                    Version::HTTP_11
                },
            "HTTP version: {request:?}"
        );
        let host = request
            .uri
            .authority()
            .map(|a| a.as_str())
            .or_else(|| request.headers.get("host").and_then(|v| v.to_str().ok()));
        ensure!(
            host == Some(if download {
                "download.test"
            } else {
                "upload.test"
            }),
            "host: {request:?}"
        );
        ensure!(
            request.uri.path() == if download { "/download/" } else { "/upload/" },
            "path: {request:?}"
        );
        let query = request.query();
        ensure!(
            query
                .get(if download { "download" } else { "upload" })
                .map(String::as_str)
                == Some("own"),
            "base query: {request:?}"
        );
        ensure!(
            !query.contains_key(if download { "upload" } else { "download" }),
            "other leg query leaked: {request:?}"
        );
        ensure!(
            request
                .headers
                .get(if download {
                    "x-download-only"
                } else {
                    "x-upload-only"
                })
                .and_then(|v| v.to_str().ok())
                == Some(if download { "down" } else { "up" }),
            "headers: {request:?}"
        );
        ensure!(
            !request.headers.contains_key(if download {
                "x-upload-only"
            } else {
                "x-download-only"
            }),
            "other leg headers leaked: {request:?}"
        );
        ensure!(
            !request.headers.contains_key("x-download-seq"),
            "download seq should be absent: {request:?}"
        );
        let session = request.session()?;
        ensure!(
            session.len() == 12
                && session
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "session must be generated from upload settings: {session}"
        );
        if download {
            ensure!(
                query
                    .get("download-pad")
                    .is_some_and(|p| p == &"X".repeat(17)),
                "download padding: {request:?}"
            );
            ensure!(
                !query.contains_key("upload-seq")
                    && !request.headers.contains_key("x-upload-session")
                    && !request.headers.contains_key("x-upload-pad"),
                "upload metadata leaked: {request:?}"
            );
            download_sessions.insert(session);
        } else {
            ensure!(
                request
                    .headers
                    .get("x-upload-pad")
                    .and_then(|v| v.to_str().ok())
                    == Some(&"X".repeat(13)),
                "upload padding: {request:?}"
            );
            ensure!(
                !query.contains_key("download-session") && !query.contains_key("download-pad"),
                "download metadata leaked: {request:?}"
            );
            ensure!(
                query.contains_key("upload-seq") == (mode == "packet-up"),
                "upload sequence metadata: {request:?}"
            );
            if let Some(seq) = query.get("upload-seq") {
                let _: u64 = seq.parse().context("upload sequence")?;
            }
            upload_sessions.insert(session);
        }
    }
    ensure!(
        !upload_sessions.is_empty() && upload_sessions == download_sessions,
        "same session must appear on both endpoints: upload={upload_sessions:?} download={download_sessions:?}"
    );
    Ok(())
}

async fn run(mode: &str, upload_security: Security, download_security: Security) {
    let Ok(xray) = std::env::var("XRAY_BINARY") else {
        eprintln!("XRAY_BINARY not set: skipped");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        let (_children, socks) = setup(
            dir.path(),
            &xray,
            mode,
            upload_security,
            download_security,
            seen.clone(),
        )
        .await
        .context("fixture")?;
        common::tcp_checks(socks).await.context("TCP")?;
        common::xudp_checks(socks).await.context("XUDP")?;
        assert_requests(
            &seen.lock().unwrap(),
            if mode == "auto" && upload_security == Security::Reality {
                "stream-up"
            } else {
                mode
            },
            upload_security,
            download_security,
        )
    })
    .await;
    if !matches!(&result, Ok(Ok(()))) {
        for name in ["rcore", "server", "client"] {
            if let Ok(log) = std::fs::read_to_string(dir.path().join(format!("{name}.log"))) {
                eprintln!("--- {name} ---");
                for line in log
                    .lines()
                    .rev()
                    .take(35)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                {
                    eprintln!("{line}");
                }
            }
        }
        let requests = seen.lock().unwrap();
        eprintln!(
            "frontend requests: {} total, latest: {:?}",
            requests.len(),
            &requests[requests.len().saturating_sub(8)..]
        );
    }
    result
        .expect("download interop exceeded 90 seconds")
        .expect("download interop failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn packet_up_separate_plaintext_download() {
    run("packet-up", Security::Plain, Security::Plain).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_up_tls_upload_plaintext_download() {
    run("stream-up", Security::Tls, Security::Plain).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn packet_up_plaintext_upload_tls_download() {
    run("packet-up", Security::Plain, Security::Tls).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_reality_upload_plaintext_download_uses_stream_up() {
    run("auto", Security::Reality, Security::Plain).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn packet_up_plaintext_upload_reality_download() {
    run("packet-up", Security::Plain, Security::Reality).await;
}

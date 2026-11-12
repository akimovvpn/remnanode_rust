use anyhow::{Context, Result, ensure};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use remnanode_rust::{
    api::{AppState, internal_router, router},
    auth::{Auth, derive_sni},
    config::Config,
    core::Core,
};
use std::{future::IntoFuture, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore, time::timeout};
use tokio_rustls::LazyConfigAcceptor;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let config = Config::from_env()?;
    let expected_sni = Arc::new(derive_sni(
        &config.payload.ca_cert_pem,
        &config.payload.jwt_public_key,
    ));
    let mut tls = config.payload.tls_config()?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    tracing::info!(binary=%config.xray_binary.display(),endpoint=%config.endpoint,"Core configured; waiting for panel start request");
    let core = Core::new(config.xray_binary, config.state_dir, config.endpoint);
    let internal = core.bind_webhook()?;
    let state = AppState::new(core, Auth::new(&config.payload.jwt_public_key)?);
    let app = router(state.clone());
    tokio::spawn(axum::serve(internal, internal_router(state.clone())).into_future());
    let listener = TcpListener::bind(("0.0.0.0", config.port))
        .await
        .context("Cannot bind NODE_PORT")?;
    let capacity = Arc::new(Semaphore::new(256));
    let mut connections = tokio::task::JoinSet::new();
    tracing::info!(
        port = config.port,
        upstream = remnanode_rust::upstream_version(),
        "Remnanode Rust listening with mutual TLS"
    );
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                let tls = tls.clone();
                let expected = expected_sni.clone();
                let service = TowerToHyperService::new(app.clone());
                connections.spawn(async move {
                    let _permit = permit;
                    let result: Result<()> = async {
                        let accept = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
                        let start = timeout(Duration::from_secs(10), accept).await??;
                        if config.verify_sni {
                            ensure!(start.client_hello().server_name() == Some(expected.as_str()), "Unknown SNI");
                        }
                        let stream = timeout(Duration::from_secs(10), start.into_stream(tls)).await??;
                        let builder = Builder::new(TokioExecutor::new());
                        builder.serve_connection(TokioIo::new(stream), service).await.map_err(|e| anyhow::anyhow!("{e}"))?;
                        Ok(())
                    }.await;
                    if let Err(error) = result { tracing::debug!(%error, "Connection ended"); }
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    state.runtime.lock().await.core.stop().await?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

use crate::{auth::Auth, core::Core, plugins::Plugins};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, OriginalUri, Query, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tower_http::decompression::RequestDecompressionLayer;

pub const ROUTES: &[(&str, &str)] = &[
    ("POST", "/node/handler/add-user"),
    ("POST", "/node/handler/add-users"),
    ("POST", "/node/handler/drop-ips"),
    ("POST", "/node/handler/drop-users-connections"),
    ("POST", "/node/handler/remove-user"),
    ("POST", "/node/handler/remove-users"),
    ("POST", "/node/plugin/nftables/block-ips"),
    ("POST", "/node/plugin/nftables/recreate-tables"),
    ("POST", "/node/plugin/nftables/unblock-ips"),
    ("POST", "/node/plugin/sync"),
    ("POST", "/node/plugin/torrent-blocker/collect"),
    ("POST", "/node/stats/get-all-inbounds-stats"),
    ("POST", "/node/stats/get-all-outbounds-stats"),
    ("POST", "/node/stats/get-combined-stats"),
    ("POST", "/node/stats/get-geocheck"),
    ("POST", "/node/stats/get-inbound-stats"),
    ("POST", "/node/stats/get-outbound-stats"),
    ("GET", "/node/stats/get-system-stats"),
    ("POST", "/node/stats/get-user-ip-list"),
    ("POST", "/node/stats/get-user-online-status"),
    ("GET", "/node/stats/get-users-ip-list"),
    ("POST", "/node/stats/get-users-stats"),
    ("GET", "/node/xray/healthcheck"),
    ("POST", "/node/xray/start"),
    ("GET", "/node/xray/stop"),
];

pub struct Runtime {
    pub core: Core,
    plugins: Plugins,
}

#[derive(Clone)]
pub struct AppState {
    pub runtime: Arc<Mutex<Runtime>>,
    auth: Arc<Auth>,
    webhook_token: Arc<str>,
}

impl AppState {
    pub fn new(core: Core, auth: Auth) -> Self {
        let webhook_token = core.webhook_token().into();
        Self {
            runtime: Arc::new(Mutex::new(Runtime {
                core,
                plugins: Plugins::default(),
            })),
            auth: Arc::new(auth),
            webhook_token,
        }
    }
}

/// Unix-socket-only router for Xray's routing webhooks (upstream /internal/webhook).
pub fn internal_router(state: AppState) -> Router {
    Router::new()
        .route("/internal/webhook", post(webhook))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

async fn webhook(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> StatusCode {
    if query.get("token").map(String::as_str) != Some(&*state.webhook_token) {
        return StatusCode::FORBIDDEN;
    }
    let Ok(event) = serde_json::from_slice::<Value>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    // Answer Xray at once; blocking waits for the runtime lock, like upstream's event bus.
    tokio::spawn(async move {
        state
            .runtime
            .lock()
            .await
            .plugins
            .torrent_event(event)
            .await
    });
    StatusCode::OK
}

pub fn router(state: AppState) -> Router {
    let mut app = Router::new();
    for (method, path) in ROUTES {
        app = app.route(
            path,
            if *method == "GET" {
                get(dispatch)
            } else {
                post(dispatch)
            },
        );
    }
    // Both limits apply after inflation; a small compressed payload cannot bypass the cap.
    app.layer(DefaultBodyLimit::max(1_000_000_000))
        .layer(RequestDecompressionLayer::new())
        .route_layer(middleware::from_fn_with_state(state.clone(), authorize))
        .with_state(state)
}

async fn authorize(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if !request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| state.auth.verify(v))
    {
        return error(
            StatusCode::UNAUTHORIZED,
            request.uri().path(),
            "Unauthorized",
        );
    }
    next.run(request).await
}

fn error(status: StatusCode, path: &str, message: &str) -> Response {
    (status, Json(json!({"timestamp":chrono::Utc::now().to_rfc3339(), "path":path, "message":message, "errorCode":"E000"}))).into_response()
}

fn operation_error(path: &str, cause: &anyhow::Error) -> Response {
    let server_error = cause.downcast_ref::<tonic::Status>().is_some()
        || cause.downcast_ref::<tonic::transport::Error>().is_some()
        || cause.downcast_ref::<std::io::Error>().is_some();
    if !server_error {
        return error(StatusCode::BAD_REQUEST, path, &cause.to_string());
    }
    let code = match path {
        "/node/stats/get-system-stats" => "A010",
        "/node/stats/get-users-stats" => "A011",
        "/node/stats/get-inbound-stats" => "A012",
        "/node/stats/get-outbound-stats" => "A013",
        "/node/stats/get-all-inbounds-stats" => "A015",
        "/node/stats/get-all-outbounds-stats" => "A016",
        "/node/stats/get-combined-stats" => "A017",
        "/node/stats/get-geocheck" => "A018",
        _ => "A001",
    };
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"timestamp":chrono::Utc::now().to_rfc3339(), "path":path, "message":cause.to_string(), "errorCode":code}))).into_response()
}

async fn dispatch(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    body: Bytes,
) -> Response {
    let path = uri.path();
    let body: Value = if method == Method::GET || body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&body) {
            Ok(Value::Object(object)) => Value::Object(object),
            _ => {
                return error(
                    StatusCode::BAD_REQUEST,
                    path,
                    "Request body must be a JSON object",
                );
            }
        }
    };
    let mut runtime = state.runtime.lock().await;
    let result = match path {
        "/node/xray/start" => {
            let Runtime { core, plugins } = &mut *runtime;
            core.start_with_plugins(&body, plugins).await
        }
        "/node/xray/stop" => {
            // Upstream resets plugins before stopping; a reset failure must not keep Xray running.
            if let Err(error) = runtime.plugins.reset().await {
                tracing::warn!(%error, "Plugin reset failed");
            }
            runtime.core.stop().await
        }
        "/node/xray/healthcheck" => Ok(runtime.core.health().await),
        "/node/plugin/sync" => {
            let Runtime { core, plugins } = &mut *runtime;
            match plugins.sync(&body).await {
                Ok(outcome) => {
                    if outcome.stop_xray
                        && let Err(error) = core.stop().await
                    {
                        tracing::warn!(%error, "Stopping Xray after plugin sync failed");
                    }
                    Ok(json!({"accepted": outcome.accepted}))
                }
                Err(error) => Err(error),
            }
        }
        "/node/plugin/torrent-blocker/collect" => Ok(runtime.plugins.collect()),
        _ if path.starts_with("/node/plugin/") => runtime.plugins.handle(path, &body).await,
        _ => {
            let Runtime { core, plugins } = &mut *runtime;
            crate::operations::handle_with_whitelist(path, &body, core, plugins.whitelist()).await
        }
    };
    match result {
        Ok(value) => Json(json!({"response":value})).into_response(),
        Err(cause) => {
            tracing::warn!(%path, error = %format!("{cause:#}"), "Request failed");
            operation_error(path, &cause)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rpc_outages_are_server_errors_and_validation_is_bad_request() {
        assert_eq!(
            operation_error(
                "/node/stats/get-users-stats",
                &tonic::Status::unavailable("Xray offline").into()
            )
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            operation_error(
                "/node/stats/get-users-stats",
                &anyhow::anyhow!("reset must be a boolean")
            )
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
}

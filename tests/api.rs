use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use remnanode_rust::{
    api::{AppState, ROUTES, router},
    auth::Auth,
    core::Core,
};
use tower::ServiceExt;

fn state() -> AppState {
    let key = include_str!("fixtures/jwt.pub");
    AppState::new(
        Core::new(
            "/missing-xray".into(),
            "/tmp/unused-state".into(),
            "http://127.0.0.1:61000".into(),
        ),
        Auth::new(key).unwrap(),
    )
}

#[tokio::test]
async fn every_public_route_requires_jwt() {
    for (method, path) in ROUTES {
        let response = router(state())
            .oneshot(
                Request::builder()
                    .method(*method)
                    .uri(*path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }
}

#[test]
fn route_inventory_matches_upstream() {
    let contract: serde_json::Value =
        serde_json::from_str(include_str!("../upstream/contract.json")).unwrap();
    let mut upstream: Vec<_> = contract["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["method"].as_str().unwrap(), r["path"].as_str().unwrap()))
        .collect();
    let mut actual = ROUTES.to_vec();
    upstream.sort();
    actual.sort();
    assert_eq!(actual, upstream);
}

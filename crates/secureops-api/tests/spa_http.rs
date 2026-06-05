//! SPA embedding test (PRODUCT.md Phase 8): the dashboard's static files are
//! served as a fallback for unmatched (client-side) routes, while API routes
//! still take precedence.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

use secureops_api::authz::PolicyEngine;
use secureops_api::store::{InMemoryStore, Store};
use secureops_api::{build_router, with_spa, AppState};

fn state() -> AppState {
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    AppState::new(
        store,
        Arc::new(PolicyEngine::default()),
        "secret",
        [7u8; 32],
    )
}

/// Create a temp web dir with an index.html; returns its path.
fn temp_web_dir() -> String {
    let dir = std::env::temp_dir().join(format!("secureops-spa-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>SecureOps SPA</title>",
    )
    .unwrap();
    dir.to_string_lossy().into_owned()
}

#[tokio::test]
async fn spa_fallback_serves_index_for_client_routes() {
    let web = temp_web_dir();
    let app = with_spa(build_router(state()), &web);

    // A client-side route (no API match) → SPA index.
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/findings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("SecureOps SPA"));

    // API routes still take precedence over the SPA fallback.
    let r = app
        .oneshot(
            Request::builder()
                .uri("/livez")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("ok"));

    let _ = std::fs::remove_dir_all(&web);
}

//! SPA embedding tests (PRODUCT.md Phase 8): the dashboard's static files are
//! served as a fallback for unmatched (client-side) routes, API routes still
//! take precedence, and the first-run wizard is server-enforced - every SPA
//! route except `/license` redirects to `/license` until a license has been
//! activated on the instance.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

use secureops_api::authz::PolicyEngine;
use secureops_api::license::{License, Tier};
use secureops_api::store::{InMemoryStore, Store};
use secureops_api::{build_router, with_spa, AppState};

fn state_with_store(store: Arc<dyn Store>) -> AppState {
    AppState::new(
        store,
        Arc::new(PolicyEngine::default()),
        "secret",
        [7u8; 32],
    )
}

fn activated_license() -> License {
    License {
        lic_id: "lic-spa-test".into(),
        tenant_id: "default".into(),
        tier: Tier::Pro,
        seats: 5,
        features: vec![],
        issued: 0,
        expiry: i64::MAX,
        mode: "offline".into(),
        grace_days: 14,
    }
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
async fn spa_fallback_serves_index_for_client_routes_once_activated() {
    let web = temp_web_dir();
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    store.put_license(&activated_license()).await.unwrap();
    let app = with_spa(build_router(state_with_store(store.clone())), &web, store);

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

#[tokio::test]
async fn wizard_redirects_to_license_until_activated() {
    let web = temp_web_dir();
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = with_spa(
        build_router(state_with_store(store.clone())),
        &web,
        store.clone(),
    );

    // No license activated: every SPA route redirects to /license...
    for path in ["/", "/dashboard/findings", "/setup/cloud"] {
        let r = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            r.status().is_redirection(),
            "{path} should redirect, got {}",
            r.status()
        );
        assert_eq!(
            r.headers().get(header::LOCATION).unwrap().to_str().unwrap(),
            "/license",
            "{path} should land on /license"
        );
    }

    // ...except /license itself, which must render so activation can happen.
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/license")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // After activation the same deep link serves the SPA.
    store.put_license(&activated_license()).await.unwrap();
    let r = app
        .oneshot(
            Request::builder()
                .uri("/dashboard/findings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(&web);
}

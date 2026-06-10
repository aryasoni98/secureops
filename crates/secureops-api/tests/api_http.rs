//! HTTP-level integration tests for the platform API (PRODUCT.md Phase 5).
//!
//! Drives the real axum router via `tower::ServiceExt::oneshot` against an
//! in-memory store — asserting the auth (`401` + `WWW-Authenticate`), license
//! activation (`200` / `403 invalid_signature`), and Cedar tier-gate
//! (`403` for a Community principal on `/bughunt`) behaviours end-to-end.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use secureops_api::auth::{issue_jwt, Claims};
use secureops_api::authz::PolicyEngine;
use secureops_api::license::{sign, License, Tier};
use secureops_api::store::{InMemoryStore, Store};
use secureops_api::{build_router, AppState};

const SEED: [u8; 32] = [7u8; 32];
const SECRET: &str = "test-secret";
const FAR_FUTURE: i64 = 4_102_444_800; // ~year 2100

fn pubkey() -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&SEED)
        .verifying_key()
        .to_bytes()
}

fn state() -> AppState {
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    AppState::new(store, Arc::new(PolicyEngine::default()), SECRET, pubkey())
}

fn valid_license_key(features: Vec<String>) -> String {
    let sk = ed25519_dalek::SigningKey::from_bytes(&SEED);
    let lic = License {
        lic_id: "lic_1".into(),
        tenant_id: "tenant_1".into(),
        tier: Tier::Pro,
        seats: 5,
        features,
        issued: 0,
        expiry: FAR_FUTURE,
        mode: "online".into(),
        grace_days: 7,
    };
    sign(&lic, &sk)
}

fn jwt(features: Vec<String>, tier: &str) -> String {
    issue_jwt(
        SECRET,
        &Claims {
            sub: "u1".into(),
            tenant: "tenant_1".into(),
            tier: tier.into(),
            features,
            exp: FAR_FUTURE as usize,
        },
    )
    .unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn missing_credentials_yields_401_with_www_authenticate() {
    let resp = build_router(state())
        .oneshot(
            Request::builder()
                .uri("/api/v1/findings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers().contains_key(header::WWW_AUTHENTICATE),
        "401 must carry WWW-Authenticate"
    );
}

#[tokio::test]
async fn livez_is_ok() {
    let resp = build_router(state())
        .oneshot(
            Request::builder()
                .uri("/livez")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn license_activate_valid_then_tampered() {
    // Valid key → 200 with tier + token.
    let key = valid_license_key(vec!["bughunt".into()]);
    let resp = build_router(state())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/license/activate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "key": key }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["tier"], "pro");
    assert!(v["token"].is_string());

    // Tampered key → 403 invalid_signature.
    let tampered = format!("{key}A");
    let resp = build_router(state())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/license/activate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "key": tampered }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["error"], "invalid_signature");
}

#[tokio::test]
async fn cedar_gates_bughunt_by_feature() {
    // Community principal (no features) → 403 on the gated endpoint.
    let resp = build_router(state())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/bughunt")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", jwt(vec![], "community")),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "scope": "all" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Principal holding the `bughunt` feature → 200; the bug-hunt runs (offline
    // LocalProvider) and completes (6b wired the engine in place of the stub).
    let resp = build_router(state())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/bughunt")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", jwt(vec!["bughunt".into()], "pro")),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "scope": "all" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "completed");
}

#[tokio::test]
async fn openapi_doc_is_served() {
    let resp = build_router(state())
        .oneshot(
            Request::builder()
                .uri("/api/v1/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["info"]["title"], "SecureOps Platform API");
}

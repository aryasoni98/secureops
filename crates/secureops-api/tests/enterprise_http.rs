//! HTTP integration tests for the Phase 8 enterprise surface: compliance report
//! formats (json/csv/signed-zip) and OIDC SSO (metadata gate + callback).

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use secureops_api::auth::{issue_jwt, Claims};
use secureops_api::authz::PolicyEngine;
use secureops_api::export::IncidentExport;
use secureops_api::sso::{OidcClaims, OidcVerifier};
use secureops_api::store::{InMemoryStore, Store};
use secureops_api::{build_router, AppState};

const SECRET: &str = "test-secret";
const FAR: i64 = 4_102_444_800;

fn base_state() -> AppState {
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    AppState::new(store, Arc::new(PolicyEngine::default()), SECRET, [7u8; 32])
}

fn jwt(features: &[&str]) -> String {
    issue_jwt(
        SECRET,
        &Claims {
            sub: "u1".into(),
            tenant: "tenant_1".into(),
            tier: "enterprise".into(),
            features: features.iter().map(|s| s.to_string()).collect(),
            exp: FAR as usize,
        },
    )
    .unwrap()
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn compliance_json_csv_and_signed_zip() {
    let app = build_router(base_state());
    let tok = jwt(&[]);

    // JSON
    let r = app
        .clone()
        .oneshot(get(
            "/api/v1/compliance/reports?framework=cis&format=json",
            &tok,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value =
        serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(v["framework"], "cis");

    // CSV
    let r = app
        .clone()
        .oneshot(get("/api/v1/compliance/reports?format=csv", &tok))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers().get(header::CONTENT_TYPE).unwrap(), "text/csv");

    // Signed ZIP — verify the Ed25519 signature with the advertised pubkey.
    let r = app
        .clone()
        .oneshot(get("/api/v1/compliance/reports?format=zip", &tok))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        r.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/zip"
    );
    let pubkey_hex = r
        .headers()
        .get("x-export-pubkey")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let bytes = r.into_body().collect().await.unwrap().to_bytes();
    let pk: [u8; 32] = hex_to_32(&pubkey_hex);
    assert!(
        IncidentExport::verify(&bytes, &pk).unwrap(),
        "exported bundle signature must verify"
    );

    // Unsupported format → 400.
    let r = app
        .oneshot(get("/api/v1/compliance/reports?format=pdf", &tok))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

struct TestVerifier;
#[async_trait]
impl OidcVerifier for TestVerifier {
    async fn verify(&self, token: &str) -> Option<OidcClaims> {
        (token == "good").then(|| OidcClaims {
            sub: "okta|u".into(),
            email: "u@corp.example".into(),
            tenant: "tenant_1".into(),
            tier: "enterprise".into(),
            features: vec!["sso".into()],
        })
    }
}

#[tokio::test]
async fn sso_metadata_is_feature_gated() {
    let app = build_router(base_state());
    // Community (no sso feature) → 403.
    let r = app
        .clone()
        .oneshot(get("/api/v1/auth/oidc/metadata", &jwt(&[])))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // With sso feature → 200.
    let r = app
        .oneshot(get("/api/v1/auth/oidc/metadata", &jwt(&["sso"])))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn sso_callback_requires_configured_verifier_and_valid_token() {
    // No verifier configured → 404.
    let app = build_router(base_state());
    let r = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/callback")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "token": "good" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    // Verifier configured: valid token → 200 + session JWT; bad token → 401.
    let app = build_router(base_state().with_oidc(Arc::new(TestVerifier)));
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/callback")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "token": "good" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value =
        serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(v["token"].is_string());

    let r = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/callback")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "token": "bad" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

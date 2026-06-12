//! # secureops-license-server
//!
//! A stateless license server (PRODUCT.md Phase 8): verifies Ed25519-signed
//! license keys on `/heartbeat` and maintains an in-memory revocation list
//! updated via the admin-authenticated `/revoke`. No database - the signature
//! and the (process-lifetime) revocation set are the only state. Single-VPS
//! deployable.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use secureops_api::license;

/// Server state: the vendor public key + revoked license ids + admin key.
#[derive(Clone)]
pub struct AppState {
    pub pubkey: [u8; 32],
    pub admin_key: Arc<str>,
    pub revoked: Arc<Mutex<HashSet<String>>>,
}

impl AppState {
    pub fn new(pubkey: [u8; 32], admin_key: impl Into<Arc<str>>) -> Self {
        Self {
            pubkey,
            admin_key: admin_key.into(),
            revoked: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Recover the revocation set even if a prior panic poisoned the mutex - a
/// `HashSet` insert/contains cannot leave the set in a broken state, and a
/// license server that panics on every later request is worse than one that
/// keeps serving the last-known revocation list.
fn revoked_set(s: &AppState) -> std::sync::MutexGuard<'_, HashSet<String>> {
    s.revoked.lock().unwrap_or_else(|e| e.into_inner())
}

/// Constant-time byte comparison so the admin key cannot be guessed
/// byte-by-byte via response timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
pub struct HeartbeatReq {
    /// The full signed license key (`payload.sig`).
    pub key: String,
    #[serde(default)]
    pub instance_fingerprint: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

async fn heartbeat(State(s): State<AppState>, Json(req): Json<HeartbeatReq>) -> Response {
    match license::verify(&req.key, &s.pubkey, now_unix()) {
        Ok(lic) => {
            let revoked = revoked_set(&s).contains(&lic.lic_id);
            let status = if revoked { "revoked" } else { "active" };
            (
                StatusCode::OK,
                Json(json!({ "status": status, "expiry": lic.expiry, "licId": lic.lic_id })),
            )
                .into_response()
        }
        // Signature was valid but the term has lapsed.
        Err("license_expired") => {
            (StatusCode::OK, Json(json!({ "status": "expired" }))).into_response()
        }
        // Malformed / forged.
        Err(code) => (StatusCode::FORBIDDEN, Json(json!({ "error": code }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct RevokeReq {
    pub lic_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

async fn revoke(
    headers: HeaderMap,
    State(s): State<AppState>,
    Json(req): Json<RevokeReq>,
) -> Response {
    let authorized = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|k| ct_eq(k.as_bytes(), s.admin_key.as_bytes()));
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    revoked_set(&s).insert(req.lic_id.clone());
    (
        StatusCode::OK,
        Json(json!({ "status": "revoked", "licId": req.lic_id })),
    )
        .into_response()
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Build the license-server router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/heartbeat", post(heartbeat))
        .route("/revoke", post(revoke))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request};
    use http_body_util::BodyExt;
    use secureops_api::license::{sign, License, Tier};
    use tower::ServiceExt;

    const SEED: [u8; 32] = [7u8; 32];
    const FAR: i64 = 4_102_444_800;

    fn pubkey() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&SEED)
            .verifying_key()
            .to_bytes()
    }

    fn key(lic_id: &str, expiry: i64) -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(&SEED);
        sign(
            &License {
                lic_id: lic_id.into(),
                tenant_id: "t1".into(),
                tier: Tier::Enterprise,
                seats: 10,
                features: vec![],
                issued: 0,
                expiry,
                mode: "online".into(),
                grace_days: 7,
            },
            &sk,
        )
    }

    fn state() -> AppState {
        AppState::new(pubkey(), "admin-secret")
    }

    async fn body(resp: Response) -> serde_json::Value {
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&b).unwrap()
    }

    fn post(uri: &str, admin: Option<&str>, body: serde_json::Value) -> Request<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(a) = admin {
            b = b.header("x-admin-key", a);
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    #[tokio::test]
    async fn heartbeat_valid_is_active() {
        let resp = build_router(state())
            .oneshot(post(
                "/heartbeat",
                None,
                json!({ "key": key("lic-1", FAR) }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body(resp).await["status"], "active");
    }

    #[tokio::test]
    async fn heartbeat_expired_reports_expired() {
        let resp = build_router(state())
            .oneshot(post(
                "/heartbeat",
                None,
                json!({ "key": key("lic-1", 1000) }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body(resp).await["status"], "expired");
    }

    #[tokio::test]
    async fn heartbeat_forged_is_403() {
        let resp = build_router(state())
            .oneshot(post("/heartbeat", None, json!({ "key": "garbage.sig" })))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn revoke_requires_admin_key_then_heartbeat_reports_revoked() {
        let st = state();
        let app = build_router(st.clone());

        // No admin key → 401.
        let resp = app
            .clone()
            .oneshot(post("/revoke", None, json!({ "lic_id": "lic-1" })))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // With admin key → revoked.
        let resp = app
            .clone()
            .oneshot(post(
                "/revoke",
                Some("admin-secret"),
                json!({ "lic_id": "lic-1" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Subsequent heartbeat for that lic reports revoked.
        let resp = app
            .oneshot(post(
                "/heartbeat",
                None,
                json!({ "key": key("lic-1", FAR) }),
            ))
            .await
            .unwrap();
        assert_eq!(body(resp).await["status"], "revoked");
    }
}

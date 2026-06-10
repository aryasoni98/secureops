//! Chaos / resilience tests (PRODUCT.md Phase 9): the API must degrade, not
//! panic, when its backing store is unavailable.
//! - Postgres down → `GET /readyz` returns `503 + Retry-After`.
//! - A store error on a data route → `503 storage_unavailable` (no 500/panic).
//! - Redis absent → scans still persist (degraded enqueue).

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use secureops_api::auth::{issue_jwt, Claims};
use secureops_api::authz::PolicyEngine;
use secureops_api::license::License;
use secureops_api::models::{Finding, Remediation, Scan};
use secureops_api::store::{FindingFilter, InMemoryStore, Store};
use secureops_api::{build_router, AppState};

const SECRET: &str = "test-secret";

/// A store that is always unreachable - every call errors, health is false.
struct DeadStore;

#[async_trait]
impl Store for DeadStore {
    async fn health(&self) -> bool {
        false
    }
    async fn lookup_api_key(&self, _h: &str) -> anyhow::Result<Option<Claims>> {
        anyhow::bail!("db down")
    }
    async fn put_license(&self, _l: &License) -> anyhow::Result<()> {
        anyhow::bail!("db down")
    }
    async fn get_license(&self, _t: &str) -> anyhow::Result<Option<License>> {
        anyhow::bail!("db down")
    }
    async fn create_scan(&self, _s: &Scan) -> anyhow::Result<()> {
        anyhow::bail!("db down")
    }
    async fn get_scan(&self, _t: &str, _id: Uuid) -> anyhow::Result<Option<Scan>> {
        anyhow::bail!("db down")
    }
    async fn list_findings(&self, _t: &str, _f: &FindingFilter) -> anyhow::Result<Vec<Finding>> {
        anyhow::bail!("db down")
    }
    async fn set_finding_status(&self, _t: &str, _id: Uuid, _s: &str) -> anyhow::Result<bool> {
        anyhow::bail!("db down")
    }
    async fn insert_finding(&self, _f: &Finding) -> anyhow::Result<()> {
        anyhow::bail!("db down")
    }
    async fn insert_remediation(&self, _t: &str, _r: &Remediation) -> anyhow::Result<()> {
        anyhow::bail!("db down")
    }
    async fn list_remediations(&self, _t: &str) -> anyhow::Result<Vec<Remediation>> {
        anyhow::bail!("db down")
    }
    async fn set_remediation_state(&self, _t: &str, _id: Uuid, _s: &str) -> anyhow::Result<bool> {
        anyhow::bail!("db down")
    }
    async fn record_rl_feedback(
        &self,
        _t: &str,
        _f: &str,
        _a: &str,
        _r: f64,
    ) -> anyhow::Result<()> {
        anyhow::bail!("db down")
    }
}

fn jwt() -> String {
    issue_jwt(
        SECRET,
        &Claims {
            sub: "u".into(),
            tenant: "t1".into(),
            tier: "pro".into(),
            features: vec![],
            exp: 4_102_444_800,
        },
    )
    .unwrap()
}

fn state_with(store: Arc<dyn Store>) -> AppState {
    AppState::new(store, Arc::new(PolicyEngine::default()), SECRET, [7u8; 32])
}

#[tokio::test]
async fn readyz_is_503_with_retry_after_when_store_down() {
    let app = build_router(state_with(Arc::new(DeadStore)));
    let r = app
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        r.headers().contains_key(header::RETRY_AFTER),
        "must set Retry-After"
    );
}

#[tokio::test]
async fn livez_stays_ok_even_when_store_down() {
    // Liveness is independent of the DB - the process is up.
    let app = build_router(state_with(Arc::new(DeadStore)));
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
}

#[tokio::test]
async fn data_route_returns_503_not_500_on_store_error() {
    let app = build_router(state_with(Arc::new(DeadStore)));
    let r = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/findings")
                .header(header::AUTHORIZATION, format!("Bearer {}", jwt()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let v: Value =
        serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(v["error"], "storage_unavailable");
}

#[tokio::test]
async fn scans_persist_in_degraded_mode_without_redis() {
    // No Redis wired (the default) → enqueue is skipped, scan still created.
    let app = build_router(state_with(Arc::new(InMemoryStore::new())));
    let r = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/scans")
                .header(header::AUTHORIZATION, format!("Bearer {}", jwt()))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "scope": "all" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value =
        serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(v["status"], "queued");
}

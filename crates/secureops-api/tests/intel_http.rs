//! HTTP integration tests for the intelligence/autonomy routes (Phase 6b/7b):
//! graph rebuild/paths/blast-radius, RL feedback/stats, bug-hunt run/get, and
//! the remediation HITL queue - all through the real router, in-memory state.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use secureops_api::auth::{issue_jwt, Claims};
use secureops_api::authz::PolicyEngine;
use secureops_api::store::{InMemoryStore, Store};
use secureops_api::{build_router, AppState};

const SECRET: &str = "test-secret";
const FAR: i64 = 4_102_444_800;

fn state() -> AppState {
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    AppState::new(store, Arc::new(PolicyEngine::default()), SECRET, [7u8; 32])
}

fn jwt(features: &[&str]) -> String {
    jwt_role("admin", features)
}

fn jwt_role(role: &str, features: &[&str]) -> String {
    issue_jwt(
        SECRET,
        &Claims {
            sub: "u1".into(),
            tenant: "tenant_1".into(),
            tier: "pro".into(),
            role: role.into(),
            features: features.iter().map(|s| s.to_string()).collect(),
            iss: "secureops".into(),
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

fn post(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn body(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn graph_rebuild_paths_and_blast_radius() {
    let app = build_router(state());
    let tok = jwt(&[]);

    let spec = json!({
        "nodes": [
            {"id": "internet", "kind": "internet", "exposed": true},
            {"id": "ec2", "kind": "ec2"},
            {"id": "rds", "kind": "rds", "sensitive": true}
        ],
        "edges": [
            {"from": "internet", "to": "ec2", "kind": "exposes", "difficulty": 1.0},
            {"from": "ec2", "to": "rds", "kind": "connects_to", "difficulty": 1.0}
        ]
    });
    let r = app
        .clone()
        .oneshot(post("/api/v1/graph/rebuild", &tok, spec))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(body(r).await["nodes"], 3);

    let r = app
        .clone()
        .oneshot(get("/api/v1/graph/paths", &tok))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = body(r).await;
    assert_eq!(v["paths"].as_array().unwrap().len(), 1);
    assert_eq!(v["paths"][0]["nodes"][0], "internet");
    assert_eq!(v["paths"][0]["nodes"][2], "rds");

    let r = app
        .oneshot(get("/api/v1/graph/blast-radius/internet", &tok))
        .await
        .unwrap();
    assert_eq!(body(r).await["blastRadius"], 1);
}

#[tokio::test]
async fn rl_feedback_trains_and_stats_report() {
    let app = build_router(state());
    let tok = jwt(&[]);

    for _ in 0..3 {
        let r = app
            .clone()
            .oneshot(post(
                "/api/v1/rl/feedback",
                &tok,
                json!({"severity": 4, "action": "confirm"}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }
    let r = app.oneshot(get("/api/v1/rl/stats", &tok)).await.unwrap();
    assert_eq!(body(r).await["updates"], 3);
}

#[tokio::test]
async fn rl_feedback_rejects_unknown_action() {
    let app = build_router(state());
    let r = app
        .oneshot(post(
            "/api/v1/rl/feedback",
            &jwt(&[]),
            json!({"severity": 2, "action": "bogus"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bughunt_gated_then_runs_and_fetches() {
    let app = build_router(state());

    // Community (no feature) → 403.
    let r = app
        .clone()
        .oneshot(post("/api/v1/bughunt", &jwt(&[]), json!({"scope": "all"})))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // With the feature → runs (LocalProvider) and returns a job id.
    let r = app
        .clone()
        .oneshot(post(
            "/api/v1/bughunt",
            &jwt(&["bughunt"]),
            json!({"scope": "all"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = body(r).await;
    assert_eq!(v["status"], "completed");
    let job_id = v["jobId"].as_str().unwrap().to_string();

    let r = app
        .oneshot(get(
            &format!("/api/v1/bughunt/{job_id}"),
            &jwt(&["bughunt"]),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(body(r).await["report"]["severity"], "info");
}

#[tokio::test]
async fn remediation_queue_and_approve_destructive() {
    let app = build_router(state());
    let tok = jwt(&[]);

    // Queue a destructive playbook.
    let r = app
        .clone()
        .oneshot(post(
            "/api/v1/remediations",
            &tok,
            json!({"finding_id": "f1", "playbook_id": "k8s-privileged-pod"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = body(r).await;
    assert_eq!(v["class"], "destructive");
    assert_eq!(v["state"], "pending");
    let id = v["id"].as_str().unwrap().to_string();

    // Queue lists it.
    let r = app
        .clone()
        .oneshot(get("/api/v1/remediations/queue", &tok))
        .await
        .unwrap();
    assert_eq!(body(r).await["remediations"].as_array().unwrap().len(), 1);

    // Approve → runs via NoopCloud → completed + executed.
    let r = app
        .oneshot(post(
            &format!("/api/v1/remediations/{id}/approve"),
            &tok,
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = body(r).await;
    assert_eq!(v["state"], "completed");
    assert_eq!(v["executed"], true);
}

fn jwt_tenant(tenant: &str, role: &str) -> String {
    issue_jwt(
        SECRET,
        &Claims {
            sub: "u1".into(),
            tenant: tenant.into(),
            tier: "pro".into(),
            role: role.into(),
            features: vec!["bughunt".into()],
            iss: "secureops".into(),
            exp: FAR as usize,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn remediation_approve_forbidden_for_member() {
    let app = build_router(state());
    // Queue as admin.
    let r = app
        .clone()
        .oneshot(post(
            "/api/v1/remediations",
            &jwt(&[]),
            json!({"finding_id": "f1", "playbook_id": "k8s-privileged-pod"}),
        ))
        .await
        .unwrap();
    let id = body(r).await["id"].as_str().unwrap().to_string();

    // A non-admin (member) cannot approve a destructive remediation.
    let r = app
        .oneshot(post(
            &format!("/api/v1/remediations/{id}/approve"),
            &jwt_role("member", &[]),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bughunt_job_is_tenant_isolated() {
    let app = build_router(state());
    // tenant_1 runs a bug-hunt and gets a job id.
    let r = app
        .clone()
        .oneshot(post(
            "/api/v1/bughunt",
            &jwt_tenant("tenant_1", "member"),
            json!({"scope": "all"}),
        ))
        .await
        .unwrap();
    let job_id = body(r).await["jobId"].as_str().unwrap().to_string();

    // tenant_2 must not be able to read tenant_1's job (was a cross-tenant leak).
    let r = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/bughunt/{job_id}"),
            &jwt_tenant("tenant_2", "member"),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    // The owning tenant still can.
    let r = app
        .oneshot(get(
            &format!("/api/v1/bughunt/{job_id}"),
            &jwt_tenant("tenant_1", "member"),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_playbook_is_404() {
    let app = build_router(state());
    let r = app
        .oneshot(post(
            "/api/v1/remediations",
            &jwt(&[]),
            json!({"finding_id": "f1", "playbook_id": "does-not-exist"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

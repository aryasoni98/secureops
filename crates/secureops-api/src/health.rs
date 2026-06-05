//! Liveness / readiness probes (PRODUCT.md Phase 5; P9 chaos tests assert the
//! `503 + Retry-After` degraded path when Postgres is down).

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

/// Liveness: the process is up. Always `200` while the event loop runs.
pub async fn livez() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

/// Readiness: dependencies (DB) are reachable. Returns `503 + Retry-After` when
/// the backing store is unavailable so load balancers shed traffic instead of
/// 500-ing (PRODUCT.md P9 chaos: "Postgres down → 503 + Retry-After, no panic").
pub async fn readyz(db_ok: bool) -> impl IntoResponse {
    if db_ok {
        (StatusCode::OK, Json(json!({ "status": "ready" }))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "5")],
            Json(json!({ "status": "degraded", "reason": "database_unreachable" })),
        )
            .into_response()
    }
}

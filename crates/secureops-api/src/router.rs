//! Router assembly + OpenAPI document (PRODUCT.md Phase 5).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::Router;
use tower_http::services::ServeDir;
use utoipa::OpenApi;

use crate::state::AppState;
use crate::store::Store;
use crate::{health, intel, routes, sso, ws};

/// Embed the built dashboard SPA (PRODUCT.md Phase 8): static assets under
/// `/assets`, and any unmatched (client-side) route falls back to the SPA
/// `index.html`. API routes still take precedence over the fallback.
///
/// **First-run wizard enforcement (P8):** until a license has been activated
/// on this instance, every SPA route except `/license` answers
/// `302 → /license` - server-side, so the wizard cannot be skipped by typing
/// a deep link. Once a license exists the check memoizes and the fallback
/// never touches the store again.
pub fn with_spa(router: Router, web_dir: &str, store: Arc<dyn Store>) -> Router {
    let index_path = format!("{web_dir}/index.html");
    let activated = Arc::new(AtomicBool::new(false));
    router
        .nest_service("/assets", ServeDir::new(format!("{web_dir}/assets")))
        .fallback(move |uri: Uri| {
            let path = index_path.clone();
            let store = store.clone();
            let activated = activated.clone();
            async move {
                if uri.path() != "/license" && !activated.load(Ordering::Relaxed) {
                    match store.any_license().await {
                        Ok(true) => activated.store(true, Ordering::Relaxed),
                        // No license yet, or the store is unreachable: land on
                        // the wizard's license step either way.
                        Ok(false) | Err(_) => {
                            return Redirect::temporary("/license").into_response()
                        }
                    }
                }
                match tokio::fs::read_to_string(&path).await {
                    Ok(html) => Html(html).into_response(),
                    Err(_) => (StatusCode::NOT_FOUND, "dashboard not built").into_response(),
                }
            }
        })
}

/// Generated OpenAPI document, served at `/api/v1/openapi.json`.
#[derive(OpenApi)]
#[openapi(
    info(title = "SecureOps Platform API", version = "0.0.2"),
    components(schemas(
        crate::models::Finding,
        crate::models::Scan,
        crate::models::ScanStatus,
        crate::models::Severity,
        crate::license::License,
        crate::license::Tier,
    ))
)]
pub struct ApiDoc;

async fn openapi_json() -> axum::Json<utoipa::openapi::OpenApi> {
    axum::Json(ApiDoc::openapi())
}

/// Readiness probe: `200` when the store is reachable, else `503 + Retry-After`.
async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    health::readyz(state.store.health().await).await
}

/// Build the full application router with state injected.
pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .route("/license/activate", post(routes::license_activate))
        .route("/license", get(routes::license_get))
        .route("/scans", post(routes::create_scan))
        .route("/scans/{id}", get(routes::get_scan))
        .route("/findings", get(routes::list_findings))
        .route("/findings/{id}/action", post(routes::finding_action))
        .route("/compliance/reports", get(routes::compliance_reports))
        // Intelligence + autonomy (6b/7b).
        .route("/bughunt", post(intel::bughunt_run))
        .route("/bughunt/{job_id}", get(intel::bughunt_get))
        .route("/graph/rebuild", post(intel::graph_rebuild))
        .route("/graph/paths", get(intel::graph_paths))
        .route("/graph/blast-radius/{node}", get(intel::graph_blast_radius))
        .route("/rl/feedback", post(intel::rl_feedback))
        .route("/rl/stats", get(intel::rl_stats))
        .route("/remediations", post(intel::remediation_create))
        .route("/remediations/queue", get(intel::remediations_queue))
        .route(
            "/remediations/{id}/approve",
            post(intel::remediation_approve),
        )
        .route("/remediations/{id}/deny", post(intel::remediation_deny))
        .route(
            "/remediations/circuit/{class}/reset",
            post(intel::remediation_circuit_reset),
        )
        // SSO (P8).
        .route("/auth/oidc/metadata", get(sso::oidc_metadata))
        .route("/auth/oidc/callback", post(sso::oidc_callback))
        .route("/openapi.json", get(openapi_json));

    Router::new()
        .route("/livez", get(health::livez))
        .route("/readyz", get(readyz))
        .route("/ws/findings", get(ws::ws_handler))
        .route("/ws/scan-progress", get(ws::ws_handler))
        .route("/ws/remediation", get(ws::ws_handler))
        .nest("/api/v1", api)
        .with_state(state)
}

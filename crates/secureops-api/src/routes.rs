//! REST handlers (PRODUCT.md Phase 5). Every handler depends only on
//! [`AppState`]; tier-locked ones gate through the Cedar [`PolicyEngine`] before
//! doing work. Bug-hunt execution and compliance PDF rendering land in P6/P8 -
//! the routes here queue jobs / return JSON and are not stubs.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::{issue_jwt, Authenticated, Claims};
use crate::error::{ApiError, ApiResult};
use crate::license;
use crate::models::{Scan, ScanStatus};
use crate::state::AppState;
use crate::store::FindingFilter;

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// `POST /api/v1/license/activate` - verify an Ed25519 key, persist it, mint a
/// session JWT scoped to the license's tier/features.
#[derive(Deserialize)]
pub struct ActivateReq {
    pub key: String,
}

pub async fn license_activate(
    State(s): State<AppState>,
    Json(req): Json<ActivateReq>,
) -> ApiResult<Json<Value>> {
    let lic =
        license::verify(&req.key, &s.license_pubkey, now_unix()).map_err(ApiError::License)?;
    s.store
        .put_license(&lic)
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?;

    let tier = format!("{:?}", lic.tier).to_lowercase();
    let claims = Claims {
        sub: format!("license:{}", lic.lic_id),
        tenant: lic.tenant_id.clone(),
        tier: tier.clone(),
        features: lic.features.clone(),
        exp: lic.expiry as usize,
    };
    let token = issue_jwt(&s.jwt_secret, &claims).map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(json!({
        "tier": tier,
        "expiry": lic.expiry,
        "features": lic.features,
        "token": token,
    })))
}

/// `GET /api/v1/license` - the authenticated tenant's active license.
pub async fn license_get(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
) -> ApiResult<Json<license::License>> {
    s.store
        .get_license(&claims.tenant)
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
pub struct ScanReq {
    pub scope: String,
}

/// `POST /api/v1/scans` - queue a scan (Cedar action `scans`).
pub async fn create_scan(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Json(req): Json<ScanReq>,
) -> ApiResult<Json<Value>> {
    if !s.authz.allows(&claims.features, "scans") {
        return Err(ApiError::Forbidden("scans"));
    }
    let scan = Scan {
        id: Uuid::new_v4(),
        tenant_id: claims.tenant.clone(),
        scope: req.scope,
        kind: "scan".into(),
        status: ScanStatus::Queued,
        created_at: now_unix(),
    };
    s.store
        .create_scan(&scan)
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?;
    // Best-effort enqueue for the scanner worker; degrade gracefully if Redis is
    // down (P9 chaos: scan is still persisted, warning logged).
    if let Some(redis) = &s.redis {
        let payload =
            json!({ "scanId": scan.id, "scope": scan.scope, "kind": scan.kind }).to_string();
        if let Err(e) = redis
            .enqueue(crate::redis_queue::SCAN_QUEUE, &payload)
            .await
        {
            tracing::warn!("scan enqueue failed (degraded mode): {e}");
        }
    }
    s.hub
        .publish(json!({ "event": "scan.queued", "id": scan.id }).to_string());
    Ok(Json(json!({ "jobId": scan.id, "status": "queued" })))
}

/// `GET /api/v1/scans/{id}` - fetch a scan (tenant-scoped).
pub async fn get_scan(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Scan>> {
    s.store
        .get_scan(&claims.tenant, id)
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
pub struct FindingsQuery {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// `GET /api/v1/findings` - list the tenant's findings (filter + paginate).
pub async fn list_findings(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Query(q): Query<FindingsQuery>,
) -> ApiResult<Json<Value>> {
    if !s.authz.allows(&claims.features, "findings") {
        return Err(ApiError::Forbidden("findings"));
    }
    let filter = FindingFilter {
        severity: q.severity,
        status: q.status,
        limit: q.limit.unwrap_or(50),
        offset: q.offset.unwrap_or(0),
    };
    let items = s
        .store
        .list_findings(&claims.tenant, &filter)
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?;
    // Re-rank by the tenant's LinUCB model (no-op until it has feedback).
    let items = crate::intel::rank_findings(&s, &claims.tenant, items);
    let count = items.len();
    Ok(Json(json!({ "findings": items, "count": count })))
}

#[derive(Deserialize)]
pub struct ActionReq {
    pub action: String,
}

/// `POST /api/v1/findings/{id}/action` - confirm/dismiss/escalate a finding.
pub async fn finding_action(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Path(id): Path<Uuid>,
    Json(req): Json<ActionReq>,
) -> ApiResult<Json<Value>> {
    let status = match req.action.as_str() {
        "confirm" => "confirmed",
        "dismiss" => "dismissed",
        "escalate" => "escalated",
        other => return Err(ApiError::BadRequest(format!("unknown action: {other}"))),
    };
    let updated = s
        .store
        .set_finding_status(&claims.tenant, id, status)
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?;
    if !updated {
        return Err(ApiError::NotFound);
    }
    s.hub
        .publish(json!({ "event": "finding.action", "id": id, "status": status }).to_string());
    Ok(Json(json!({ "id": id, "status": status })))
}

#[derive(Deserialize)]
pub struct ReportQuery {
    pub framework: Option<String>,
    pub format: Option<String>,
}

/// `GET /api/v1/compliance/reports?framework=cis|soc2|pci&format=json|csv|zip`.
/// `zip` returns an Ed25519-signed incident bundle (verify with the pubkey in
/// the `X-Export-Pubkey` header). Cedar gates the `compliance` capability.
pub async fn compliance_reports(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Query(q): Query<ReportQuery>,
) -> ApiResult<Response> {
    if !s.authz.allows(&claims.features, "compliance") {
        return Err(ApiError::Forbidden("compliance"));
    }
    let framework = q.framework.unwrap_or_else(|| "cis".into());
    let format = q.format.unwrap_or_else(|| "json".into());
    let findings = s
        .store
        .list_findings(&claims.tenant, &FindingFilter::default())
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?;

    match format.as_str() {
        "json" => Ok(Json(json!({
            "framework": framework,
            "count": findings.len(),
            "findings": findings,
        }))
        .into_response()),
        "csv" => {
            let mut csv = String::from("id,severity,status,cloud,blastRadius,title\n");
            for f in &findings {
                csv.push_str(&format!(
                    "{},{:?},{},{},{},{}\n",
                    f.id,
                    f.severity,
                    f.status,
                    f.cloud.clone().unwrap_or_default(),
                    f.blast_radius,
                    f.title.replace(',', " "),
                ));
            }
            Ok(([(header::CONTENT_TYPE, "text/csv")], csv).into_response())
        }
        "zip" => {
            let findings_json = serde_json::to_string(&findings).unwrap_or_else(|_| "[]".into());
            let manifest = json!({
                "framework": framework,
                "policyVersion": "1",
                "generatedAt": now_unix(),
                "tenant": claims.tenant,
                "count": findings.len(),
            })
            .to_string();
            let bytes = s
                .export
                .build(&findings_json, &manifest)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            let pubkey = hex::encode(s.export.public_key());
            let mut resp = Response::new(Body::from(bytes));
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"),
            );
            if let Ok(v) = HeaderValue::from_str(&pubkey) {
                resp.headers_mut().insert("x-export-pubkey", v);
            }
            Ok(resp)
        }
        other => Err(ApiError::BadRequest(format!("unsupported format: {other}"))),
    }
}

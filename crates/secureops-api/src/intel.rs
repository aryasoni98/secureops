//! Intelligence + autonomy wiring (PRODUCT.md Phase 6b/7b): exposes the graph,
//! RL ranker, bug-hunt loop, and self-healing playbook engines over HTTP.
//!
//! Engine state lives in [`AppState`] (per-tenant, in-memory). Cloud mutations
//! for remediations go through a [`NoopCloud`] backend by default - it performs
//! no real changes, so approving a destructive playbook is safe out of the box;
//! real AWS/GCP/Azure backends slot in behind the same `CloudBackend` trait.

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use secureops_bughunt::{BugHunter, FindingReport, LocalProvider, NoTools};
use secureops_graph::{EdgeKind, NodeData, SecurityGraph};
use secureops_rl::{decayed_reward, Action, FindingFeatures, LinUcb};
use secureops_selfheal::{
    azure::AzureCloud, gcp::GcpCloud, sample_playbooks, Approval, CloudBackend, ExecState,
    Playbook, PlaybookClass, VecAudit,
};
use secureops_tokenbudget::{Evidence, EvidenceKind, TokenBudget};

use crate::auth::Authenticated;
use crate::error::{ApiError, ApiResult};
use crate::models::{Finding, Remediation, Severity};
use crate::state::AppState;
use crate::store::FindingFilter;

// ---------------------------------------------------------------------------
// Shared state types (referenced by AppState)
// ---------------------------------------------------------------------------

/// Stored result of a bug-hunt job (6b).
#[derive(Debug, Clone, Serialize)]
pub struct BugHuntJob {
    pub status: String,
    pub report: Option<FindingReport>,
    pub iterations: usize,
}

/// Default cloud backend: performs **no** real mutations (safe placeholder until
/// real provider backends are configured). Every step "succeeds" / is healthy.
pub struct NoopCloud;

#[async_trait]
impl CloudBackend for NoopCloud {
    async fn dry_run(&self, step: &str) -> anyhow::Result<String> {
        Ok(format!("noop dry_run: {step}"))
    }
    async fn snapshot(&self, _step: &str) -> anyhow::Result<String> {
        Ok("noop-snapshot".into())
    }
    async fn execute(&self, step: &str) -> anyhow::Result<String> {
        Ok(format!("noop execute (no real change): {step}"))
    }
    async fn health_check(&self, _step: &str) -> anyhow::Result<bool> {
        Ok(true)
    }
    async fn rollback(&self, _step: &str, _snapshot: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Resolve the right cloud backend for a playbook by looking at the `execute`
/// step's provider prefix (e.g. `gcs.bucket.set_acl` → GCP). Unhandled prefixes
/// fall back to the safe [`NoopCloud`] - no real mutations.
fn cloud_backend_for(pb: &Playbook) -> Box<dyn CloudBackend> {
    match pb.execute.split('.').next().unwrap_or("") {
        "gcs" | "gcp" => Box::new(GcpCloud::new()),
        "azure" => Box::new(AzureCloud::new()),
        _ => Box::new(NoopCloud),
    }
}

fn parse_finding_action(s: &str) -> Result<Action, ApiError> {
    match s {
        "confirm" => Ok(Action::Confirm),
        "escalate" => Ok(Action::Escalate),
        "dismiss" => Ok(Action::Dismiss),
        other => Err(ApiError::BadRequest(format!("unknown action: {other}"))),
    }
}

fn parse_playbook_class(s: &str) -> Result<PlaybookClass, ApiError> {
    match s {
        "safe" => Ok(PlaybookClass::Safe),
        "reversible" => Ok(PlaybookClass::Reversible),
        "destructive" => Ok(PlaybookClass::Destructive),
        other => Err(ApiError::BadRequest(format!("unknown class: {other}"))),
    }
}

fn exec_state_str(state: ExecState) -> &'static str {
    match state {
        ExecState::Completed => "completed",
        ExecState::RolledBack => "rolled_back",
        ExecState::Aborted => "aborted",
        ExecState::Failed => "failed",
    }
}

// ---------------------------------------------------------------------------
// RL feature mapping + ranking (used by routes::list_findings too)
// ---------------------------------------------------------------------------

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

fn cloud_index(cloud: Option<&str>) -> usize {
    match cloud {
        Some("aws") => 0,
        Some("gcp") => 1,
        Some("azure") => 2,
        _ => 3,
    }
}

/// Build the RL feature vector for a finding.
pub fn features_for(state: &AppState, f: &Finding) -> Vec<f32> {
    FindingFeatures {
        severity: severity_rank(f.severity),
        blast_radius_norm: (f.blast_radius as f32 / 100.0).clamp(0.0, 1.0),
        exposed_internet: false,
        rule_category: 0,
        cloud: cloud_index(f.cloud.as_deref()),
        recency_decay: 1.0,
    }
    .to_vec(&state.feature_spec)
}

/// Re-order findings by the tenant's LinUCB score (best first). If the tenant
/// has no trained model yet, the input order is preserved.
pub fn rank_findings(state: &AppState, tenant: &str, items: Vec<Finding>) -> Vec<Finding> {
    let ranker = state.ranker.lock().expect("ranker lock");
    match ranker.get(tenant) {
        Some(model) => {
            let feats: Vec<Vec<f32>> = items.iter().map(|f| features_for(state, f)).collect();
            model
                .rank(&feats)
                .into_iter()
                .map(|i| items[i].clone())
                .collect()
        }
        None => items,
    }
}

// ---------------------------------------------------------------------------
// Graph routes (6b)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct NodeSpec {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub exposed: bool,
    #[serde(default)]
    pub sensitive: bool,
}

fn default_difficulty() -> f32 {
    1.0
}

#[derive(Deserialize)]
pub struct EdgeSpec {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    #[serde(default = "default_difficulty")]
    pub difficulty: f32,
}

#[derive(Deserialize)]
pub struct GraphSpec {
    #[serde(default)]
    pub nodes: Vec<NodeSpec>,
    #[serde(default)]
    pub edges: Vec<EdgeSpec>,
}

/// `POST /api/v1/graph/rebuild` - ingest a topology (nodes + typed edges) for
/// the tenant. Later fed by the scanner; for now accepted directly.
pub async fn graph_rebuild(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Json(spec): Json<GraphSpec>,
) -> ApiResult<Json<Value>> {
    let mut g = SecurityGraph::new();
    for n in spec.nodes {
        let mut nd = NodeData::new(n.id, n.kind);
        nd.exposed = n.exposed;
        nd.sensitive = n.sensitive;
        g.add_node(nd);
    }
    for e in spec.edges {
        g.add_edge(e.from, e.to, e.kind, e.difficulty);
    }
    let nodes = g.node_count();
    s.graphs
        .lock()
        .expect("graphs lock")
        .insert(claims.tenant.clone(), g);
    Ok(Json(json!({ "nodes": nodes })))
}

/// `GET /api/v1/graph/paths` - attack paths (internet→sensitive), ranked.
pub async fn graph_paths(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
) -> ApiResult<Json<Value>> {
    let graphs = s.graphs.lock().expect("graphs lock");
    let paths = graphs
        .get(&claims.tenant)
        .map(|g| g.attack_paths())
        .unwrap_or_default();
    Ok(Json(json!({ "paths": paths })))
}

/// `GET /api/v1/graph/blast-radius/{node}` - sensitive nodes reachable if `node`
/// is compromised.
pub async fn graph_blast_radius(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Path(node): Path<String>,
) -> ApiResult<Json<Value>> {
    let graphs = s.graphs.lock().expect("graphs lock");
    let radius = graphs
        .get(&claims.tenant)
        .map(|g| g.blast_radius(&node))
        .unwrap_or(0);
    Ok(Json(json!({ "node": node, "blastRadius": radius })))
}

// ---------------------------------------------------------------------------
// RL routes (7b)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct FeedbackReq {
    pub severity: u8,
    #[serde(default)]
    pub blast_radius_norm: f32,
    #[serde(default)]
    pub exposed: bool,
    #[serde(default)]
    pub rule_category: usize,
    #[serde(default)]
    pub cloud: usize,
    #[serde(default = "default_difficulty")]
    pub recency: f32,
    pub action: String,
    #[serde(default)]
    pub finding_id: Option<String>,
}

/// `POST /api/v1/rl/feedback` - train the ranker from an analyst decision.
pub async fn rl_feedback(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Json(req): Json<FeedbackReq>,
) -> ApiResult<Json<Value>> {
    let action = parse_finding_action(&req.action)?;
    let feats = FindingFeatures {
        severity: req.severity.min(4),
        blast_radius_norm: req.blast_radius_norm,
        exposed_internet: req.exposed,
        rule_category: req.rule_category,
        cloud: req.cloud,
        recency_decay: req.recency,
    }
    .to_vec(&s.feature_spec);
    let reward = decayed_reward(action, 0.0);

    let updates = {
        let dim = s.feature_spec.dim();
        let mut ranker = s.ranker.lock().expect("ranker lock");
        let model = ranker
            .entry(claims.tenant.clone())
            .or_insert_with(|| LinUcb::new(dim, 0.1));
        model.update(&feats, reward);
        model.updates
    };
    // Persist the feedback event for offline retraining (best-effort).
    if let Err(e) = s
        .store
        .record_rl_feedback(
            &claims.tenant,
            req.finding_id.as_deref().unwrap_or(""),
            &req.action,
            reward as f64,
        )
        .await
    {
        tracing::warn!("rl_feedback persist failed (degraded): {e}");
    }
    Ok(Json(json!({ "updates": updates })))
}

/// `GET /api/v1/rl/stats` - ranker telemetry for the tenant.
pub async fn rl_stats(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
) -> ApiResult<Json<Value>> {
    let ranker = s.ranker.lock().expect("ranker lock");
    let updates = ranker.get(&claims.tenant).map(|m| m.updates).unwrap_or(0);
    Ok(Json(json!({
        "updates": updates,
        "dim": s.feature_spec.dim(),
        "alpha": 0.1,
    })))
}

// ---------------------------------------------------------------------------
// Bug-hunt routes (6b)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct BugHuntReq {
    pub scope: String,
}

/// `POST /api/v1/bughunt` - run a bounded bug-hunt over the tenant's findings
/// using the offline LocalProvider, store the result, return a job id. Cedar
/// gates the `bughunt` capability (Community → 403).
pub async fn bughunt_run(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Json(req): Json<BugHuntReq>,
) -> ApiResult<Json<Value>> {
    if !s.authz.allows(&claims.features, "bughunt") {
        return Err(ApiError::Forbidden("bughunt"));
    }
    let findings = s
        .store
        .list_findings(&claims.tenant, &FindingFilter::default())
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?;
    let evidence: Vec<Evidence> = findings
        .iter()
        .map(|f| {
            Evidence::new(
                EvidenceKind::Finding,
                format!(
                    "{} [{:?}] {}",
                    f.title,
                    f.severity,
                    f.cloud.clone().unwrap_or_default()
                ),
                0.8,
            )
        })
        .collect();

    let budget = TokenBudget::new("local", 8000, 1000);
    let hunter = BugHunter::new(LocalProvider, budget);
    let outcome = hunter.hunt(&req.scope, evidence, &NoTools).await;

    let job_id = Uuid::new_v4();
    let job = BugHuntJob {
        status: format!("{:?}", outcome.status).to_lowercase(),
        report: outcome.report,
        iterations: outcome.iterations,
    };
    let status = job.status.clone();
    s.bughunt_jobs
        .lock()
        .expect("jobs lock")
        .insert(job_id, job);
    Ok(Json(json!({ "jobId": job_id, "status": status })))
}

/// `GET /api/v1/bughunt/{job_id}` - fetch a stored bug-hunt result.
pub async fn bughunt_get(
    State(s): State<AppState>,
    Authenticated(_claims): Authenticated,
    Path(job_id): Path<Uuid>,
) -> ApiResult<Json<BugHuntJob>> {
    s.bughunt_jobs
        .lock()
        .expect("jobs lock")
        .get(&job_id)
        .cloned()
        .map(Json)
        .ok_or(ApiError::NotFound)
}

// ---------------------------------------------------------------------------
// Remediation routes (7b)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RemediationReq {
    pub finding_id: String,
    pub playbook_id: String,
}

/// `POST /api/v1/remediations` - queue a remediation for a finding (persisted).
pub async fn remediation_create(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Json(req): Json<RemediationReq>,
) -> ApiResult<Json<Remediation>> {
    let pb = sample_playbooks()
        .into_iter()
        .find(|p| p.id == req.playbook_id)
        .ok_or(ApiError::NotFound)?;
    let rem = Remediation {
        id: Uuid::new_v4(),
        finding_id: req.finding_id,
        playbook_id: pb.id.clone(),
        class: format!("{:?}", pb.class).to_lowercase(),
        state: "pending".into(),
    };
    s.store
        .insert_remediation(&claims.tenant, &rem)
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?;
    s.hub.publish(
        json!({ "event": "remediation.queued", "id": rem.id, "class": rem.class }).to_string(),
    );
    Ok(Json(rem))
}

/// `POST /api/v1/remediations/circuit/{class}/reset` - operator-only reset of
/// a halted playbook class. `class` is one of `safe|reversible|destructive`.
pub async fn remediation_circuit_reset(
    State(s): State<AppState>,
    Authenticated(_claims): Authenticated,
    Path(class): Path<String>,
) -> ApiResult<Json<Value>> {
    let pc = parse_playbook_class(&class)?;
    s.heal.breaker.reset(pc);
    Ok(Json(json!({ "class": class, "halted": false })))
}

/// `GET /api/v1/remediations/queue` - the tenant's remediation queue.
pub async fn remediations_queue(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
) -> ApiResult<Json<Value>> {
    let items = s
        .store
        .list_remediations(&claims.tenant)
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?;
    Ok(Json(json!({ "remediations": items })))
}

/// `POST /api/v1/remediations/{id}/approve` - approve + run a queued remediation
/// through the self-healing engine (NoopCloud by default - no real mutation).
pub async fn remediation_approve(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let rem = s
        .store
        .list_remediations(&claims.tenant)
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or(ApiError::NotFound)?;
    let pb = sample_playbooks()
        .into_iter()
        .find(|p| p.id == rem.playbook_id)
        .ok_or(ApiError::NotFound)?;

    let audit = VecAudit::new();
    let backend = cloud_backend_for(&pb);
    let outcome = s
        .heal
        .run(
            &pb,
            backend.as_ref(),
            Some(Approval::Approved {
                by: claims.sub.clone(),
            }),
            &audit,
        )
        .await;
    let state_str = exec_state_str(outcome.state);
    s.hub.publish(
        json!({ "event": "remediation.completed", "id": id, "state": state_str }).to_string(),
    );

    s.store
        .set_remediation_state(&claims.tenant, id, state_str)
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?;
    Ok(Json(
        json!({ "id": id, "state": state_str, "executed": outcome.executed }),
    ))
}

/// `POST /api/v1/remediations/{id}/deny` - deny a queued remediation (never runs).
pub async fn remediation_deny(
    State(s): State<AppState>,
    Authenticated(claims): Authenticated,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let updated = s
        .store
        .set_remediation_state(&claims.tenant, id, "aborted")
        .await
        .map_err(|e| ApiError::Store(e.to_string()))?;
    if !updated {
        return Err(ApiError::NotFound);
    }
    s.hub.publish(
        json!({ "event": "remediation.denied", "id": id, "state": "aborted" }).to_string(),
    );
    Ok(Json(json!({ "id": id, "state": "aborted" })))
}

//! Wire models for the platform API (PRODUCT.md Phase 5).
//!
//! All structs are `camelCase` on the wire for consistency with the rest of the
//! tool, and derive `utoipa::ToSchema` so they appear in the generated OpenAPI.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Lifecycle of a scan job (Redis queue → scanner worker → terminal state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

/// A cloud/asset scan job.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Scan {
    pub id: Uuid,
    pub tenant_id: String,
    /// `"all" | "aws" | "gcp" | "azure" | <asset_id>` (PRODUCT.md Phase 5).
    pub scope: String,
    /// `"scan" | "bughunt"` — the job kind (bug-hunt logic lands in P6).
    pub kind: String,
    pub status: ScanStatus,
    /// Unix seconds.
    pub created_at: i64,
}

/// Finding severity (camelCase wire; mirrors `secureops_core::Severity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A security finding surfaced by a scan (RL-ranked in P7, graphed in P6).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: Uuid,
    pub tenant_id: String,
    pub scan_id: Option<Uuid>,
    pub title: String,
    pub severity: Severity,
    /// `"open" | "confirmed" | "dismissed" | "escalated"`.
    pub status: String,
    pub cloud: Option<String>,
    /// Reachable sensitive nodes if this asset is compromised (filled by P6).
    pub blast_radius: i64,
}

/// A queued/finished self-healing remediation (Phase 7b). Persisted via the
/// `Store` so HITL state survives restarts and is shared across replicas.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Remediation {
    pub id: Uuid,
    pub finding_id: String,
    pub playbook_id: String,
    /// `safe | reversible | destructive`.
    pub class: String,
    /// `pending | completed | rolled_back | aborted | failed`.
    pub state: String,
}

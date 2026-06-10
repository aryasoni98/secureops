//! The `Check` trait and the `run_audit` orchestrator.
//!
//! In the TS tool each audit *category* (`auditGateway`, `auditCredentials`, …)
//! is one async function returning `AuditFinding[]`. Here that becomes one
//! `Check` impl per category (PRODUCT.md A.4: "one Check impl per audit* fn"),
//! living in the `secureops-checks` crate.

use crate::context::AuditContext;
use crate::scoring::{calculate_score, compute_summary, cross_layer_risk};
use crate::types::{AuditFinding, AuditReport};
use async_trait::async_trait;

/// Options for running an audit (port of `AuditOptions`, minus `context` which
/// is passed explicitly).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditOptions {
    pub deep: bool,
    pub fix: bool,
    pub json: bool,
}

/// One audit category. Implementors live in `secureops-checks`.
#[async_trait]
pub trait Check: Send + Sync {
    /// Stable category id (e.g. `"gateway"`), used for logging/diagnostics.
    fn category(&self) -> &'static str;

    /// Run the category against the context, returning zero or more findings.
    ///
    /// A check must never panic the run: the orchestrator isolates failures,
    /// but checks should also degrade to an INFO finding on missing inputs
    /// (mirrors the TS "the run never aborts" guarantee, PRODUCT.md B.2).
    async fn run(&self, ctx: &dyn AuditContext, opts: &AuditOptions) -> Vec<AuditFinding>;
}

/// Run every check against `ctx`, append the MAESTRO cross-layer compound-risk
/// finding, then score and summarize - the faithful port of `runAudit`.
///
/// `timestamp` is injected (RFC3339) rather than read from a clock here so this
/// stays pure and deterministic; callers stamp `new Date().toISOString()`'s
/// equivalent. Findings are concatenated in `checks` order, matching the fixed
/// category order of the TS `Promise.all` aggregation.
pub async fn run_audit(
    ctx: &dyn AuditContext,
    checks: &[Box<dyn Check>],
    opts: &AuditOptions,
    timestamp: String,
    secureops_version: &str,
) -> AuditReport {
    let mut findings: Vec<AuditFinding> = Vec::new();
    for check in checks {
        findings.extend(check.run(ctx, opts).await);
    }

    // Cross-layer threat detection runs after all checks (PRODUCT.md B.2).
    let cross = cross_layer_risk(&findings);
    findings.extend(cross);

    let score = calculate_score(&findings);
    let summary = compute_summary(&findings);

    AuditReport {
        timestamp,
        openclaw_version: ctx.openclaw_version().to_string(),
        secureops_version: secureops_version.to_string(),
        platform: ctx.platform().to_string(),
        deployment_mode: ctx.deployment_mode().to_string(),
        score,
        findings,
        summary,
    }
}

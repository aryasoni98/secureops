//! # secureops-napi
//!
//! The **Ring 1** in-process engine surface (PRODUCT.md A.2, Part G Phase 1:
//! *"Rust core behind napi"*). This crate is built as a Node native addon
//! (`crate-type = ["cdylib", "rlib"]`) and loaded by a thin TypeScript shim that
//! replaces the legacy `@adversa/secureops` audit body with a single FFI call.
//!
//! ## Why a plain-Rust seam
//!
//! The actual `#[napi]` wrappers (provided by `napi-derive`) are intentionally
//! *not* compiled in this scaffold — the `napi` / `napi-derive` / `napi-build`
//! crates require a Node toolchain and pull a large native build, which would
//! break the offline-fast workspace build. So the public functions here are
//! ordinary Rust (`String`-in / `String`-out, JSON on the wire). Each is annotated
//! with the `#[napi]` attribute it *will* carry once Phase 1 wiring lands, e.g.:
//!
//! ```ignore
//! #[napi]
//! pub async fn audit_to_json(state_dir: String, deep: bool, fix: bool) -> napi::Result<String> {
//!     Ok(crate::audit_to_json(state_dir, deep, fix).await)
//! }
//! ```
//!
//! Keeping the logic in plain functions means the standalone `clap` binary
//! (`secureops-cli`) and unit tests can drive the identical code path without
//! Node, and the FFI layer stays a thin, generated shim.
//!
//! The full OpenClaw plugin surface (lifecycle hooks, command dispatch, MCP
//! tools — the TS `legacyPlugin`) is ported in [`plugin`]; the TS shim wires
//! OpenClaw's callbacks to those functions.
//!
//! ## Trust model (PRODUCT.md A.2)
//!
//! Ring 1 shares the agent's fate: it gives fast, in-context audit + monitoring
//! while the host process is healthy but provides **no enforcement**. Enforcement
//! lives in the Ring 2 daemon. This addon's job is *feedback and convenience*.
//!
//! ## Wire-format contract (PRODUCT.md A.5 / A.3)
//!
//! Everything crossing the FFI boundary is JSON produced by
//! [`secureops_core::AuditReport::to_json_pretty`], so the shim and a future
//! Rust daemon read/write byte-compatible `<stateDir>/.secureops/` artifacts.
//! Treat the JSON field names as frozen.

#![forbid(unsafe_code)]

pub mod napi_surface;
pub mod plugin;

use secureops_core::{run_audit, AuditOptions, AuditReport, Check, OpenClawConfig};
use std::sync::Arc;

/// SecureOps report version surfaced to the TS shim (becomes `secureopsVersion`
/// in the emitted [`AuditReport`]). Matches the TS tool's hardcoded value so the
/// JSON wire output is identical regardless of which side produced it.
pub const SECUREOPS_VERSION: &str = "2.2.0";

/// Bundled IOC database (same asset the CLI embeds), so the Ring-1 audit path
/// matches the CLI's IOC coverage.
pub(crate) const BUNDLED_IOC: &str = include_str!("../../secureops-cli/assets/indicators.json");

pub(crate) use secureops_core::now_iso;

pub(crate) fn load_config(state_dir: &str) -> OpenClawConfig {
    let content = std::fs::read_to_string(format!("{state_dir}/openclaw.json")).unwrap_or_default();
    OpenClawConfig::from_json_or_default(&content)
}

/// Run a full read-only audit and return the report as pretty JSON.
///
/// This is the primary Ring 1 entrypoint (PRODUCT.md B.2 *Audit*). In the
/// Phase 1 build it is wrapped by a `#[napi] pub async fn` so the TS shim can
/// `await secureops.auditToJson(stateDir, deep, fix)` in place of its legacy
/// audit body.
///
/// Pipeline it will drive (PRODUCT.md B.2):
/// 1. build an `Arc<dyn AuditContext>` from [`secureops_fs`] (real `tokio::fs`),
/// 2. assemble the [`Check`] registry from [`secureops_checks`],
/// 3. call [`secureops_core::run_audit`] (panicking checks degrade to INFO,
///    the run never aborts),
/// 4. serialize via [`AuditReport::to_json_pretty`].
///
/// # Wire shape
/// Returns the JSON of an [`AuditReport`]; on a fatal harness error it returns a
/// JSON error envelope (never panics across the FFI boundary).
///
/// Future FFI signature:
/// ```ignore
/// #[napi]
/// pub async fn audit_to_json(state_dir: String, deep: bool, fix: bool) -> napi::Result<String>;
/// ```
pub async fn audit_to_json(state_dir: String, deep: bool, fix: bool) -> String {
    let opts = AuditOptions {
        deep,
        fix,
        json: true,
    };
    run_audit_report(&state_dir, &opts).await.to_json_pretty()
}

/// Run the audit and return the structured [`AuditReport`] (no serialization).
///
/// Internal seam shared by [`audit_to_json`] and the standalone CLI so both go
/// through one code path. Splitting JSON encoding out keeps the FFI wrapper a
/// trivial `to_json_pretty` call and lets the CLI render a human console report
/// from the same value.
pub async fn run_audit_report(state_dir: &str, opts: &AuditOptions) -> AuditReport {
    let config = load_config(state_dir);
    let ctx = secureops_fs::RealAuditContext::for_host(
        state_dir.to_string(),
        config,
        "native",
        "unknown",
    );
    let checks = default_check_registry();
    run_audit(&ctx, &checks, opts, now_iso(), SECUREOPS_VERSION).await
}

/// Build the default [`Check`] registry (one boxed impl per audit category).
///
/// Mirrors the TS tool's check set (PRODUCT.md B.2 step 2). The concrete impls
/// live in [`secureops_checks`]; this scaffold just declares the seam the FFI
/// and CLI consume.
pub fn default_check_registry() -> Vec<Box<dyn Check>> {
    let ioc = Arc::new(secureops_intel::load_from_str(BUNDLED_IOC));
    secureops_checks::default_checks(ioc)
}

/// JSON of the current SecureOps IOC database version metadata, for the shim's
/// `--version` / health output (PRODUCT.md B.1 step 4 bundled IOC DB).
///
/// Future FFI signature: `#[napi] pub fn ioc_db_info() -> napi::Result<String>;`
pub fn ioc_db_info() -> String {
    let db = secureops_intel::load_from_str(BUNDLED_IOC);
    serde_json::json!({
        "version": db.version,
        "lastUpdated": db.last_updated,
        "c2Ips": db.c2_ips.len(),
        "maliciousDomains": db.malicious_domains.len(),
        "maliciousSkillHashes": db.malicious_skill_hashes.len(),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_constant_is_populated() {
        assert!(!SECUREOPS_VERSION.is_empty());
    }

    #[test]
    fn audit_options_defaults_are_read_only() {
        let opts = AuditOptions::default();
        assert!(!opts.deep);
        assert!(!opts.fix);
    }

    #[test]
    fn ioc_db_info_is_valid_json_with_version() {
        let v: serde_json::Value = serde_json::from_str(&ioc_db_info()).unwrap();
        assert!(v.get("version").is_some());
        assert!(v.get("c2Ips").is_some());
    }

    #[tokio::test]
    async fn audit_to_json_emits_report() {
        let dir = tempfile::tempdir().unwrap();
        let json = audit_to_json(dir.path().to_string_lossy().to_string(), false, false).await;
        let report: AuditReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.secureops_version, "2.2.0");
        assert!(report.score <= 100);
    }
}

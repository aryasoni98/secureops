//! # secureops-checks
//!
//! One [`Check`] impl per audit *category* — the faithful Rust targets for the
//! 56 `SC-*` checks of the TypeScript tool (PRODUCT.md **A.4** "one Check impl
//! per audit\* fn", **B.2** the audit run model).
//!
//! In `secureops/src/auditor.ts` each category is a single async function
//! (`auditGateway`, `auditCredentials`, …) returning `AuditFinding[]`. Here each
//! becomes a struct implementing [`Check`], grouped one module per category, with
//! the audit logic ported faithfully — same `SC-*` ids, severities, MAESTRO
//! layers, NIST categories and finding text as the TS source. The 55 category
//! findings plus `SC-CROSS-001` (applied by [`secureops_core::run_audit`]) make
//! up the 56 checks.
//!
//! ## Category order (PRODUCT.md B.2)
//!
//! [`default_checks`] returns the nine checks in the exact order the TS
//! `runAudit` aggregates them. Order is load-bearing: `run_audit` concatenates
//! findings in `checks` order, so the JSON wire output must match the TS tool.
//!
//! 1. [`gateway`] — `GatewayCheck` (`auditGateway`)
//! 2. [`credentials`] — `CredentialsCheck` (`auditCredentials`)
//! 3. [`execution`] — `ExecutionCheck` (`auditExecution`)
//! 4. [`access_control`] — `AccessControlCheck` (`auditAccessControl`)
//! 5. [`supply_chain`] — `SupplyChainCheck` (`auditSupplyChain`)
//! 6. [`memory_integrity`] — `MemoryIntegrityCheck` (`auditMemoryIntegrity`)
//! 7. [`cost_exposure`] — `CostExposureCheck` (`auditCostExposure`)
//! 8. [`ioc`] — `IocCheck` (`auditIOC`)
//! 9. [`multi_framework`] — `MultiFrameworkCheck` (`auditMultiFramework`)
//!
//! The MAESTRO cross-layer compound-risk pass is *not* a `Check`; it is applied
//! by [`secureops_core::run_audit`] after all checks, via
//! [`secureops_core::cross_layer_risk`].

#![forbid(unsafe_code)]

pub mod access_control;
pub mod cost_exposure;
pub mod credentials;
pub mod execution;
pub mod gateway;
pub mod ioc;
pub mod memory_integrity;
pub mod mock;
pub mod multi_framework;
pub mod patterns;
pub mod supply_chain;

pub use access_control::AccessControlCheck;
pub use cost_exposure::CostExposureCheck;
pub use credentials::CredentialsCheck;
pub use execution::ExecutionCheck;
pub use gateway::GatewayCheck;
pub use ioc::IocCheck;
pub use memory_integrity::MemoryIntegrityCheck;
pub use multi_framework::MultiFrameworkCheck;
pub use supply_chain::SupplyChainCheck;

use secureops_core::{Check, IocDatabase};
use std::sync::Arc;

/// All nine category checks, in the fixed TS `runAudit` order (PRODUCT.md B.2).
///
/// Every check is constructed with a shared [`IocDatabase`] handle (loaded once
/// by the I/O layer — `secureops-fs` / `secureops-cli`). Checks that don't
/// consult the IOC database simply ignore it, keeping the constructor uniform
/// and `core`/`checks` free of file I/O (PRODUCT.md A.4).
///
/// Pass straight to [`secureops_core::run_audit`]:
///
/// ```ignore
/// use secureops_checks::default_checks;
/// use std::sync::Arc;
/// let checks = default_checks(Arc::new(ioc_db));
/// let report = secureops_core::run_audit(&ctx, &checks, &opts, ts, version).await;
/// ```
pub fn default_checks(ioc_db: Arc<IocDatabase>) -> Vec<Box<dyn Check>> {
    vec![
        Box::new(GatewayCheck::new(ioc_db.clone())),
        Box::new(CredentialsCheck::new(ioc_db.clone())),
        Box::new(ExecutionCheck::new(ioc_db.clone())),
        Box::new(AccessControlCheck::new(ioc_db.clone())),
        Box::new(SupplyChainCheck::new(ioc_db.clone())),
        Box::new(MemoryIntegrityCheck::new(ioc_db.clone())),
        Box::new(CostExposureCheck::new(ioc_db.clone())),
        Box::new(IocCheck::new(ioc_db.clone())),
        Box::new(MultiFrameworkCheck::new(ioc_db)),
    ]
}

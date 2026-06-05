//! # secureops-core
//!
//! The shared, I/O-free heart of SecureOps. It holds:
//!
//! - the **type model** ([`types`]) — `AuditFinding`, `Severity`, `AuditReport`, …
//! - the **OpenClaw config tree** ([`config`]) it audits
//! - the **`AuditContext`** trait ([`context`]) — dependency injection for all
//!   filesystem / environment access, so checks stay unit-testable against a mock
//! - the **`Check`** trait ([`check`]) — one impl per audit category
//! - **scoring** ([`scoring`]) — the faithful port of `calculateScore`,
//!   `computeSummary` and the MAESTRO cross-layer compound-risk pass
//! - **IOC / runtime** value types ([`ioc`], [`runtime`]) shared by the
//!   intel, monitors and daemon crates
//!
//! ## Wire-format contract (PRODUCT.md A.5)
//!
//! The JSON emitted here must stay **byte-compatible** with the TypeScript tool
//! for the whole migration window: both a TS shim and a Rust daemon may read and
//! write the same `<stateDir>/.secureops/` files. Every serialized struct is
//! `#[serde(rename_all = "camelCase")]` (or an explicit case) to match the TS
//! field names exactly. Treat the field names as frozen.

#![forbid(unsafe_code)]

pub mod check;
pub mod config;
pub mod context;
pub mod ioc;
pub mod patterns;
pub mod runtime;
pub mod scoring;
pub mod types;
pub mod util;

pub use check::*;
pub use config::*;
pub use context::*;
pub use ioc::*;
pub use patterns::*;
pub use runtime::*;
pub use scoring::*;
pub use types::*;
pub use util::*;

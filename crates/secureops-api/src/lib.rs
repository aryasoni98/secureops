//! # secureops-api - SecureOps platform HTTP API (PRODUCT.md Phase 5)
//!
//! An axum service exposing the multi-cloud security platform over REST +
//! WebSocket. It is the front door for the platform tier (the CLI/daemon remain
//! the host-local enforcement surface):
//!
//! - **License activation** - Ed25519-verified keys gate tiers/features ([`license`]).
//! - **Auth** - dual JWT (HMAC) + per-tenant API key, hashed at rest ([`auth`]).
//! - **Authorization** - Cedar policy gates every tier-locked capability ([`authz`]).
//! - **Realtime** - a `tokio::broadcast` hub fans findings/scan progress to WS clients ([`ws`]).
//! - **Storage** - a [`store::Store`] trait over Postgres (prod) / in-memory (test).
//!
//! Handlers depend on the [`AppState`] only, so the whole surface unit-tests
//! against an in-memory store with no external infrastructure.

#![forbid(unsafe_code)]

pub mod auth;
pub mod authz;
pub mod error;
pub mod evidence;
pub mod export;
pub mod health;
pub mod intel;
pub mod license;
pub mod models;
pub mod redis_queue;
pub mod router;
pub mod routes;
pub mod sso;
pub mod store;
pub mod ws;

pub use error::{ApiError, ApiResult};
pub use router::{build_router, with_spa};
pub use state::AppState;

/// Lock a mutex, recovering from poisoning instead of panicking.
///
/// A poisoned mutex means some earlier handler panicked while holding it; the
/// shared maps guarded here (graphs/ranker/jobs/in-memory store) stay usable
/// after such a panic, so recovering the guard keeps the API serving instead of
/// turning one panic into a panic on every subsequent request.
pub(crate) fn lock_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub mod state {
    //! Shared application state injected into every handler.
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use secureops_graph::SecurityGraph;
    use secureops_rl::{FeatureSpec, LinUcb};
    use secureops_selfheal::PlaybookEngine;
    use uuid::Uuid;

    use crate::authz::PolicyEngine;
    use crate::evidence::S3Presigner;
    use crate::intel::BugHuntJob;
    use crate::redis_queue::RedisQueue;
    use crate::store::Store;
    use crate::ws::Hub;

    /// Cloneable handle to all shared services. `Clone` is cheap - everything is
    /// behind an `Arc` or a pool handle.
    #[derive(Clone)]
    pub struct AppState {
        /// The backing store (Postgres in prod, in-memory in tests).
        pub store: Arc<dyn Store>,
        /// Cedar authorization engine (tier/feature gating).
        pub authz: Arc<PolicyEngine>,
        /// Realtime fan-out hub for `/ws/*`.
        pub hub: Hub,
        /// HMAC secret for issuing/verifying session JWTs.
        pub jwt_secret: Arc<str>,
        /// Ed25519 public key (32 bytes) that valid license keys are signed by.
        pub license_pubkey: [u8; 32],
        /// Redis scan-job queue (5b). `None` → enqueue is skipped (degraded).
        pub redis: Option<RedisQueue>,
        /// S3/MinIO evidence presigner (5b). `None` → presign endpoints disabled.
        pub evidence: Option<S3Presigner>,
        /// Per-tenant security knowledge graph (6b).
        pub graphs: Arc<Mutex<HashMap<String, SecurityGraph>>>,
        /// Per-tenant LinUCB finding ranker (7b).
        pub ranker: Arc<Mutex<HashMap<String, LinUcb>>>,
        /// Feature-vector layout for the ranker.
        pub feature_spec: FeatureSpec,
        /// Bug-hunt job results keyed by job id (6b).
        pub bughunt_jobs: Arc<Mutex<HashMap<Uuid, BugHuntJob>>>,
        /// Self-healing playbook engine (7b). Remediation state persists via the [`Store`].
        pub heal: Arc<PlaybookEngine>,
        /// Ed25519 signer for incident-report exports (P8).
        pub export: Arc<crate::export::IncidentExport>,
        /// OIDC verifier (P8). `None` → SSO not configured (callback → 404).
        pub oidc: Option<Arc<dyn crate::sso::OidcVerifier>>,
    }

    impl AppState {
        /// Construct state from its core parts (storage backends added via
        /// [`AppState::with_redis`] / [`AppState::with_evidence`]).
        pub fn new(
            store: Arc<dyn Store>,
            authz: Arc<PolicyEngine>,
            jwt_secret: impl Into<Arc<str>>,
            license_pubkey: [u8; 32],
        ) -> Self {
            Self {
                store,
                authz,
                hub: Hub::new(),
                jwt_secret: jwt_secret.into(),
                license_pubkey,
                redis: None,
                evidence: None,
                graphs: Arc::new(Mutex::new(HashMap::new())),
                ranker: Arc::new(Mutex::new(HashMap::new())),
                feature_spec: FeatureSpec {
                    n_rule_categories: 16,
                    n_clouds: 4,
                },
                bughunt_jobs: Arc::new(Mutex::new(HashMap::new())),
                heal: Arc::new(PlaybookEngine::new()),
                export: Arc::new(crate::export::IncidentExport::from_seed([9u8; 32])),
                oidc: None,
            }
        }

        /// Replace the export signer (e.g. with a key from a Secret/keystore).
        pub fn with_export(mut self, export: crate::export::IncidentExport) -> Self {
            self.export = std::sync::Arc::new(export);
            self
        }

        /// Attach an OIDC verifier (enables the SSO callback).
        pub fn with_oidc(mut self, verifier: Arc<dyn crate::sso::OidcVerifier>) -> Self {
            self.oidc = Some(verifier);
            self
        }

        /// Attach a Redis scan-job queue.
        pub fn with_redis(mut self, redis: RedisQueue) -> Self {
            self.redis = Some(redis);
            self
        }

        /// Attach an S3/MinIO evidence presigner.
        pub fn with_evidence(mut self, evidence: S3Presigner) -> Self {
            self.evidence = Some(evidence);
            self
        }
    }
}

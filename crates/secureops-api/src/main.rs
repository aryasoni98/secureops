//! `secureops-api` binary — boots the platform HTTP API (PRODUCT.md Phase 5).
//!
//! Config (env):
//! - `SECUREOPS_API_ADDR` — listen addr (default `0.0.0.0:8080`).
//! - `SECUREOPS_JWT_SECRET` — HMAC secret for session JWTs (dev default if unset).
//! - `SECUREOPS_LICENSE_PUBKEY` — base64url 32-byte Ed25519 vendor public key.
//! - `DATABASE_URL` — Postgres DSN; migrations run on boot. Unset → in-memory store.
//! - `REDIS_URL` — Redis DSN for the scan queue (degraded if unset/unreachable).
//! - `MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD` (+ `S3_ENDPOINT`/`AWS_REGION`/`S3_SCHEME`)
//!   — enable the evidence presigner.

#![forbid(unsafe_code)]

use std::sync::Arc;

use base64::Engine as _;
use secureops_api::authz::PolicyEngine;
use secureops_api::evidence::S3Presigner;
use secureops_api::redis_queue::RedisQueue;
use secureops_api::store::pg::PgStore;
use secureops_api::store::{InMemoryStore, Store};
use secureops_api::{build_router, AppState};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let jwt_secret =
        std::env::var("SECUREOPS_JWT_SECRET").unwrap_or_else(|_| "dev-insecure-secret".into());
    let license_pubkey = load_license_pubkey();
    let authz = Arc::new(PolicyEngine::default());

    // Storage: Postgres when DATABASE_URL is set (migrations applied on boot),
    // else an in-memory store for local/dev.
    let store: Arc<dyn Store> = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => {
            let pg = PgStore::connect(&url).await?;
            pg.migrate().await?;
            tracing::info!("postgres store ready (migrations applied)");
            Arc::new(pg)
        }
        _ => {
            tracing::warn!("DATABASE_URL unset — using in-memory store (non-persistent)");
            Arc::new(InMemoryStore::new())
        }
    };

    let mut state = AppState::new(store, authz, jwt_secret, license_pubkey);

    if let Ok(url) = std::env::var("REDIS_URL") {
        if !url.is_empty() {
            match RedisQueue::from_url(&url) {
                Ok(q) => {
                    state = state.with_redis(q);
                    tracing::info!("redis scan queue wired");
                }
                Err(e) => tracing::warn!("redis unavailable ({e}); scans run in degraded mode"),
            }
        }
    }

    if let (Ok(ak), Ok(sk)) = (
        std::env::var("MINIO_ROOT_USER"),
        std::env::var("MINIO_ROOT_PASSWORD"),
    ) {
        let host = std::env::var("S3_ENDPOINT").unwrap_or_else(|_| "minio:9000".into());
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into());
        let scheme = std::env::var("S3_SCHEME").unwrap_or_else(|_| "http".into());
        state = state.with_evidence(S3Presigner::new(ak, sk, region, host, scheme));
        tracing::info!("evidence presigner wired");
    }

    let addr = std::env::var("SECUREOPS_API_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("secureops-api listening on {addr}");
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

/// Load the vendor Ed25519 public key from env, or fall back to the dev key
/// (public half of the deterministic `[7u8; 32]` seed). Dev key is local-only.
fn load_license_pubkey() -> [u8; 32] {
    if let Ok(b64) = std::env::var("SECUREOPS_LICENSE_PUBKEY") {
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64) {
            Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(arr) => return arr,
                Err(_) => tracing::warn!("SECUREOPS_LICENSE_PUBKEY is not 32 bytes; using dev key"),
            },
            Err(_) => {
                tracing::warn!("SECUREOPS_LICENSE_PUBKEY is not valid base64url; using dev key")
            }
        }
    }
    ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
        .verifying_key()
        .to_bytes()
}

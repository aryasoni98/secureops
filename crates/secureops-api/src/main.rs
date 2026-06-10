//! `secureops-api` binary - boots the platform HTTP API (PRODUCT.md Phase 5).
//!
//! Config (env):
//! - `SECUREOPS_API_ADDR` - listen addr (default `127.0.0.1:8080`; set
//!   `0.0.0.0:8080` explicitly for containers).
//! - `SECUREOPS_JWT_SECRET` - HMAC secret for session JWTs (required unless
//!   `SECUREOPS_DEV_MODE=1`).
//! - `SECUREOPS_LICENSE_PUBKEY` - base64url 32-byte Ed25519 vendor public key
//!   (required unless `SECUREOPS_DEV_MODE=1`).
//! - `SECUREOPS_DEV_MODE` - set to `1` to accept insecure local-only defaults
//!   for the two secrets above. Never set in production.
//! - `SECUREOPS_CORS_ORIGINS` - comma-separated browser origins allowed to call
//!   the API cross-origin. Unset → no CORS headers (same-origin only).
//! - `DATABASE_URL` - Postgres DSN; migrations run on boot. Unset → in-memory store.
//! - `REDIS_URL` - Redis DSN for the scan queue (degraded if unset/unreachable).
//! - `MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD` (+ `S3_ENDPOINT`/`AWS_REGION`/`S3_SCHEME`)
//!   - enable the evidence presigner.

#![forbid(unsafe_code)]

use std::sync::Arc;

use base64::Engine as _;
use secureops_api::authz::PolicyEngine;
use secureops_api::evidence::S3Presigner;
use secureops_api::redis_queue::RedisQueue;
use secureops_api::store::pg::PgStore;
use secureops_api::store::{InMemoryStore, Store};
use secureops_api::{build_router, with_spa, AppState};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let dev_mode = dev_mode();
    let jwt_secret = match std::env::var("SECUREOPS_JWT_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ if dev_mode => {
            tracing::warn!(
                "SECUREOPS_JWT_SECRET unset - using insecure dev secret (SECUREOPS_DEV_MODE=1)"
            );
            "dev-insecure-secret".into()
        }
        _ => anyhow::bail!(
            "SECUREOPS_JWT_SECRET is required (generate with `openssl rand -hex 32`). \
             For local development only, set SECUREOPS_DEV_MODE=1 to accept an insecure default."
        ),
    };
    let license_pubkey = load_license_pubkey(dev_mode)?;
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
            tracing::warn!("DATABASE_URL unset - using in-memory store (non-persistent)");
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

    // Optionally embed the built dashboard SPA (PRODUCT.md Phase 8).
    let spa_store = state.store.clone();
    let mut app = build_router(state);
    if let Ok(dir) = std::env::var("SECUREOPS_WEB_DIR") {
        if !dir.is_empty() {
            tracing::info!("serving dashboard SPA from {dir}");
            app = with_spa(app, &dir, spa_store);
        }
    }

    // Cross-origin access is opt-in via an explicit origin allowlist; without
    // it the API emits no CORS headers (same-origin / embedded SPA only).
    if let Ok(origins) = std::env::var("SECUREOPS_CORS_ORIGINS") {
        if !origins.is_empty() {
            app = app.layer(cors_layer(&origins)?);
            tracing::info!("CORS enabled for origins: {origins}");
        }
    }

    let addr = std::env::var("SECUREOPS_API_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("secureops-api listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// True when `SECUREOPS_DEV_MODE` opts into insecure local-only defaults.
fn dev_mode() -> bool {
    std::env::var("SECUREOPS_DEV_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Load the vendor Ed25519 public key from env. A malformed value is always a
/// hard error (never silently downgraded); an unset value falls back to the
/// dev key (public half of the deterministic `[7u8; 32]` seed) only when
/// `SECUREOPS_DEV_MODE=1`.
fn load_license_pubkey(dev_mode: bool) -> anyhow::Result<[u8; 32]> {
    match std::env::var("SECUREOPS_LICENSE_PUBKEY") {
        Ok(b64) if !b64.is_empty() => {
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| {
                    anyhow::anyhow!("SECUREOPS_LICENSE_PUBKEY is not valid base64url: {e}")
                })?;
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                anyhow::anyhow!(
                    "SECUREOPS_LICENSE_PUBKEY must decode to exactly 32 bytes (got {})",
                    bytes.len()
                )
            })
        }
        _ if dev_mode => {
            tracing::warn!(
                "SECUREOPS_LICENSE_PUBKEY unset - using insecure dev key (SECUREOPS_DEV_MODE=1)"
            );
            Ok(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
                .verifying_key()
                .to_bytes())
        }
        _ => anyhow::bail!(
            "SECUREOPS_LICENSE_PUBKEY is required (base64url 32-byte Ed25519 public key). \
             For local development only, set SECUREOPS_DEV_MODE=1 to use the built-in dev key."
        ),
    }
}

/// Build a [`CorsLayer`] from a comma-separated origin allowlist. Any origin
/// that fails to parse is a hard error so typos cannot widen access.
fn cors_layer(origins: &str) -> anyhow::Result<tower_http::cors::CorsLayer> {
    let parsed = origins
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|o| {
            o.parse::<axum::http::HeaderValue>()
                .map_err(|_| anyhow::anyhow!("SECUREOPS_CORS_ORIGINS: invalid origin {o:?}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    anyhow::ensure!(
        !parsed.is_empty(),
        "SECUREOPS_CORS_ORIGINS is set but empty"
    );
    Ok(tower_http::cors::CorsLayer::new()
        .allow_origin(parsed)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ]))
}

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
//! - `SECUREOPS_API_KEY_PEPPER` - server-side pepper for hashing API keys at
//!   rest (defaults to the JWT secret if unset).
//! - `SECUREOPS_ALLOW_INSECURE_BIND` - opt-in to bind a non-loopback addr in dev
//!   mode (local container networks only).
//! - `SECUREOPS_RL_GLOBAL`/`SECUREOPS_RL_AUTH`/`SECUREOPS_RL_WINDOW_SECS` - rate
//!   limiter budgets.
//! - `SECUREOPS_TLS_CERT`/`SECUREOPS_TLS_KEY` - PEM paths to serve HTTPS
//!   in-process (build with `--features tls`; see docs/tls-and-otlp.md).
//! - `OTEL_EXPORTER_OTLP_ENDPOINT` - collector URL (HTTP `:4318`) for OTLP span
//!   export (build with `--features otlp`).

#![forbid(unsafe_code)]

use std::sync::Arc;

use base64::Engine as _;
use secureops_api::authz::PolicyEngine;
use secureops_api::evidence::S3Presigner;
use secureops_api::ratelimit::RateLimiter;
use secureops_api::redis_queue::RedisQueue;
use secureops_api::store::pg::PgStore;
use secureops_api::store::{InMemoryStore, Store};
use secureops_api::{build_router, with_spa, AppState};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_telemetry();

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

    let mut state = AppState::new(store, authz, jwt_secret, license_pubkey)
        .with_rate_limiter(RateLimiter::from_env());

    // Dedicated API-key pepper (so key hashes and JWTs don't share a secret).
    if let Ok(pepper) = std::env::var("SECUREOPS_API_KEY_PEPPER") {
        if !pepper.is_empty() {
            state = state.with_api_key_pepper(pepper);
            tracing::info!("API-key pepper configured from env");
        }
    }

    // Wire a real OIDC verifier when compiled with `--features live-oidc` and
    // configured. Without it the SSO callback returns 404 (SSO not configured),
    // which is now explicit rather than a silent default.
    state = wire_oidc(state);

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
    // Dev mode installs well-known insecure secrets (forgeable JWTs/licenses).
    // Refuse to bind a non-loopback address in dev mode so those secrets can
    // never be exposed to a network by accident.
    if dev_mode && !is_loopback_addr(&addr) {
        let allow_insecure = std::env::var("SECUREOPS_ALLOW_INSECURE_BIND")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !allow_insecure {
            anyhow::bail!(
                "SECUREOPS_DEV_MODE=1 uses insecure well-known secrets and must not bind a \
                 non-loopback address ({addr}). For a local container network you may set \
                 SECUREOPS_ALLOW_INSECURE_BIND=1 to override; for any real deployment unset \
                 dev mode and provide real SECUREOPS_JWT_SECRET / SECUREOPS_LICENSE_PUBKEY."
            );
        }
        tracing::warn!(
            "SECUREOPS_DEV_MODE=1 binding non-loopback {addr} with SECUREOPS_ALLOW_INSECURE_BIND=1 \
             - INSECURE, local/dev only. Never expose this to an untrusted network."
        );
    }
    serve(app, &addr).await?;
    Ok(())
}

/// Serve the app, terminating TLS in-process when built with `--features tls`
/// and `SECUREOPS_TLS_CERT` / `SECUREOPS_TLS_KEY` (PEM paths) are set; otherwise
/// plain HTTP (front with a TLS terminator).
#[cfg(feature = "tls")]
async fn serve(app: axum::Router, addr: &str) -> anyhow::Result<()> {
    let cert = std::env::var("SECUREOPS_TLS_CERT").unwrap_or_default();
    let key = std::env::var("SECUREOPS_TLS_KEY").unwrap_or_default();
    if !cert.is_empty() && !key.is_empty() {
        // rustls 0.23 needs a process-default crypto provider installed once.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let sockaddr: std::net::SocketAddr = addr.parse().map_err(|e| {
            anyhow::anyhow!("TLS requires an ip:port SECUREOPS_API_ADDR ({addr}): {e}")
        })?;
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key).await?;
        tracing::info!("secureops-api listening on https://{addr} (TLS terminated in-process)");
        axum_server::bind_rustls(sockaddr, config)
            .serve(app.into_make_service())
            .await?;
        return Ok(());
    }
    tracing::warn!(
        "tls feature built but SECUREOPS_TLS_CERT/KEY unset - serving plaintext HTTP on {addr}"
    );
    serve_plain(app, addr).await
}

/// Plain-HTTP serve (default build, or TLS build without cert/key configured).
#[cfg(not(feature = "tls"))]
async fn serve(app: axum::Router, addr: &str) -> anyhow::Result<()> {
    serve_plain(app, addr).await
}

async fn serve_plain(app: axum::Router, addr: &str) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("secureops-api listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Initialise tracing. With `--features otlp`, spans are exported to the
/// OpenTelemetry collector at `OTEL_EXPORTER_OTLP_ENDPOINT` (HTTP/protobuf, the
/// `/v1/traces` path) in addition to stdout; otherwise stdout only.
#[cfg(feature = "otlp")]
fn init_telemetry() {
    use tracing_subscriber::prelude::*;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer();

    match build_otlp_layer() {
        Ok(otel_layer) => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .with(otel_layer)
                .init();
            tracing::info!("OTLP trace export enabled");
        }
        Err(e) => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
            tracing::warn!("OTLP export disabled (init failed: {e}); stdout tracing only");
        }
    }
}

#[cfg(feature = "otlp")]
fn build_otlp_layer<S>(
) -> anyhow::Result<tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4318".into());
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()?;
    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .build();
    let tracer = provider.tracer("secureops-api");
    opentelemetry::global::set_tracer_provider(provider);
    Ok(tracing_opentelemetry::layer().with_tracer(tracer))
}

/// Stdout-only tracing (default build).
#[cfg(not(feature = "otlp"))]
fn init_telemetry() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

/// True when `addr`'s host is a loopback address (127.0.0.0/8, ::1, localhost).
fn is_loopback_addr(addr: &str) -> bool {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// Attach a real OIDC verifier when built with `--features live-oidc` and the
/// `SECUREOPS_OIDC_*` env is present. A no-op otherwise.
#[cfg(feature = "live-oidc")]
fn wire_oidc(state: AppState) -> AppState {
    use secureops_api::sso::HttpOidcVerifier;
    let (Ok(jwks_uri), Ok(audience), Ok(issuer)) = (
        std::env::var("SECUREOPS_OIDC_JWKS_URI"),
        std::env::var("SECUREOPS_OIDC_AUDIENCE"),
        std::env::var("SECUREOPS_OIDC_ISSUER"),
    ) else {
        return state;
    };
    if jwks_uri.is_empty() || audience.is_empty() || issuer.is_empty() {
        return state;
    }
    let default_tenant =
        std::env::var("SECUREOPS_OIDC_DEFAULT_TENANT").unwrap_or_else(|_| "default".into());
    tracing::info!("OIDC verifier wired (issuer={issuer})");
    state.with_oidc(std::sync::Arc::new(HttpOidcVerifier {
        jwks_uri,
        audience,
        issuer,
        default_tenant,
    }))
}

/// No-op when the real OIDC verifier isn't compiled in.
#[cfg(not(feature = "live-oidc"))]
fn wire_oidc(state: AppState) -> AppState {
    state
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

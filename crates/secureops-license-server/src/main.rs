//! `secureops-license-server` binary (PRODUCT.md Phase 8).
//!
//! Env:
//! - `SECUREOPS_LICENSE_PUBKEY` — base64url 32-byte Ed25519 vendor public key
//!   (falls back to the dev key for local runs).
//! - `SECUREOPS_ADMIN_KEY` — bearer for `/revoke` (required in production).
//! - `SECUREOPS_LICENSE_ADDR` — listen addr (default `0.0.0.0:8090`).

#![forbid(unsafe_code)]

use base64::Engine as _;
use secureops_license_server::{build_router, AppState};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let pubkey = load_pubkey();
    let admin_key = std::env::var("SECUREOPS_ADMIN_KEY").unwrap_or_else(|_| {
        tracing::warn!("SECUREOPS_ADMIN_KEY unset — using insecure dev key");
        "dev-admin-key".into()
    });
    let state = AppState::new(pubkey, admin_key);

    let addr = std::env::var("SECUREOPS_LICENSE_ADDR").unwrap_or_else(|_| "0.0.0.0:8090".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("secureops-license-server listening on {addr}");
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

fn load_pubkey() -> [u8; 32] {
    if let Ok(b64) = std::env::var("SECUREOPS_LICENSE_PUBKEY") {
        if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return arr;
            }
        }
        tracing::warn!("SECUREOPS_LICENSE_PUBKEY invalid; using dev key");
    }
    ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
        .verifying_key()
        .to_bytes()
}

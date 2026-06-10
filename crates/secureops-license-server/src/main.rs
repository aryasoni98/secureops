//! `secureops-license-server` binary (PRODUCT.md Phase 8).
//!
//! Subcommands:
//! - *(default)* / `serve` — run the stateless heartbeat/revoke HTTP server.
//! - `mint` — sign a license key (vendor tooling; `--dev` uses the built-in
//!   dev key for local/beta runs).
//! - `verify` — verify a license key offline and print its claims.
//!
//! Env (serve):
//! - `SECUREOPS_LICENSE_PUBKEY` — base64url 32-byte Ed25519 vendor public key
//!   (required unless `SECUREOPS_DEV_MODE=1`).
//! - `SECUREOPS_ADMIN_KEY` — bearer for `/revoke` (required unless
//!   `SECUREOPS_DEV_MODE=1`).
//! - `SECUREOPS_DEV_MODE` — set to `1` to accept insecure local-only defaults
//!   for the two values above. Never set in production.
//! - `SECUREOPS_LICENSE_ADDR` — listen addr (default `127.0.0.1:8090`; set
//!   `0.0.0.0:8090` explicitly for containers).
//!
//! Env (mint):
//! - `SECUREOPS_SIGNING_KEY` — base64url 32-byte Ed25519 seed (vendor private
//!   key). Not needed with `--dev`.

#![forbid(unsafe_code)]

use base64::Engine as _;
use clap::{Parser, Subcommand};
use secureops_api::license::{self, License, Tier};
use secureops_license_server::{build_router, AppState};
use tracing_subscriber::EnvFilter;

/// Deterministic dev seed — local/beta only, never trusted in production.
const DEV_SEED: [u8; 32] = [7u8; 32];

#[derive(Parser)]
#[command(name = "secureops-license-server", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the stateless heartbeat/revoke HTTP server (default).
    Serve,
    /// Sign a license key and print it to stdout (vendor tooling).
    Mint {
        /// Tenant the license is issued to.
        #[arg(long)]
        tenant: String,
        /// Tier: community | pro | enterprise.
        #[arg(long, default_value = "community")]
        tier: String,
        /// Validity in days from now.
        #[arg(long, default_value_t = 365)]
        days: u32,
        /// Seat count.
        #[arg(long, default_value_t = 5)]
        seats: u32,
        /// Comma-separated feature overrides (default: tier's feature set).
        #[arg(long)]
        features: Option<String>,
        /// Grace days after expiry before features hard-lock.
        #[arg(long, default_value_t = 7)]
        grace_days: u32,
        /// Sign with the built-in dev key (local/beta only — pairs with
        /// `SECUREOPS_DEV_MODE=1` on the API/license server).
        #[arg(long)]
        dev: bool,
    },
    /// Verify a license key offline and print its claims as JSON.
    Verify {
        /// The license key string (`payload.signature`).
        #[arg(long)]
        key: String,
        /// base64url 32-byte vendor public key (default: `SECUREOPS_LICENSE_PUBKEY`).
        #[arg(long)]
        pubkey: Option<String>,
        /// Verify against the built-in dev key (local/beta only).
        #[arg(long)]
        dev: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd.unwrap_or(Cmd::Serve) {
        Cmd::Serve => serve().await,
        Cmd::Mint {
            tenant,
            tier,
            days,
            seats,
            features,
            grace_days,
            dev,
        } => mint(
            &tenant,
            &tier,
            days,
            seats,
            features.as_deref(),
            grace_days,
            dev,
        ),
        Cmd::Verify { key, pubkey, dev } => verify(&key, pubkey.as_deref(), dev),
    }
}

async fn serve() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let dev_mode = dev_mode();
    let pubkey = load_pubkey(dev_mode)?;
    let admin_key = match std::env::var("SECUREOPS_ADMIN_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ if dev_mode => {
            tracing::warn!(
                "SECUREOPS_ADMIN_KEY unset — using insecure dev key (SECUREOPS_DEV_MODE=1)"
            );
            "dev-admin-key".into()
        }
        _ => anyhow::bail!(
            "SECUREOPS_ADMIN_KEY is required (generate with `openssl rand -hex 32`). \
             For local development only, set SECUREOPS_DEV_MODE=1 to accept an insecure default."
        ),
    };
    let state = AppState::new(pubkey, admin_key);

    let addr = std::env::var("SECUREOPS_LICENSE_ADDR").unwrap_or_else(|_| "127.0.0.1:8090".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("secureops-license-server listening on {addr}");
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

/// Default Cedar feature set per tier (mirrors docs/license.md).
fn tier_features(tier: Tier) -> Vec<String> {
    match tier {
        Tier::Community => vec![],
        Tier::Pro => vec!["threat_intel".into()],
        Tier::Enterprise => vec!["threat_intel".into(), "bughunt".into(), "sso".into()],
    }
}

fn parse_tier(s: &str) -> anyhow::Result<Tier> {
    match s.to_ascii_lowercase().as_str() {
        "community" => Ok(Tier::Community),
        "pro" => Ok(Tier::Pro),
        "enterprise" => Ok(Tier::Enterprise),
        other => anyhow::bail!("unknown tier {other:?} (expected community | pro | enterprise)"),
    }
}

fn mint(
    tenant: &str,
    tier: &str,
    days: u32,
    seats: u32,
    features: Option<&str>,
    grace_days: u32,
    dev: bool,
) -> anyhow::Result<()> {
    let tier = parse_tier(tier)?;
    let signing_key = if dev {
        eprintln!("warning: signing with the built-in DEV key — local/beta use only");
        ed25519_dalek::SigningKey::from_bytes(&DEV_SEED)
    } else {
        let b64 = std::env::var("SECUREOPS_SIGNING_KEY").map_err(|_| {
            anyhow::anyhow!(
                "SECUREOPS_SIGNING_KEY is required to mint (base64url 32-byte Ed25519 seed), \
                 or pass --dev to sign with the built-in dev key (local/beta only)."
            )
        })?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| anyhow::anyhow!("SECUREOPS_SIGNING_KEY is not valid base64url: {e}"))?;
        let seed = <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("SECUREOPS_SIGNING_KEY must be exactly 32 bytes"))?;
        ed25519_dalek::SigningKey::from_bytes(&seed)
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let features = match features {
        Some(list) => list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        None => tier_features(tier),
    };
    let lic = License {
        lic_id: format!("lic_{tenant}_{now}"),
        tenant_id: tenant.to_string(),
        tier,
        seats,
        features,
        issued: now,
        expiry: now + i64::from(days) * 86_400,
        mode: "offline".into(),
        grace_days,
    };
    println!("{}", license::sign(&lic, &signing_key));
    Ok(())
}

fn verify(key: &str, pubkey_b64: Option<&str>, dev: bool) -> anyhow::Result<()> {
    let pubkey = if dev {
        ed25519_dalek::SigningKey::from_bytes(&DEV_SEED)
            .verifying_key()
            .to_bytes()
    } else {
        let b64 = match pubkey_b64 {
            Some(s) => s.to_string(),
            None => std::env::var("SECUREOPS_LICENSE_PUBKEY").map_err(|_| {
                anyhow::anyhow!(
                    "pass --pubkey, set SECUREOPS_LICENSE_PUBKEY, or use --dev for the dev key"
                )
            })?,
        };
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| anyhow::anyhow!("public key is not valid base64url: {e}"))?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("public key must be exactly 32 bytes"))?
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    match license::verify(key, &pubkey, now) {
        Ok(lic) => {
            println!("{}", serde_json::to_string_pretty(&lic)?);
            Ok(())
        }
        Err(code) => anyhow::bail!("license invalid: {code}"),
    }
}

/// True when `SECUREOPS_DEV_MODE` opts into insecure local-only defaults.
fn dev_mode() -> bool {
    std::env::var("SECUREOPS_DEV_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Load the vendor Ed25519 public key from env. A malformed value is always a
/// hard error; an unset value falls back to the dev key only when
/// `SECUREOPS_DEV_MODE=1`.
fn load_pubkey(dev_mode: bool) -> anyhow::Result<[u8; 32]> {
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
                "SECUREOPS_LICENSE_PUBKEY unset — using insecure dev key (SECUREOPS_DEV_MODE=1)"
            );
            Ok(ed25519_dalek::SigningKey::from_bytes(&DEV_SEED)
                .verifying_key()
                .to_bytes())
        }
        _ => anyhow::bail!(
            "SECUREOPS_LICENSE_PUBKEY is required (base64url 32-byte Ed25519 public key). \
             For local development only, set SECUREOPS_DEV_MODE=1 to use the built-in dev key."
        ),
    }
}

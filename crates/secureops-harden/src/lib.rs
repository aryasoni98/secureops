//! # secureops-harden
//!
//! The hardening engine — faithful port of `secureops/src/hardener.ts` and the
//! five `src/hardening/*` modules (PRODUCT.md **B.3**). Unlike checks, hardening
//! *mutates* state, so this crate performs real file I/O (`tokio::fs`): it
//! backs up `openclaw.json` into a timestamped backup dir, runs each module
//! (which reads → mutates → writes the config), writes a manifest, and supports
//! rollback.
//!
//! Modules run in **priority order**: gateway(1) → credential(2) → config(3) →
//! docker(4) → network(5).

#![forbid(unsafe_code)]

pub mod config_hardening;
pub mod credential_hardening;
pub mod docker_hardening;
pub mod gateway_hardening;
pub mod network_hardening;

pub use config_hardening::ConfigHardening;
pub use credential_hardening::CredentialHardening;
pub use docker_hardening::DockerHardening;
pub use gateway_hardening::GatewayHardening;
pub use network_hardening::NetworkHardening;

use async_trait::async_trait;
use secureops_core::{AuditContext, AuditFinding, HardeningResult, IocDatabase, OpenClawConfig};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A hardening module: detects issues ([`check`](HardeningModule::check)) and
/// applies fixes ([`fix`](HardeningModule::fix)). Per-module rollback is a no-op
/// in the TS source — the orchestrator restores the whole config backup.
#[async_trait]
pub trait HardeningModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn priority(&self) -> u32;
    async fn check(&self, ctx: &dyn AuditContext) -> Vec<AuditFinding>;
    async fn fix(&self, ctx: &dyn AuditContext, backup_dir: &Path) -> HardeningResult;
}

/// All modules in priority order (gateway, credential, config, docker, network).
///
/// `ioc` is the shared IOC database; only [`NetworkHardening`] consults it (for
/// the C2 blocklist), but it is threaded through uniformly.
pub fn default_modules(ioc: Arc<IocDatabase>) -> Vec<Box<dyn HardeningModule>> {
    let mut mods: Vec<Box<dyn HardeningModule>> = vec![
        Box::new(GatewayHardening),
        Box::new(CredentialHardening),
        Box::new(ConfigHardening),
        Box::new(DockerHardening),
        Box::new(NetworkHardening::new(ioc)),
    ];
    mods.sort_by_key(|m| m.priority());
    mods
}

/// Result of a [`harden`] run.
pub struct HardenOutcome {
    pub backup_dir: PathBuf,
    pub results: Vec<HardeningResult>,
}

/// Read `<stateDir>/openclaw.json`, or `OpenClawConfig::default()` if
/// absent/invalid (port of the modules' `readConfig`).
pub async fn read_config(state_dir: &str) -> OpenClawConfig {
    let path = format!("{state_dir}/openclaw.json");
    let content = tokio::fs::read_to_string(&path).await.unwrap_or_default();
    OpenClawConfig::from_json_or_default(&content)
}

/// Write `<stateDir>/openclaw.json` as 2-space pretty JSON (port of `writeConfig`;
/// `JSON.stringify(config, null, 2)`, no trailing newline).
pub async fn write_config(state_dir: &str, config: &OpenClawConfig) -> std::io::Result<()> {
    let path = format!("{state_dir}/openclaw.json");
    let json = serde_json::to_string_pretty(config).map_err(std::io::Error::other)?;
    tokio::fs::write(&path, json).await
}

/// Sanitize an RFC3339 timestamp into a backup-dir name: replace `:` and `.`
/// with `-` (port of `new Date().toISOString().replace(/[:.]/g, '-')`).
fn sanitize_timestamp(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' || c == '.' { '-' } else { c })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestEntry {
    module: String,
    actions_applied: usize,
    actions_skipped: usize,
    errors: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    timestamp: String,
    backup_dir: String,
    modules: Vec<ManifestEntry>,
}

/// Run all hardening modules in priority order (port of `harden`).
///
/// `now` is an RFC3339 timestamp injected by the caller (keeps this clock-free
/// and testable). Creates `<stateDir>/.secureops/backup/<sanitized-now>/`,
/// backs up `openclaw.json` → `openclaw.json.original`, runs the modules, and
/// writes `manifest.json`.
pub async fn harden(
    ctx: &dyn AuditContext,
    // TS source carries a `full` flag that toggles destructive modules; the
    // Rust port runs the same five modules unconditionally for now, so this is
    // accepted but ignored (kept for the public API of CLI / NAPI callers).
    _full: bool,
    now: &str,
    ioc: Arc<IocDatabase>,
) -> anyhow::Result<HardenOutcome> {
    let state_dir = ctx.state_dir().to_string();
    let backup_dir = PathBuf::from(&state_dir)
        .join(".secureops")
        .join("backup")
        .join(sanitize_timestamp(now));
    tokio::fs::create_dir_all(&backup_dir).await?;

    // Backup the main config before any changes (ignore only if it doesn't exist).
    let config_path = PathBuf::from(&state_dir).join("openclaw.json");
    match tokio::fs::copy(&config_path, backup_dir.join("openclaw.json.original")).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to backup config before hardening: {e}"
            ))
        }
    }

    let mut results = Vec::new();
    for module in default_modules(ioc) {
        let result = module.fix(ctx, &backup_dir).await;
        results.push(result);
    }

    let manifest = Manifest {
        timestamp: now.to_string(),
        backup_dir: backup_dir.to_string_lossy().to_string(),
        modules: results
            .iter()
            .map(|r| ManifestEntry {
                module: r.module.clone(),
                actions_applied: r.applied.len(),
                actions_skipped: r.skipped.len(),
                errors: r.errors.len(),
            })
            .collect(),
    };
    tokio::fs::write(
        backup_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )
    .await?;

    Ok(HardenOutcome {
        backup_dir,
        results,
    })
}

/// List available backups, newest first (port of `listBackups`).
pub async fn list_backups(state_dir: &str) -> Vec<String> {
    let base = PathBuf::from(state_dir).join(".secureops").join("backup");
    let mut entries = Vec::new();
    if let Ok(mut rd) = tokio::fs::read_dir(&base).await {
        while let Ok(Some(e)) = rd.next_entry().await {
            entries.push(e.file_name().to_string_lossy().to_string());
        }
    }
    entries.sort();
    entries.reverse();
    entries
}

/// Roll back to a previous backup (port of `rollback`). Restores the original
/// `openclaw.json`, then any backed-up credential / `.env` / auth-profiles /
/// memory files.
pub async fn rollback(state_dir: &str, timestamp: Option<&str>) -> anyhow::Result<()> {
    let backups = list_backups(state_dir).await;
    if backups.is_empty() {
        return Err(anyhow::anyhow!("No backups available for rollback"));
    }
    let target = timestamp
        .map(|t| t.to_string())
        .unwrap_or_else(|| backups[0].clone());
    let backup_dir = PathBuf::from(state_dir)
        .join(".secureops")
        .join("backup")
        .join(&target);
    if tokio::fs::metadata(&backup_dir).await.is_err() {
        return Err(anyhow::anyhow!(
            "Backup directory not found: {}",
            backup_dir.to_string_lossy()
        ));
    }

    // Restore the original config (try `.original`, then plain `openclaw.json`).
    let target_config = PathBuf::from(state_dir).join("openclaw.json");
    if tokio::fs::copy(backup_dir.join("openclaw.json.original"), &target_config)
        .await
        .is_err()
        && tokio::fs::copy(backup_dir.join("openclaw.json"), &target_config)
            .await
            .is_err()
    {
        return Err(anyhow::anyhow!(
            "No config backup found in backup directory"
        ));
    }

    // Restore any other backed-up files.
    let mut rd = match tokio::fs::read_dir(&backup_dir).await {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };
    while let Ok(Some(entry)) = rd.next_entry().await {
        let file = entry.file_name().to_string_lossy().to_string();
        match file.as_str() {
            "manifest.json"
            | "openclaw.json.original"
            | "openclaw.json"
            | "openclaw-config.json" => continue,
            _ => {}
        }
        let src = backup_dir.join(&file);

        if let Some(name) = file.strip_prefix("cred-") {
            let dest = PathBuf::from(state_dir).join("credentials").join(name);
            let _ = tokio::fs::copy(&src, &dest).await;
        }
        if file == ".env" {
            let _ = tokio::fs::copy(&src, PathBuf::from(state_dir).join(".env")).await;
        }
        if let Some(rest) = file.strip_prefix("auth-profiles-") {
            let agent = rest.strip_suffix(".json").unwrap_or(rest);
            let dest = PathBuf::from(state_dir)
                .join("agents")
                .join(agent)
                .join("agent")
                .join("auth-profiles.json");
            let _ = tokio::fs::copy(&src, &dest).await;
        }
        for mem in ["soul.md", "SOUL.md", "MEMORY.md"] {
            if let Some(agent) = file.strip_suffix(&format!("-{mem}")) {
                let dest = PathBuf::from(state_dir)
                    .join("agents")
                    .join(agent)
                    .join(mem);
                let _ = tokio::fs::copy(&src, &dest).await;
                break;
            }
        }
    }
    Ok(())
}

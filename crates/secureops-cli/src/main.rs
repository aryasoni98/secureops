//! # secureops-cli
//!
//! The `secureops` command-line binary (PRODUCT.md B.1-B.3, B.9, Part C).
//!
//! This is the operator-facing entry point. It is a thin shell: it parses
//! arguments with [`clap`] and dispatches to the library crates. All real work
//! lives elsewhere -
//!
//! - `secureops_checks::default_checks(ioc_db)` builds the `Vec<Box<dyn Check>>`
//!   (one [`secureops_core::Check`] per audit category),
//! - `secureops_fs::RealAuditContext` supplies the on-disk
//!   [`secureops_core::AuditContext`] (tokio fs + localhost port probe),
//! - [`secureops_core::run_audit`] runs the checks and returns an
//!   [`secureops_core::AuditReport`] (with `.to_json_pretty()` for `--json`).
//!
//! All subcommands are wired end-to-end: `audit` (console + JSON + CI gate),
//! `harden`/`--rollback`, `monitor` (live), `kill`/`--deactivate`, `init`
//! (keystore), `status`, `behavioral`, `export-incident` (audit bundle).
//!
//! ## CI/CD gate (PRODUCT.md Part C)
//!
//! `secureops audit --json` is meant to run in pipelines. When the computed
//! [`AuditReport::score`] falls below a configured threshold (default
//! [`DEFAULT_SCORE_THRESHOLD`]), the process must **exit non-zero** so the build
//! fails. See [`Command::Audit`] and [`audit_exit_code`] for where that contract
//! is enforced. In JSON mode only the report is written to stdout (machine
//! readable); any human-facing text goes to stderr.

#![allow(dead_code, unused_variables)]
#![forbid(unsafe_code)]

mod console;

use clap::{Parser, Subcommand};
use secureops_core::{run_audit, AuditOptions, OpenClawConfig};
use std::sync::Arc;

/// SecureOps report version (matches the TS `runAudit` hardcoded value).
const SECUREOPS_VERSION: &str = "2.2.0";

/// The IOC database bundled into the binary at build time (single static binary,
/// PRODUCT.md P3). Same `ioc/indicators.json` the TS tool ships.
const BUNDLED_IOC: &str = include_str!("../assets/indicators.json");

/// Default minimum audit score (0-100) that the CI/CD gate requires.
///
/// `secureops audit --json` exits non-zero when `report.score` is below this,
/// failing the pipeline (PRODUCT.md Part C). The threshold will become
/// configurable (flag / config / env) when the gate is wired up.
pub const DEFAULT_SCORE_THRESHOLD: u32 = 80;

/// Process exit code returned when the audit gate fails (score below threshold).
pub const EXIT_GATE_FAILED: i32 = 2;

/// Top-level `secureops` command (PRODUCT.md B.1-B.3, B.9).
#[derive(Parser, Debug)]
#[command(
    name = "secureops",
    version,
    about = "Security audit, hardening and runtime monitoring for OpenClaw deployments",
    long_about = None
)]
pub struct Cli {
    /// Which subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The `secureops` subcommands.
///
/// Mirrors the TypeScript CLI surface so the Rust binary is a drop-in:
/// `init`, `audit`, `harden`, `monitor`, `kill`, `export-incident`.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scaffold a `.secureops/` state dir and starter config (PRODUCT.md B.2).
    Init,

    /// Run the security audit and print a report / score (PRODUCT.md B.1, Part C).
    ///
    /// `--deep` enables the slower, higher-coverage checks; `--json` emits the
    /// machine-readable [`AuditReport`] and turns this into the CI/CD gate that
    /// exits non-zero below [`DEFAULT_SCORE_THRESHOLD`].
    Audit {
        /// Run the deep / expensive checks too (maps to `AuditOptions::deep`).
        #[arg(long)]
        deep: bool,
        /// Emit JSON and act as the CI/CD gate (maps to `AuditOptions::json`).
        /// With `--json`, the process exits 2 when the score is below the
        /// threshold so pipelines fail the build.
        #[arg(long)]
        json: bool,
        /// Minimum passing score for the `--json` CI/CD gate.
        #[arg(long, default_value_t = DEFAULT_SCORE_THRESHOLD)]
        threshold: u32,
    },

    /// Apply auto-fixable remediations (PRODUCT.md B.3).
    ///
    /// `--full` applies every auto-fixable finding rather than the safe subset;
    /// `--rollback <id>` reverts a previously-applied hardening transaction.
    Harden {
        /// Apply all auto-fixable findings, not just the conservative defaults.
        #[arg(long)]
        full: bool,
        /// Roll back the hardening transaction with this id.
        #[arg(long)]
        rollback: Option<String>,
    },

    /// Start the runtime monitors (cost / behavioral / network) (PRODUCT.md B.1).
    Monitor,

    /// Emergency stop: halt the agent / sandbox immediately (PRODUCT.md B.9).
    Kill {
        /// Optional human-readable reason recorded in the killswitch file.
        #[arg(long)]
        reason: Option<String>,
        /// Deactivate the kill switch instead of activating it.
        #[arg(long)]
        deactivate: bool,
    },

    /// Bundle logs + findings into a portable incident report (PRODUCT.md B.9).
    ExportIncident,

    /// Show security status: kill switch, score, monitor toggles.
    Status,

    /// Show behavioral baseline statistics (directive G3).
    Behavioral {
        /// Rolling window in minutes (default 60).
        #[arg(long, default_value_t = 60)]
        window: i64,
    },
}

/// Current UTC timestamp as RFC3339, matching TS `new Date().toISOString()`
/// (PRODUCT.md A.5 wire format).
use secureops_core::now_iso as now_timestamp;

/// Resolve the OpenClaw state dir: `$OPENCLAW_STATE_DIR` else `~/.openclaw`
/// (same precedence as the TS plugin).
fn resolve_state_dir() -> String {
    if let Ok(dir) = std::env::var("OPENCLAW_STATE_DIR") {
        return dir;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{home}/.openclaw")
}

/// Load `<stateDir>/openclaw.json`, or an empty config if absent/invalid
/// (mirrors `createAuditContext`'s try/catch → `{}`).
async fn load_config(state_dir: &str) -> OpenClawConfig {
    let path = format!("{state_dir}/openclaw.json");
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => OpenClawConfig::default(),
    }
}

/// Map an [`AuditReport`] score to the CI/CD gate exit code (PRODUCT.md Part C).
///
/// Returns [`EXIT_GATE_FAILED`] when `score < threshold`, else `0`. Kept as a
/// pure, testable function so the gate contract is unit-coverable independent of
/// I/O.
pub fn audit_exit_code(score: u32, threshold: u32) -> i32 {
    if score < threshold {
        EXIT_GATE_FAILED
    } else {
        0
    }
}

/// Starter `secureops` config block written by `init` when no `openclaw.json`
/// exists. Values mirror the runtime defaults (cost 2/10/100 USD + breaker on,
/// all monitors on, egress allowlist present but disabled) so the file is a
/// template to edit, not a behaviour change.
fn starter_config() -> OpenClawConfig {
    use secureops_core::config::{CostLimits, MonitorsToggle, NetworkSettings, SecureOpsConfig};
    OpenClawConfig {
        secureops: Some(SecureOpsConfig {
            monitors: Some(MonitorsToggle {
                credentials: Some(true),
                memory: Some(true),
                skills: Some(true),
                cost: Some(true),
            }),
            cost: Some(CostLimits {
                hourly_limit_usd: Some(2.0),
                daily_limit_usd: Some(10.0),
                monthly_limit_usd: Some(100.0),
                circuit_breaker_enabled: Some(true),
            }),
            network: Some(NetworkSettings {
                egress_allowlist_enabled: Some(false),
                egress_allowlist: Some(vec!["api.anthropic.com".into(), "api.openai.com".into()]),
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Handle `secureops init` (PRODUCT.md B.1): create `<stateDir>/.secureops/`,
/// the machine-keyed keystore, and - only when absent - a starter
/// `openclaw.json`. An existing config file is never touched: it may belong to
/// the agent runtime SecureOps is auditing.
async fn run_init() -> anyhow::Result<()> {
    let state_dir = resolve_state_dir();
    let (machine_id, keystore_path) =
        secureops_crypto::machinekey::ensure_keystore(&state_dir).await?;
    println!("Initialized SecureOps state at {state_dir}/.secureops/");
    println!("  keystore: {}", keystore_path.display());
    println!("  machine id: {}…", &machine_id[..machine_id.len().min(12)]);

    let config_path = format!("{state_dir}/openclaw.json");
    if tokio::fs::try_exists(&config_path).await.unwrap_or(false) {
        println!("  config: {config_path} (existing - left untouched)");
    } else {
        let json = serde_json::to_string_pretty(&starter_config())?;
        tokio::fs::write(&config_path, format!("{json}\n")).await?;
        println!("  config: {config_path} (starter defaults written - edit to taste)");
    }

    println!("  next: run `secureops audit` to score your config.");
    Ok(())
}

/// Handle `secureops status`: kill switch + a quick audit score + monitor toggles.
async fn run_status() -> anyhow::Result<()> {
    let state_dir = resolve_state_dir();
    let kill = secureops_fs::killswitch::is_kill_switch_active(&state_dir).await;
    println!("SecureOps status ({state_dir})");
    println!(
        "  kill switch: {}",
        if kill {
            "ACTIVE - tool calls blocked"
        } else {
            "inactive"
        }
    );

    let config = load_config(&state_dir).await;
    let ioc_db = Arc::new(secureops_intel::load_from_str(BUNDLED_IOC));
    let checks = secureops_checks::default_checks(ioc_db);
    let ctx = secureops_fs::RealAuditContext::for_host(
        state_dir.clone(),
        config.clone(),
        "native",
        "unknown",
    );
    let report = run_audit(
        &ctx,
        &checks,
        &AuditOptions::default(),
        now_timestamp(),
        SECUREOPS_VERSION,
    )
    .await;
    println!(
        "  score: {}/100 ({} findings)",
        report.score,
        report.findings.len()
    );

    let m = config.secureops.as_ref().and_then(|s| s.monitors.as_ref());
    let on = |b: Option<bool>| if b == Some(true) { "on" } else { "off" };
    println!(
        "  monitors (config): credentials={} memory={} skills={} cost={}",
        on(m.and_then(|x| x.credentials)),
        on(m.and_then(|x| x.memory)),
        on(m.and_then(|x| x.skills)),
        on(m.and_then(|x| x.cost)),
    );
    println!("  (run `secureops monitor` or the daemon to start live monitoring)");
    Ok(())
}

/// Handle `secureops behavioral [--window N]` (directive G3).
async fn run_behavioral(window: i64) -> anyhow::Result<()> {
    let state_dir = resolve_state_dir();
    let now_ms = secureops_core::now_ms();
    let stats = secureops_fs::behavioral::get_behavioral_baseline(&state_dir, window, now_ms).await;
    println!("Behavioral baseline (last {window} min)");
    println!("  total calls: {}", stats.total_calls);
    println!("  unique tools: {}", stats.unique_tools);
    let mut tools: Vec<(&String, &u64)> = stats.tool_frequency.iter().collect();
    tools.sort_by(|a, b| b.1.cmp(a.1));
    for (tool, count) in tools {
        println!("    {tool}: {count}");
    }
    Ok(())
}

/// Handle `secureops audit [--deep] [--json]` (PRODUCT.md B.1, Part C).
///
/// When wired up this is also the CI/CD gate: in `--json` mode it prints the
/// report to stdout and exits non-zero when the score is below threshold.
async fn run_audit_cmd(deep: bool, json: bool, threshold: u32) -> anyhow::Result<()> {
    let state_dir = resolve_state_dir();
    let config = load_config(&state_dir).await;

    // Bundled IOC database; degrades to empty (audit still runs) on parse error,
    // mirroring the TS `loadIOCDatabase` graceful fallback (PRODUCT.md B.2/B.8).
    let ioc_db = Arc::new(secureops_intel::load_from_str(BUNDLED_IOC));

    let ctx = secureops_fs::RealAuditContext::for_host(state_dir, config, "native", "unknown");
    let checks = secureops_checks::default_checks(ioc_db);
    let opts = AuditOptions {
        deep,
        fix: false,
        json,
    };

    let report = run_audit(&ctx, &checks, &opts, now_timestamp(), SECUREOPS_VERSION).await;

    if json {
        // Machine-readable report on stdout for the pipeline to capture.
        println!("{}", report.to_json_pretty());
        // CI/CD gate (PRODUCT.md Part C): fail the build on a low score.
        std::process::exit(audit_exit_code(report.score, threshold));
    } else {
        println!("{}", console::format_console_report(&report));
    }
    Ok(())
}

/// Handle `secureops harden [--full] [--rollback <id>]` (PRODUCT.md B.3).
async fn run_harden(full: bool, rollback: Option<String>) -> anyhow::Result<()> {
    let state_dir = resolve_state_dir();

    // Rollback path: restore a prior backup (latest if the id is empty).
    if let Some(ts) = rollback {
        let target = if ts.is_empty() {
            None
        } else {
            Some(ts.as_str())
        };
        secureops_harden::rollback(&state_dir, target).await?;
        println!("secureops harden: rolled back config in {state_dir}");
        return Ok(());
    }

    let config = load_config(&state_dir).await;
    let ioc = Arc::new(secureops_intel::load_from_str(BUNDLED_IOC));
    let ctx = secureops_fs::RealAuditContext::for_host(state_dir, config, "native", "unknown");

    let outcome = secureops_harden::harden(&ctx, full, &now_timestamp(), ioc).await?;

    println!("Backup: {}", outcome.backup_dir.display());
    for r in &outcome.results {
        println!(
            "[{}] applied {} · skipped {} · errors {}",
            r.module,
            r.applied.len(),
            r.skipped.len(),
            r.errors.len()
        );
        for a in &r.applied {
            println!(
                "  + {}: {} ({} -> {})",
                a.id, a.description, a.before, a.after
            );
        }
        for e in &r.errors {
            println!("  ! {e}");
        }
    }
    Ok(())
}

/// Handle `secureops monitor` (PRODUCT.md B.1).
async fn run_monitor() -> anyhow::Result<()> {
    use secureops_monitors::cost::Limits;
    use secureops_monitors::{
        circuit_channel, AlertBus, CancellationToken, CostMonitor, CredentialMonitor,
        MemoryIntegrityMonitor, Monitor, SkillScanner,
    };

    let state_dir = resolve_state_dir();
    let config = load_config(&state_dir).await;
    let ioc = Arc::new(secureops_intel::load_from_str(BUNDLED_IOC));

    // Cost limits from config.secureops.cost (TS defaults: 2 / 10 / 100, breaker on).
    let limits = config
        .secureops
        .as_ref()
        .and_then(|s| s.cost.as_ref())
        .map(|c| Limits {
            hourly_usd: c.hourly_limit_usd.unwrap_or(2.0),
            daily_usd: c.daily_limit_usd.unwrap_or(10.0),
            monthly_usd: c.monthly_limit_usd.unwrap_or(100.0),
            circuit_breaker_enabled: c.circuit_breaker_enabled.unwrap_or(true),
        })
        .unwrap_or_default();

    let (circuit_tx, _circuit_rx) = circuit_channel();
    let bus = AlertBus::new();
    let (cancel_src, cancel) = CancellationToken::new();

    let monitors: Vec<Box<dyn Monitor>> = vec![
        Box::new(
            CostMonitor::new(circuit_tx)
                .with_state_dir(state_dir.clone())
                .with_limits(limits),
        ),
        Box::new(CredentialMonitor::new().with_state_dir(state_dir.clone())),
        Box::new(MemoryIntegrityMonitor::new().with_state_dir(state_dir.clone())),
        Box::new(SkillScanner::new(ioc).with_state_dir(state_dir.clone())),
    ];

    // Print every alert as it lands on the bus.
    let mut rx = bus.subscribe();
    let printer = tokio::spawn(async move {
        while let Ok(a) = rx.recv().await {
            let details = a.details.map(|d| format!(" - {d}")).unwrap_or_default();
            println!(
                "[{:?}] {} :: {}{}",
                a.severity, a.monitor, a.message, details
            );
        }
    });

    let mut set = tokio::task::JoinSet::new();
    for m in monitors {
        let bus = bus.clone();
        let cancel = cancel.clone();
        set.spawn(async move { m.run(bus, cancel).await });
    }

    println!("secureops monitor running ({state_dir}). Ctrl-C to stop.");
    tokio::signal::ctrl_c().await?;
    println!("\nShutting down monitors...");
    cancel_src.cancel();
    while set.join_next().await.is_some() {}
    printer.abort();
    Ok(())
}

/// Handle `secureops kill [--reason <r>]` (PRODUCT.md B.9).
async fn run_kill(reason: Option<String>, deactivate: bool) -> anyhow::Result<()> {
    let state_dir = resolve_state_dir();
    if deactivate {
        secureops_fs::killswitch::deactivate_kill_switch(&state_dir).await?;
        println!("Kill switch DEACTIVATED - normal operation resumes ({state_dir}).");
        return Ok(());
    }
    secureops_fs::killswitch::activate_kill_switch(&state_dir, reason.as_deref(), &now_timestamp())
        .await?;
    println!(
        "Kill switch ACTIVATED - all tool calls are now blocked ({state_dir}).\n\
         Run `secureops kill --deactivate` to resume."
    );
    Ok(())
}

/// Adapter: drive the hash-chain [`secureops_auditlog::Signer`] contract with
/// the OS-keychain ed25519 backend (PRODUCT.md A.3), so incident-export chain
/// entries are signed with a key that survives process restarts.
struct KeychainAuditSigner {
    backend: secureops_crypto::signing::KeychainSigner,
    key_id: &'static str,
}

impl KeychainAuditSigner {
    const KEY_ID: &'static str = "secureops-incident-export";

    fn new() -> anyhow::Result<Self> {
        use secureops_crypto::signing::SigningBackend as _;
        let backend = secureops_crypto::signing::KeychainSigner::default();
        backend.ensure_key(Self::KEY_ID)?;
        Ok(Self {
            backend,
            key_id: Self::KEY_ID,
        })
    }

    fn public_key_hex(&self) -> anyhow::Result<String> {
        use secureops_crypto::signing::SigningBackend as _;
        Ok(hex_encode(&self.backend.public_key(self.key_id)?))
    }

    fn sign_bytes(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use secureops_crypto::signing::SigningBackend as _;
        Ok(self.backend.sign(self.key_id, data)?)
    }
}

impl secureops_auditlog::Signer for KeychainAuditSigner {
    fn sign(&self, hash: &str) -> Result<String, secureops_auditlog::AuditLogError> {
        self.sign_bytes(hash.as_bytes())
            .map(|sig| hex_encode(&sig))
            .map_err(|e| secureops_auditlog::AuditLogError::Signing(e.to_string()))
    }

    fn verify(
        &self,
        hash: &str,
        signature: &str,
    ) -> Result<bool, secureops_auditlog::AuditLogError> {
        use ed25519_dalek::Verifier as _;
        let err = |m: &str| secureops_auditlog::AuditLogError::Signing(m.to_string());
        let pk_bytes = {
            use secureops_crypto::signing::SigningBackend as _;
            self.backend
                .public_key(self.key_id)
                .map_err(|e| err(&e.to_string()))?
        };
        let pk_arr: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| err("public key not 32 bytes"))?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
            .map_err(|_| err("invalid public key"))?;
        let sig_bytes = hex_decode(signature).ok_or_else(|| err("signature not hex"))?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| err("signature not 64 bytes"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        Ok(vk.verify(hash.as_bytes(), &sig).is_ok())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    hex_encode(&sha2::Sha256::digest(data))
}

/// Handle `secureops export-incident` (PRODUCT.md B.9).
async fn run_export_incident() -> anyhow::Result<()> {
    let state_dir = resolve_state_dir();
    let ts = now_timestamp();
    let safe_ts: String = ts
        .chars()
        .map(|c| if c == ':' || c == '.' { '-' } else { c })
        .collect();
    let bundle = format!("{state_dir}/.secureops/incidents/{safe_ts}");
    tokio::fs::create_dir_all(&bundle).await?;

    // Fresh audit snapshot.
    let config = load_config(&state_dir).await;
    let ioc_db = Arc::new(secureops_intel::load_from_str(BUNDLED_IOC));
    let checks = secureops_checks::default_checks(ioc_db);
    let ctx =
        secureops_fs::RealAuditContext::for_host(state_dir.clone(), config, "native", "unknown");
    let report = run_audit(
        &ctx,
        &checks,
        &AuditOptions::default(),
        ts.clone(),
        SECUREOPS_VERSION,
    )
    .await;
    let audit_json = report.to_json_pretty();
    tokio::fs::write(format!("{bundle}/audit.json"), &audit_json).await?;

    // Kill-switch state + behavioral snapshot.
    let kill = secureops_fs::killswitch::is_kill_switch_active(&state_dir).await;
    let meta = serde_json::json!({
        "timestamp": ts,
        "stateDir": state_dir,
        "killSwitchActive": kill,
        "score": report.score,
        "secureopsVersion": SECUREOPS_VERSION,
    });
    let incident_json = serde_json::to_string_pretty(&meta)?;
    tokio::fs::write(format!("{bundle}/incident.json"), &incident_json).await?;

    // Sign the bundle (PRODUCT.md B.9): a manifest commits to the SHA-256 of
    // every file, and an ed25519 signature over the manifest bytes - keyed in
    // the OS keychain - makes tampering with the bundle detectable.
    let signer = KeychainAuditSigner::new()?;
    let manifest = serde_json::json!({
        "timestamp": ts,
        "algorithm": "ed25519",
        "publicKey": signer.public_key_hex()?,
        "files": {
            "audit.json": sha256_hex(audit_json.as_bytes()),
            "incident.json": sha256_hex(incident_json.as_bytes()),
        },
    });
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    let manifest_sig = hex_encode(&signer.sign_bytes(manifest_json.as_bytes())?);
    tokio::fs::write(format!("{bundle}/manifest.json"), &manifest_json).await?;
    tokio::fs::write(format!("{bundle}/manifest.sig"), &manifest_sig).await?;

    // Anchor the export into the hash-chained audit log so the incident export
    // itself is a tamper-evident event (same chain the daemon appends to).
    let log_path = format!("{state_dir}/.secureops/audit.jsonl");
    let mut log = secureops_auditlog::AuditLog::open(&log_path, Box::new(signer))?;
    let entry = log.append(
        serde_json::json!({
            "event": "incident_exported",
            "bundle": bundle,
            "manifestSha256": sha256_hex(manifest_json.as_bytes()),
        }),
        ts.clone(),
    )?;

    println!("Incident bundle written: {bundle}");
    println!(
        "  audit.json ({} findings, score {})",
        report.findings.len(),
        report.score
    );
    println!("  incident.json (kill switch: {kill})");
    println!("  manifest.json + manifest.sig (ed25519, OS-keychain key)");
    println!("  audit-log anchor: seq {} in {log_path}", entry.seq);
    Ok(())
}

/// Parse arguments and dispatch to the matching subcommand handler.
///
/// `audit --json` exits non-zero (EXIT_GATE_FAILED) below the score threshold;
/// every other subcommand returns `Ok(())` after running its handler.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init => run_init().await,
        Command::Audit {
            deep,
            json,
            threshold,
        } => run_audit_cmd(deep, json, threshold).await,
        Command::Harden { full, rollback } => run_harden(full, rollback).await,
        Command::Monitor => run_monitor().await,
        Command::Kill { reason, deactivate } => run_kill(reason, deactivate).await,
        Command::ExportIncident => run_export_incident().await,
        Command::Status => run_status().await,
        Command::Behavioral { window } => run_behavioral(window).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The clap definition must be internally consistent (debug-asserts the
    /// command tree); guards against arg/subcommand mistakes at build time.
    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    /// The CI/CD gate (PRODUCT.md Part C): below threshold fails, at/above passes.
    #[test]
    fn gate_fails_below_threshold() {
        assert_eq!(
            audit_exit_code(79, DEFAULT_SCORE_THRESHOLD),
            EXIT_GATE_FAILED
        );
        assert_eq!(audit_exit_code(80, DEFAULT_SCORE_THRESHOLD), 0);
        assert_eq!(audit_exit_code(100, DEFAULT_SCORE_THRESHOLD), 0);
    }

    #[test]
    fn hex_helpers_round_trip() {
        let data = [0u8, 1, 0xab, 0xff];
        let hex = hex_encode(&data);
        assert_eq!(hex, "0001abff");
        assert_eq!(hex_decode(&hex).unwrap(), data);
        assert!(hex_decode("abc").is_none()); // odd length
        assert!(hex_decode("zz").is_none()); // non-hex
    }

    /// The keychain-backed audit signer must verify its own signatures and
    /// reject a signature for a different message (B.9 incident anchoring).
    #[test]
    fn keychain_audit_signer_round_trip() {
        use secureops_auditlog::Signer as _;
        let signer = KeychainAuditSigner::new().expect("keychain signer");
        let sig = signer.sign("chain-hash-abc").expect("sign");
        assert!(signer.verify("chain-hash-abc", &sig).expect("verify"));
        assert!(!signer.verify("different-hash", &sig).expect("verify"));
    }

    #[test]
    fn sha256_hex_is_stable() {
        // Known SHA-256 of the empty string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}

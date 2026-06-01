//! OpenClaw plugin surface — Rust port of the `legacyPlugin` object + lifecycle
//! hooks + command/tool dispatch from `src/index.ts`.
//!
//! The TypeScript tool registered itself with OpenClaw's plugin runtime
//! (`onGatewayStart`/`onGatewayStop`, `api.registerCli`, MCP `tools[]`). In the
//! Rust architecture those hooks live behind the **napi addon**: the thin TS
//! shim wires OpenClaw's lifecycle/CLI/tool callbacks to these functions, each of
//! which runs the real engine and returns JSON. The `#[napi]` wrappers are
//! deferred (need the node toolchain) but the dispatch logic is fully here.

use crate::{load_config, now_iso, run_audit_report, BUNDLED_IOC, SECUREOPS_VERSION};
use secureops_core::AuditOptions;
use serde_json::json;
use std::sync::Arc;

fn ctx_for(state_dir: &str) -> secureops_fs::RealAuditContext {
    secureops_fs::RealAuditContext::for_host(
        state_dir.to_string(),
        load_config(state_dir),
        "native",
        "unknown",
    )
}

fn now_ms() -> i128 {
    time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000
}

/// The plugin manifest (port of `legacyPlugin` name/version/description +
/// command names + MCP `tools[]`). The TS shim registers each command/tool with
/// OpenClaw, dispatching back to [`dispatch_command`] / [`call_tool`].
pub fn plugin_manifest() -> String {
    json!({
        "name": "secureops",
        "version": SECUREOPS_VERSION,
        "description": "Automated security hardening for OpenClaw",
        "commands": [
            "audit", "harden", "status", "scan-skill", "cost-report",
            "kill", "resume", "baseline",
            "skill-install", "skill-audit", "skill-update", "skill-uninstall"
        ],
        "tools": [
            "security_audit", "security_status", "skill_scan",
            "cost_report", "kill_switch", "behavioral_baseline"
        ],
    })
    .to_string()
}

/// `gateway_start` hook (port of the TS `api.on('gateway_start', …)`): kill-switch
/// gate → startup audit → report score/critical + skill presence. Never throws
/// (the gateway must keep running); returns a JSON status.
pub async fn on_gateway_start(state_dir: &str) -> String {
    if secureops_fs::killswitch::is_kill_switch_active(state_dir).await {
        return json!({
            "started": false,
            "killSwitchActive": true,
            "reason": "KILL SWITCH ACTIVE — all operations suspended",
        })
        .to_string();
    }
    let report = run_audit_report(state_dir, &AuditOptions::default()).await;
    let skill_detected =
        std::path::Path::new(&format!("{state_dir}/skills/secureops/SKILL.md")).exists();
    json!({
        "started": true,
        "killSwitchActive": false,
        "score": report.score,
        "critical": report.summary.critical,
        "skillDetected": skill_detected,
        "version": SECUREOPS_VERSION,
    })
    .to_string()
}

/// `gateway_stop` hook (port of `onGatewayStop`). Monitors are owned by the
/// daemon/`monitor` command; nothing to tear down in the addon itself.
pub fn on_gateway_stop() -> String {
    json!({ "stopped": true, "message": "Background monitors stopped." }).to_string()
}

/// Dispatch a `secureops <cmd>` command (port of the `legacyPlugin.commands`
/// map). Returns JSON. `args` are the post-command tokens (e.g. `["--full"]`).
pub async fn dispatch_command(cmd: &str, args: &[String]) -> String {
    let state_dir = crate::plugin::resolve_state_dir();
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let positional = || args.iter().find(|a| !a.starts_with("--")).cloned();

    match cmd {
        "audit" => crate::audit_to_json(state_dir, has("--deep"), has("--fix")).await,
        "status" => {
            let r = run_audit_report(&state_dir, &AuditOptions::default()).await;
            json!({ "score": r.score, "findings": r.findings.len() }).to_string()
        }
        "harden" => {
            if has("--rollback") {
                let ts = positional();
                match secureops_harden::rollback(&state_dir, ts.as_deref()).await {
                    Ok(()) => json!({ "rolledBack": true }).to_string(),
                    Err(e) => json!({ "error": e.to_string() }).to_string(),
                }
            } else {
                let ctx = ctx_for(&state_dir);
                let ioc = Arc::new(secureops_intel::load_from_str(BUNDLED_IOC));
                match secureops_harden::harden(&ctx, has("--full"), &now_iso(), ioc).await {
                    Ok(out) => json!({
                        "backupDir": out.backup_dir.to_string_lossy(),
                        "results": out.results.iter().map(|r| json!({
                            "module": r.module, "applied": r.applied.len(), "errors": r.errors.len(),
                        })).collect::<Vec<_>>(),
                    })
                    .to_string(),
                    Err(e) => json!({ "error": e.to_string() }).to_string(),
                }
            }
        }
        "kill" => {
            let reason = positional().unwrap_or_else(|| "Manual activation".to_string());
            match secureops_fs::killswitch::activate_kill_switch(
                &state_dir,
                Some(&reason),
                &now_iso(),
            )
            .await
            {
                Ok(()) => json!({ "killSwitch": "activated", "reason": reason }).to_string(),
                Err(e) => json!({ "error": e.to_string() }).to_string(),
            }
        }
        "resume" => match secureops_fs::killswitch::deactivate_kill_switch(&state_dir).await {
            Ok(()) => json!({ "killSwitch": "deactivated" }).to_string(),
            Err(e) => json!({ "error": e.to_string() }).to_string(),
        },
        "baseline" => {
            let window = positional().and_then(|w| w.parse().ok()).unwrap_or(60i64);
            let stats =
                secureops_fs::behavioral::get_behavioral_baseline(&state_dir, window, now_ms())
                    .await;
            json!({
                "windowMinutes": window,
                "totalCalls": stats.total_calls,
                "uniqueTools": stats.unique_tools,
                "toolFrequency": stats.tool_frequency,
            })
            .to_string()
        }
        "scan-skill" => match positional() {
            None => json!({ "error": "usage: scan-skill <name>" }).to_string(),
            Some(name) => {
                let db = Arc::new(secureops_intel::load_from_str(BUNDLED_IOC));
                let skills = secureops_monitors::skill_scanner::scan_skills_dir(&state_dir).await;
                match skills.into_iter().find(|(n, _)| *n == name) {
                    Some((n, files)) => {
                        let r = secureops_monitors::skill_scanner::scan_skill_content(
                            &n,
                            &files,
                            Some(&db),
                        );
                        serde_json::to_string(&r).unwrap_or_default()
                    }
                    None => json!({ "error": format!("skill '{name}' not found") }).to_string(),
                }
            }
        },
        "cost-report" => {
            let iso = now_iso();
            let entries = secureops_monitors::cost::scan_state_dir(&state_dir, &iso).await;
            let report = secureops_monitors::cost::generate_cost_report(&entries, now_ms(), false);
            serde_json::to_string(&report).unwrap_or_default()
        }
        // Skill lifecycle was shell-script driven in TS (install.sh, etc.) —
        // managed outside the Rust addon.
        "skill-install" | "skill-audit" | "skill-update" | "skill-uninstall" => {
            json!({ "skip": format!("`{cmd}` is shell-script managed (skill/scripts/*.sh)") })
                .to_string()
        }
        other => json!({ "error": format!("unknown command: {other}") }).to_string(),
    }
}

/// Dispatch an MCP tool call (port of the `tools[]` surface). Maps the six tool
/// names to the same engines the commands use.
pub async fn call_tool(tool: &str, args: &[String]) -> String {
    match tool {
        "security_audit" => dispatch_command("audit", args).await,
        "security_status" => dispatch_command("status", args).await,
        "skill_scan" => dispatch_command("scan-skill", args).await,
        "cost_report" => dispatch_command("cost-report", args).await,
        "kill_switch" => dispatch_command("kill", args).await,
        "behavioral_baseline" => dispatch_command("baseline", args).await,
        other => json!({ "error": format!("unknown tool: {other}") }).to_string(),
    }
}

/// `OPENCLAW_STATE_DIR` → `~/.openclaw` (same contract as the TS tool).
pub(crate) fn resolve_state_dir() -> String {
    if let Ok(dir) = std::env::var("OPENCLAW_STATE_DIR") {
        return dir;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{home}/.openclaw")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serializes tests that mutate the process-global OPENCLAW_STATE_DIR.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn manifest_lists_commands_and_tools() {
        let v: serde_json::Value = serde_json::from_str(&plugin_manifest()).unwrap();
        assert_eq!(v["name"], "secureops");
        assert_eq!(v["version"], "2.2.0");
        assert_eq!(v["tools"].as_array().unwrap().len(), 6);
        assert!(v["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "audit"));
    }

    #[tokio::test]
    async fn gateway_start_refuses_when_kill_switch_active() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_string_lossy().to_string();
        secureops_fs::killswitch::activate_kill_switch(&sd, Some("test"), "t")
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&on_gateway_start(&sd).await).unwrap();
        assert_eq!(v["started"], false);
        assert_eq!(v["killSwitchActive"], true);
    }

    #[tokio::test]
    async fn gateway_start_audits_when_clean() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_string_lossy().to_string();
        let v: serde_json::Value = serde_json::from_str(&on_gateway_start(&sd).await).unwrap();
        assert_eq!(v["started"], true);
        assert!(v["score"].is_number());
    }

    #[tokio::test]
    async fn kill_then_resume_via_command() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_string_lossy().to_string();
        std::env::set_var("OPENCLAW_STATE_DIR", &sd);
        let k: serde_json::Value =
            serde_json::from_str(&dispatch_command("kill", &["breach".into()]).await).unwrap();
        assert_eq!(k["killSwitch"], "activated");
        assert!(secureops_fs::killswitch::is_kill_switch_active(&sd).await);
        let r: serde_json::Value =
            serde_json::from_str(&dispatch_command("resume", &[]).await).unwrap();
        assert_eq!(r["killSwitch"], "deactivated");
        std::env::remove_var("OPENCLAW_STATE_DIR");
    }

    #[tokio::test]
    async fn tool_dispatch_maps_to_commands() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("OPENCLAW_STATE_DIR", dir.path());
        let v: serde_json::Value =
            serde_json::from_str(&call_tool("security_status", &[]).await).unwrap();
        assert!(v["score"].is_number());
        std::env::remove_var("OPENCLAW_STATE_DIR");
    }
}

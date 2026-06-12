//! Config hardening (priority 3) - port of `hardening/config-hardening.ts`.
//!
//! `check()` emits three finding kinds:
//!   * `SC-EXEC-001` when `exec.approvals == "off"` (CRITICAL, not auto-fixable),
//!   * `SC-EXEC-003` when `sandbox.mode != "all"` (MEDIUM, not auto-fixable),
//!   * `SC-AC-001` per channel whose `dmPolicy == "open"` (HIGH, auto-fixable).
//!
//! `fix()` only writes keys OpenClaw's runtime schema accepts (`tools.exec.host`,
//! `session.dmScope`, `logging.redactSensitive`) and strips the invalid
//! root-level `exec` / `sandbox` keys. The CRITICAL/MEDIUM findings stay manual.

use crate::{read_config, write_config, HardeningModule};
use async_trait::async_trait;
use secureops_core::{AuditContext, AuditFinding, HardeningAction, HardeningResult, Severity};
use std::path::Path;

pub struct ConfigHardening;

#[async_trait]
impl HardeningModule for ConfigHardening {
    fn name(&self) -> &'static str {
        "config-hardening"
    }

    fn priority(&self) -> u32 {
        3
    }

    async fn check(&self, ctx: &dyn AuditContext) -> Vec<AuditFinding> {
        let mut findings: Vec<AuditFinding> = Vec::new();
        let config = ctx.config();

        // exec.approvals === 'off'
        if config.exec.as_ref().and_then(|e| e.approvals.as_deref()) == Some("off") {
            findings.push(
                AuditFinding::builder("SC-EXEC-001", Severity::Critical, "execution")
                    .title("Execution approvals disabled")
                    .description("Execution approvals are disabled. This allows commands to run without user confirmation.")
                    .evidence("exec.approvals = \"off\"")
                    .remediation("Manually set exec.approvals to \"always\" in your OpenClaw settings (not auto-fixable - key not in OpenClaw config schema)")
                    .owasp_asi("ASI02")
                    .build(),
            );
        }

        // sandbox.mode !== 'all'
        let sandbox_mode = config.sandbox.as_ref().and_then(|s| s.mode.as_deref());
        if sandbox_mode != Some("all") {
            findings.push(
                AuditFinding::builder("SC-EXEC-003", Severity::Medium, "execution")
                    .title("Sandbox not set to all")
                    .description("Sandbox mode is not set to \"all\". Not all commands run in a sandboxed environment.")
                    .evidence(format!("sandbox.mode = \"{}\"", sandbox_mode.unwrap_or("undefined")))
                    .remediation("Manually set sandbox.mode to \"all\" in your OpenClaw settings (not auto-fixable - key not in OpenClaw config schema)")
                    .owasp_asi("ASI05")
                    .build(),
            );
        }

        // Per-channel: dmPolicy === 'open'
        for ch in ctx.channels() {
            if ch.dm_policy.as_deref() == Some("open") {
                findings.push(
                    AuditFinding::builder("SC-AC-001", Severity::High, "access-control")
                        .title(format!("Channel \"{}\" has open DM policy", ch.name))
                        .description("Will set to \"pairing\".")
                        .evidence("dmPolicy = \"open\"")
                        .remediation("Set dmPolicy to \"pairing\"")
                        .auto_fixable(true)
                        .owasp_asi("ASI01")
                        .build(),
                );
            }
        }

        findings
    }

    async fn fix(&self, ctx: &dyn AuditContext, backup_dir: &Path) -> HardeningResult {
        let mut applied: Vec<HardeningAction> = Vec::new();
        let skipped: Vec<HardeningAction> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        // Backup current config (config may not exist yet - ignore failure).
        let config_path = format!("{}/openclaw.json", ctx.state_dir());
        let _ = tokio::fs::copy(&config_path, backup_dir.join("openclaw-config.json")).await;

        let mut config = read_config(ctx.state_dir()).await;

        // NOTE: We only write keys that OpenClaw's runtime schema accepts.
        // Keys like exec.approvals, exec.autoApprove, sandbox.mode are NOT
        // valid in OpenClaw's config and would cause "Invalid config" errors.
        // Those settings are reported as audit findings with manual remediation.

        // 1. Set tools.exec.host to sandbox (valid OpenClaw key)
        let tools = config.tools.get_or_insert_with(Default::default);
        let exec = tools.exec.get_or_insert_with(Default::default);
        let old_exec_host = exec.host.clone();
        if old_exec_host.as_deref() != Some("sandbox") {
            exec.host = Some("sandbox".to_string());
            applied.push(HardeningAction {
                id: "config-exec-host".to_string(),
                description: "Set tools.exec.host to \"sandbox\"".to_string(),
                before: old_exec_host.unwrap_or_else(|| "undefined".to_string()),
                after: "sandbox".to_string(),
            });
        }

        // 2. Enable DM session isolation (valid OpenClaw key)
        let session = config.session.get_or_insert_with(Default::default);
        let old_dm_scope = session.dm_scope.clone();
        if old_dm_scope.as_deref() != Some("per-channel-peer") {
            session.dm_scope = Some("per-channel-peer".to_string());
            applied.push(HardeningAction {
                id: "config-dm-scope".to_string(),
                description: "Set session.dmScope to \"per-channel-peer\"".to_string(),
                before: old_dm_scope.unwrap_or_else(|| "undefined".to_string()),
                after: "per-channel-peer".to_string(),
            });
        }

        // 3. Enable sensitive log redaction (valid OpenClaw key)
        let logging = config.logging.get_or_insert_with(Default::default);
        let old_redact = logging.redact_sensitive.clone();
        if old_redact.as_deref() != Some("tools") {
            logging.redact_sensitive = Some("tools".to_string());
            applied.push(HardeningAction {
                id: "config-log-redact".to_string(),
                description: "Enabled sensitive log redaction".to_string(),
                before: old_redact.unwrap_or_else(|| "undefined".to_string()),
                after: "tools".to_string(),
            });
        }

        // 4. Strip keys that are NOT in OpenClaw's config schema to avoid
        //    "Invalid config" / "Unrecognized key" errors on startup.
        if config.exec.is_some() {
            config.exec = None;
            applied.push(HardeningAction {
                id: "config-strip-exec".to_string(),
                description: "Removed invalid root-level \"exec\" key (not in OpenClaw schema)"
                    .to_string(),
                before: "present".to_string(),
                after: "removed".to_string(),
            });
        }
        if config.sandbox.is_some() {
            config.sandbox = None;
            applied.push(HardeningAction {
                id: "config-strip-sandbox".to_string(),
                description: "Removed invalid root-level \"sandbox\" key (not in OpenClaw schema)"
                    .to_string(),
                before: "present".to_string(),
                after: "removed".to_string(),
            });
        }

        if let Err(e) = write_config(ctx.state_dir(), &config).await {
            errors.push(format!("Config hardening error: {e}"));
        }

        HardeningResult {
            module: "config-hardening".to_string(),
            applied,
            skipped,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureops_core::config::{ExecConfig, OpenClawConfig, SandboxConfig};
    use secureops_core::context::{ChannelConfig, FileInfo};
    use secureops_core::AuditContext;
    use std::path::PathBuf;

    /// Minimal in-memory AuditContext for the tests in this module.
    struct MockCtx {
        state_dir: String,
        config: OpenClawConfig,
        channels: Vec<ChannelConfig>,
    }

    impl MockCtx {
        fn new(state_dir: impl Into<String>) -> Self {
            MockCtx {
                state_dir: state_dir.into(),
                config: OpenClawConfig::default(),
                channels: Vec::new(),
            }
        }
    }

    #[async_trait]
    impl AuditContext for MockCtx {
        fn state_dir(&self) -> &str {
            &self.state_dir
        }
        fn config(&self) -> &OpenClawConfig {
            &self.config
        }
        fn platform(&self) -> &str {
            "darwin"
        }
        fn deployment_mode(&self) -> &str {
            "local"
        }
        fn openclaw_version(&self) -> &str {
            "0.0.0"
        }
        async fn file_info(&self, path: &str) -> FileInfo {
            FileInfo {
                path: path.to_string(),
                ..Default::default()
            }
        }
        async fn read_file(&self, _path: &str) -> Option<String> {
            None
        }
        async fn list_dir(&self, _path: &str) -> Vec<String> {
            Vec::new()
        }
        async fn file_exists(&self, _path: &str) -> bool {
            false
        }
        async fn get_file_permissions(&self, _path: &str) -> Option<u32> {
            None
        }
        fn channels(&self) -> &[ChannelConfig] {
            &self.channels
        }
    }

    #[tokio::test]
    async fn check_emits_all_three_finding_kinds() {
        let mut ctx = MockCtx::new("/tmp/unused");
        ctx.config.exec = Some(ExecConfig {
            approvals: Some("off".to_string()),
            ..Default::default()
        });
        ctx.config.sandbox = Some(SandboxConfig {
            mode: Some("workspace".to_string()),
            ..Default::default()
        });
        ctx.channels = vec![ChannelConfig {
            name: "general".to_string(),
            dm_policy: Some("open".to_string()),
            ..Default::default()
        }];

        let findings = ConfigHardening.check(&ctx).await;
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["SC-EXEC-001", "SC-EXEC-003", "SC-AC-001"]);

        let exec001 = &findings[0];
        assert_eq!(exec001.severity, Severity::Critical);
        assert_eq!(exec001.owasp_asi, "ASI02");
        assert!(!exec001.auto_fixable);

        let exec003 = &findings[1];
        assert_eq!(exec003.severity, Severity::Medium);
        assert_eq!(exec003.evidence, "sandbox.mode = \"workspace\"");

        let ac001 = &findings[2];
        assert_eq!(ac001.severity, Severity::High);
        assert_eq!(ac001.title, "Channel \"general\" has open DM policy");
        assert!(ac001.auto_fixable);
    }

    #[tokio::test]
    async fn clean_config_yields_only_sandbox_finding() {
        // exec.approvals not "off", sandbox.mode == "all", no open channels.
        let mut ctx = MockCtx::new("/tmp/unused");
        ctx.config.exec = Some(ExecConfig {
            approvals: Some("always".to_string()),
            ..Default::default()
        });
        ctx.config.sandbox = Some(SandboxConfig {
            mode: Some("all".to_string()),
            ..Default::default()
        });

        let findings = ConfigHardening.check(&ctx).await;
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn check_missing_sandbox_reports_undefined() {
        // No sandbox object at all -> SC-EXEC-003 fires with "undefined".
        let ctx = MockCtx::new("/tmp/unused");
        let findings = ConfigHardening.check(&ctx).await;
        let exec003 = findings
            .iter()
            .find(|f| f.id == "SC-EXEC-003")
            .expect("SC-EXEC-003 should fire when sandbox is absent");
        assert_eq!(exec003.evidence, "sandbox.mode = \"undefined\"");
    }

    #[tokio::test]
    async fn fix_mutates_config_and_strips_invalid_keys() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_string_lossy().to_string();

        // Seed an openclaw.json with invalid root keys present.
        let seed = OpenClawConfig {
            exec: Some(ExecConfig {
                approvals: Some("off".to_string()),
                ..Default::default()
            }),
            sandbox: Some(SandboxConfig {
                mode: Some("workspace".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        write_config(&state_dir, &seed).await.unwrap();

        let backup_dir = dir.path().join("backup");
        tokio::fs::create_dir_all(&backup_dir).await.unwrap();

        let ctx = MockCtx::new(state_dir.clone());
        let result = ConfigHardening.fix(&ctx, &backup_dir).await;

        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let applied_ids: Vec<&str> = result.applied.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(
            applied_ids,
            vec![
                "config-exec-host",
                "config-dm-scope",
                "config-log-redact",
                "config-strip-exec",
                "config-strip-sandbox",
            ]
        );

        // Re-read and assert the mutations + stripped keys.
        let after = read_config(&state_dir).await;
        assert_eq!(
            after
                .tools
                .as_ref()
                .and_then(|t| t.exec.as_ref())
                .and_then(|e| e.host.as_deref()),
            Some("sandbox")
        );
        assert_eq!(
            after.session.as_ref().and_then(|s| s.dm_scope.as_deref()),
            Some("per-channel-peer")
        );
        assert_eq!(
            after
                .logging
                .as_ref()
                .and_then(|l| l.redact_sensitive.as_deref()),
            Some("tools")
        );
        assert!(after.exec.is_none(), "root exec should be stripped");
        assert!(after.sandbox.is_none(), "root sandbox should be stripped");

        // Backup copy of the original config was written.
        assert!(PathBuf::from(&backup_dir)
            .join("openclaw-config.json")
            .exists());
    }
}

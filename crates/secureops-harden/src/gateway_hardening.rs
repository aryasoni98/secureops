//! Gateway hardening (priority 1) — faithful port of `hardening/gateway-hardening.ts`.
//!
//! `check()` reports findings SC-GW-001/002/003/009/010/007; `fix()` backs up
//! `openclaw.json` into the backup dir, then enforces loopback bind, enables
//! password auth (or regenerates a weak token), re-enables device auth, disables
//! insecure auth, strips the invalid `gateway.mdns` key, and ensures
//! `trustedProxies` is present.

use crate::{read_config, write_config, HardeningModule};
use async_trait::async_trait;
use secureops_core::{AuditContext, AuditFinding, HardeningAction, HardeningResult, Severity};
use secureops_crypto::generate_token;
use std::path::Path;

pub struct GatewayHardening;

#[async_trait]
impl HardeningModule for GatewayHardening {
    fn name(&self) -> &'static str {
        "gateway-hardening"
    }

    fn priority(&self) -> u32 {
        1
    }

    async fn check(&self, ctx: &dyn AuditContext) -> Vec<AuditFinding> {
        let mut findings: Vec<AuditFinding> = Vec::new();
        let gw = ctx.config().gateway.as_ref();

        // SC-GW-001: gateway not bound to loopback.
        // TS: if (gw?.bind !== 'loopback')
        if gw.and_then(|g| g.bind.as_deref()) != Some("loopback") {
            let bind = gw.and_then(|g| g.bind.as_deref()).unwrap_or("undefined");
            findings.push(AuditFinding {
                id: "SC-GW-001".to_string(),
                severity: Severity::Critical,
                category: "gateway".to_string(),
                title: "Gateway not bound to loopback".to_string(),
                description: "Gateway needs to be bound to loopback.".to_string(),
                evidence: format!("gateway.bind = \"{bind}\""),
                remediation: "Will set gateway.bind to \"loopback\"".to_string(),
                auto_fixable: true,
                references: vec![],
                owasp_asi: "ASI03".to_string(),
                maestro_layer: None,
                nist_category: None,
            });
        }

        // SC-GW-002: gateway authentication disabled.
        // TS: const authMode = gw?.auth?.mode; if (authMode !== 'password' && authMode !== 'token')
        let auth_mode = gw
            .and_then(|g| g.auth.as_ref())
            .and_then(|a| a.mode.as_deref());
        if auth_mode != Some("password") && auth_mode != Some("token") {
            findings.push(AuditFinding {
                id: "SC-GW-002".to_string(),
                severity: Severity::Critical,
                category: "gateway".to_string(),
                title: "Gateway authentication disabled".to_string(),
                description: "Will enable password authentication with a strong token.".to_string(),
                evidence: format!("gateway.auth.mode = \"{}\"", auth_mode.unwrap_or("none")),
                remediation: "Will set gateway.auth.mode to \"password\" and generate a token"
                    .to_string(),
                auto_fixable: true,
                references: vec![],
                owasp_asi: "ASI03".to_string(),
                maestro_layer: None,
                nist_category: None,
            });
        }

        // SC-GW-003: weak gateway auth token.
        // TS: const token = gw?.auth?.token ?? gw?.auth?.password ?? '';
        let token: &str = gw
            .and_then(|g| g.auth.as_ref())
            .and_then(|a| a.token.as_deref().or(a.password.as_deref()))
            .unwrap_or("");
        if (auth_mode == Some("token") || auth_mode == Some("password"))
            && !token.is_empty()
            && token.len() < 32
        {
            findings.push(AuditFinding {
                id: "SC-GW-003".to_string(),
                severity: Severity::Medium,
                category: "gateway".to_string(),
                title: "Weak gateway auth token".to_string(),
                description: "Will regenerate a strong 64-character token.".to_string(),
                evidence: format!("Token length: {}", token.len()),
                remediation: "Will generate a 32-byte (64-char hex) token".to_string(),
                auto_fixable: true,
                references: vec![],
                owasp_asi: "ASI03".to_string(),
                maestro_layer: None,
                nist_category: None,
            });
        }

        // SC-GW-009: device auth disabled.
        // TS: if (gw?.controlUi?.dangerouslyDisableDeviceAuth === true)
        if gw
            .and_then(|g| g.control_ui.as_ref())
            .and_then(|c| c.dangerously_disable_device_auth)
            == Some(true)
        {
            findings.push(AuditFinding {
                id: "SC-GW-009".to_string(),
                severity: Severity::Critical,
                category: "gateway".to_string(),
                title: "Device auth disabled".to_string(),
                description: "Will re-enable device authentication.".to_string(),
                evidence: "dangerouslyDisableDeviceAuth = true".to_string(),
                remediation: "Will set to false".to_string(),
                auto_fixable: true,
                references: vec![],
                owasp_asi: "ASI03".to_string(),
                maestro_layer: None,
                nist_category: None,
            });
        }

        // SC-GW-010: insecure auth allowed.
        // TS: if (gw?.controlUi?.allowInsecureAuth === true)
        if gw
            .and_then(|g| g.control_ui.as_ref())
            .and_then(|c| c.allow_insecure_auth)
            == Some(true)
        {
            findings.push(AuditFinding {
                id: "SC-GW-010".to_string(),
                severity: Severity::Medium,
                category: "gateway".to_string(),
                title: "Insecure auth allowed".to_string(),
                description: "Will disable insecure auth.".to_string(),
                evidence: "allowInsecureAuth = true".to_string(),
                remediation: "Will set to false".to_string(),
                auto_fixable: true,
                references: vec![],
                owasp_asi: "ASI03".to_string(),
                maestro_layer: None,
                nist_category: None,
            });
        }

        // SC-GW-007: mDNS in full mode.
        // TS: if (gw?.mdns && gw.mdns.mode !== 'minimal')
        if let Some(mdns) = gw.and_then(|g| g.mdns.as_ref()) {
            let mode = mdns.mode.as_deref();
            if mode != Some("minimal") {
                findings.push(AuditFinding {
                    id: "SC-GW-007".to_string(),
                    severity: Severity::Medium,
                    category: "gateway".to_string(),
                    title: "mDNS in full mode".to_string(),
                    description: "mDNS is broadcasting in full mode, exposing service information to the local network.".to_string(),
                    evidence: format!("mdns.mode = \"{}\"", mode.unwrap_or("")),
                    remediation: "Manually set gateway.mdns.mode to \"minimal\" (not auto-fixable — key not in OpenClaw config schema)".to_string(),
                    auto_fixable: false,
                    references: vec![],
                    owasp_asi: "ASI05".to_string(),
                    maestro_layer: None,
                    nist_category: None,
                });
            }
        }

        findings
    }

    async fn fix(&self, ctx: &dyn AuditContext, backup_dir: &Path) -> HardeningResult {
        let mut applied: Vec<HardeningAction> = Vec::new();
        let skipped: Vec<HardeningAction> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        // Mirrors the TS try/catch: any error inside is captured into `errors`.
        if let Err(e) = fix_inner(ctx, backup_dir, &mut applied).await {
            errors.push(format!("Gateway hardening error: {e}"));
        }

        HardeningResult {
            module: "gateway-hardening".to_string(),
            applied,
            skipped,
            errors,
        }
    }
}

/// Inner fix routine — the body of the TS `try {}` block. The caller wraps the
/// `Err` into the `errors` vec (ports the `catch`).
async fn fix_inner(
    ctx: &dyn AuditContext,
    backup_dir: &Path,
    applied: &mut Vec<HardeningAction>,
) -> std::io::Result<()> {
    // Backup current config (may not exist yet — ignore the error, like TS).
    let config_path = format!("{}/openclaw.json", ctx.state_dir());
    let _ = tokio::fs::copy(&config_path, backup_dir.join("openclaw.json")).await;

    let mut config = read_config(ctx.state_dir()).await;

    // 1. Enforce loopback bind.
    let gw = config.gateway.get_or_insert_with(Default::default);
    let old_bind = gw.bind.clone();
    if old_bind.as_deref() != Some("loopback") {
        gw.bind = Some("loopback".to_string());
        applied.push(HardeningAction {
            id: "gw-bind".to_string(),
            description: "Set gateway bind to loopback".to_string(),
            before: old_bind.unwrap_or_else(|| "undefined".to_string()),
            after: "loopback".to_string(),
        });
    }

    // 2. Generate strong auth token.
    let auth = gw.auth.get_or_insert_with(Default::default);
    let old_auth_mode = auth.mode.clone();
    let old_password = auth.password.clone();
    if old_auth_mode.as_deref() != Some("password") && old_auth_mode.as_deref() != Some("token") {
        let token = generate_token(32);
        auth.mode = Some("password".to_string());
        auth.password = Some(token.clone());
        applied.push(HardeningAction {
            id: "gw-auth".to_string(),
            description: "Enabled password authentication with strong token".to_string(),
            before: format!("mode={}", old_auth_mode.as_deref().unwrap_or("none")),
            after: format!("mode=password, token={}...", &token[..8]),
        });
    } else {
        // TS: (oldPassword ?? config.gateway.auth.token ?? '')
        let existing: String = old_password
            .clone()
            .or_else(|| auth.token.clone())
            .unwrap_or_default();
        if !existing.is_empty() && existing.len() < 32 {
            let token = generate_token(32);
            auth.password = Some(token.clone());
            applied.push(HardeningAction {
                id: "gw-token-strength".to_string(),
                description: "Regenerated stronger auth token".to_string(),
                before: format!("length={}", existing.len()),
                after: format!("length={}", token.len()),
            });
        }
    }

    // 3. Disable dangerous flags.
    let control_ui = gw.control_ui.get_or_insert_with(Default::default);
    if control_ui.dangerously_disable_device_auth == Some(true) {
        control_ui.dangerously_disable_device_auth = Some(false);
        applied.push(HardeningAction {
            id: "gw-device-auth".to_string(),
            description: "Re-enabled device authentication".to_string(),
            before: "true".to_string(),
            after: "false".to_string(),
        });
    }
    if control_ui.allow_insecure_auth == Some(true) {
        control_ui.allow_insecure_auth = Some(false);
        applied.push(HardeningAction {
            id: "gw-insecure-auth".to_string(),
            description: "Disabled insecure authentication".to_string(),
            before: "true".to_string(),
            after: "false".to_string(),
        });
    }

    // 4. Strip gateway.mdns — NOT a valid OpenClaw config key.
    // mDNS findings are reported as non-auto-fixable in the auditor.
    // TS `delete gwAny['mdns']` -> set the Option field to None.
    if gw.mdns.is_some() {
        gw.mdns = None;
        applied.push(HardeningAction {
            id: "gw-strip-mdns".to_string(),
            description: "Removed invalid \"gateway.mdns\" key (not in OpenClaw schema)"
                .to_string(),
            before: "present".to_string(),
            after: "removed".to_string(),
        });
    }

    // 5. Set trustedProxies if binding to non-loopback.
    // TS: if (!config.gateway.trustedProxies) config.gateway.trustedProxies = [];
    if gw.trusted_proxies.is_none() {
        gw.trusted_proxies = Some(vec![]);
    }

    write_config(ctx.state_dir(), &config).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use secureops_core::config::{
        ControlUiConfig, GatewayAuth, GatewayConfig, MdnsConfig, OpenClawConfig,
    };
    use secureops_core::context::FileInfo;
    use std::path::PathBuf;

    /// Minimal in-memory `AuditContext` for the tests in this module.
    struct MockCtx {
        state_dir: String,
        config: OpenClawConfig,
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
            "test"
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
            vec![]
        }
        async fn file_exists(&self, _path: &str) -> bool {
            false
        }
        async fn get_file_permissions(&self, _path: &str) -> Option<u32> {
            None
        }
    }

    fn finding_ids(findings: &[AuditFinding]) -> Vec<String> {
        findings.iter().map(|f| f.id.clone()).collect()
    }

    #[tokio::test]
    async fn clean_config_yields_no_findings() {
        let config = OpenClawConfig {
            gateway: Some(GatewayConfig {
                bind: Some("loopback".to_string()),
                auth: Some(GatewayAuth {
                    mode: Some("password".to_string()),
                    password: Some("a".repeat(64)),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = MockCtx {
            state_dir: "/tmp/unused".to_string(),
            config,
        };
        let findings = GatewayHardening.check(&ctx).await;
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn insecure_config_fires_expected_findings_in_order() {
        let config = OpenClawConfig {
            gateway: Some(GatewayConfig {
                bind: Some("0.0.0.0".to_string()),
                auth: Some(GatewayAuth {
                    mode: Some("none".to_string()),
                    ..Default::default()
                }),
                control_ui: Some(ControlUiConfig {
                    dangerously_disable_device_auth: Some(true),
                    allow_insecure_auth: Some(true),
                }),
                mdns: Some(MdnsConfig {
                    mode: Some("full".to_string()),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = MockCtx {
            state_dir: "/tmp/unused".to_string(),
            config,
        };
        let ids = finding_ids(&GatewayHardening.check(&ctx).await);
        assert_eq!(
            ids,
            vec![
                "SC-GW-001",
                "SC-GW-002",
                "SC-GW-009",
                "SC-GW-010",
                "SC-GW-007"
            ]
        );
    }

    #[tokio::test]
    async fn weak_token_fires_sc_gw_003() {
        let config = OpenClawConfig {
            gateway: Some(GatewayConfig {
                bind: Some("loopback".to_string()),
                auth: Some(GatewayAuth {
                    mode: Some("password".to_string()),
                    password: Some("short".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = MockCtx {
            state_dir: "/tmp/unused".to_string(),
            config,
        };
        let findings = GatewayHardening.check(&ctx).await;
        let ids = finding_ids(&findings);
        assert_eq!(ids, vec!["SC-GW-003"]);
        assert_eq!(findings[0].evidence, "Token length: 5");
        assert!(findings[0].auto_fixable);
    }

    #[tokio::test]
    async fn fix_mutates_config_and_applies_actions() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_string_lossy().to_string();
        let backup_dir: PathBuf = dir.path().join("backup");
        tokio::fs::create_dir_all(&backup_dir).await.unwrap();

        // Write an insecure openclaw.json.
        let initial = r#"{
  "gateway": {
    "bind": "0.0.0.0",
    "auth": { "mode": "none" },
    "controlUi": { "dangerouslyDisableDeviceAuth": true, "allowInsecureAuth": true },
    "mdns": { "mode": "full" }
  }
}"#;
        tokio::fs::write(format!("{state_dir}/openclaw.json"), initial)
            .await
            .unwrap();

        let ctx = MockCtx {
            state_dir: state_dir.clone(),
            config: OpenClawConfig::default(),
        };
        let result = GatewayHardening.fix(&ctx, &backup_dir).await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);

        let action_ids: Vec<String> = result.applied.iter().map(|a| a.id.clone()).collect();
        assert!(action_ids.contains(&"gw-bind".to_string()));
        assert!(action_ids.contains(&"gw-auth".to_string()));
        assert!(action_ids.contains(&"gw-device-auth".to_string()));
        assert!(action_ids.contains(&"gw-insecure-auth".to_string()));
        assert!(action_ids.contains(&"gw-strip-mdns".to_string()));

        // The gw-auth action's `after` uses the 8-char token prefix.
        let gw_auth = result.applied.iter().find(|a| a.id == "gw-auth").unwrap();
        assert_eq!(gw_auth.before, "mode=none");
        assert!(gw_auth.after.starts_with("mode=password, token="));
        assert!(gw_auth.after.ends_with("..."));

        // Backup was made.
        assert!(backup_dir.join("openclaw.json").exists());

        // Read back the mutated config.
        let config = read_config(&state_dir).await;
        let gw = config.gateway.unwrap();
        assert_eq!(gw.bind, Some("loopback".to_string()));
        let auth = gw.auth.unwrap();
        assert_eq!(auth.mode, Some("password".to_string()));
        assert_eq!(auth.password.as_ref().map(|p| p.len()), Some(64));
        let cui = gw.control_ui.unwrap();
        assert_eq!(cui.dangerously_disable_device_auth, Some(false));
        assert_eq!(cui.allow_insecure_auth, Some(false));
        assert!(gw.mdns.is_none());
        assert_eq!(gw.trusted_proxies, Some(vec![]));
    }
}

//! Execution / sandbox category (PRODUCT.md A.4, B.2).
//!
//! Ports `auditExecution` from `secureops/src/auditor.ts`: validates the
//! `exec`/`sandbox` config - command execution gating, sandbox enforcement,
//! and tool-invocation surface (SC-EXEC-\*), plus Docker-compose hardening.

use async_trait::async_trait;
use secureops_core::{
    AuditContext, AuditFinding, AuditOptions, Check, IocDatabase, MaestroLayer, NistAttackType,
    Severity,
};
use std::sync::Arc;

/// Audits execution/sandbox posture (`auditExecution`). Emits `"execution"` findings.
pub struct ExecutionCheck {
    db: Arc<IocDatabase>,
}

impl ExecutionCheck {
    pub fn new(db: Arc<IocDatabase>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Check for ExecutionCheck {
    fn category(&self) -> &'static str {
        "execution"
    }

    async fn run(&self, ctx: &dyn AuditContext, _opts: &AuditOptions) -> Vec<AuditFinding> {
        // IOC db is intentionally unused by this category (kept for a uniform ctor).
        let _db = &*self.db;

        let mut findings: Vec<AuditFinding> = Vec::new();
        let config = ctx.config();

        // EXEC-001: exec.approvals off
        if config.exec.as_ref().and_then(|e| e.approvals.as_deref()) == Some("off") {
            findings.push(
                AuditFinding::builder("SC-EXEC-001", Severity::Critical, "execution")
                    .title("Execution approvals disabled")
                    .description(
                        "exec.approvals is set to \"off\". The agent can execute arbitrary commands without user confirmation.",
                    )
                    .evidence("exec.approvals = \"off\"")
                    .remediation(
                        "Manually set exec.approvals to \"always\" in your OpenClaw settings (not auto-fixable - key not in OpenClaw config schema)",
                    )
                    .references(["CVE-2026-25253"])
                    .owasp_asi("ASI02")
                    .maestro(MaestroLayer::L3)
                    .nist(NistAttackType::Misuse)
                    .build(),
            );
        }

        // EXEC-002: tools.exec.host = gateway
        if config
            .tools
            .as_ref()
            .and_then(|t| t.exec.as_ref())
            .and_then(|e| e.host.as_deref())
            == Some("gateway")
        {
            findings.push(
                AuditFinding::builder("SC-EXEC-002", Severity::High, "execution")
                    .title("Commands execute on host, not in sandbox")
                    .description(
                        "tools.exec.host is \"gateway\", meaning commands run directly on the host machine without isolation.",
                    )
                    .evidence("tools.exec.host = \"gateway\"")
                    .remediation("Set tools.exec.host to \"sandbox\"")
                    .auto_fixable(true)
                    .owasp_asi("ASI05")
                    .maestro(MaestroLayer::L3)
                    .nist(NistAttackType::Misuse)
                    .build(),
            );
        }

        // EXEC-003: Sandbox mode
        let sandbox_mode = config.sandbox.as_ref().and_then(|s| s.mode.as_deref());
        if sandbox_mode != Some("all") {
            let mode_label = sandbox_mode.unwrap_or("undefined");
            findings.push(
                AuditFinding::builder("SC-EXEC-003", Severity::Medium, "execution")
                    .title("Sandbox mode not set to \"all\"")
                    .description(format!(
                        "Sandbox mode is \"{}\". Not all commands run in a sandboxed environment.",
                        mode_label
                    ))
                    .evidence(format!("sandbox.mode = \"{}\"", mode_label))
                    .remediation(
                        "Manually set sandbox.mode to \"all\" in your OpenClaw settings (not auto-fixable - key not in OpenClaw config schema)",
                    )
                    .owasp_asi("ASI05")
                    .maestro(MaestroLayer::L3)
                    .nist(NistAttackType::Misuse)
                    .build(),
            );
        }

        // EXEC-004..007: Docker compose hardening
        if let Some(dc) = ctx.docker_compose() {
            if let Some(services) = dc.services.as_ref() {
                for (svc_name, svc) in services.iter() {
                    // EXEC-004: Docker --read-only
                    if svc.read_only != Some(true) {
                        findings.push(
                            AuditFinding::builder("SC-EXEC-004", Severity::Medium, "execution")
                                .title(format!("Docker service \"{}\" not read-only", svc_name))
                                .description(
                                    "Container filesystem is writable, allowing post-exploitation persistence.",
                                )
                                .evidence(format!("Service \"{}\": read_only is not set", svc_name))
                                .remediation("Add read_only: true to the service configuration")
                                .auto_fixable(true)
                                .owasp_asi("ASI05")
                                .maestro(MaestroLayer::L3)
                                .nist(NistAttackType::Misuse)
                                .build(),
                        );
                    }

                    // EXEC-005: Docker --cap-drop=ALL
                    let has_cap_drop_all = svc
                        .cap_drop
                        .as_ref()
                        .is_some_and(|c| c.iter().any(|v| v == "ALL"));
                    if !has_cap_drop_all {
                        findings.push(
                            AuditFinding::builder("SC-EXEC-005", Severity::Medium, "execution")
                                .title(format!(
                                    "Docker service \"{}\" retains Linux capabilities",
                                    svc_name
                                ))
                                .description("Container has not dropped all capabilities, increasing attack surface.")
                                .evidence(format!("Service \"{}\": cap_drop does not include \"ALL\"", svc_name))
                                .remediation("Add cap_drop: [\"ALL\"] to the service configuration")
                                .auto_fixable(true)
                                .owasp_asi("ASI05")
                                .maestro(MaestroLayer::L3)
                                .nist(NistAttackType::Misuse)
                                .build(),
                        );
                    }

                    // EXEC-006: Docker no-new-privileges
                    let has_no_new_privileges = svc
                        .security_opt
                        .as_ref()
                        .is_some_and(|s| s.iter().any(|v| v == "no-new-privileges:true"));
                    if !has_no_new_privileges {
                        findings.push(
                            AuditFinding::builder("SC-EXEC-006", Severity::Medium, "execution")
                                .title(format!(
                                    "Docker service \"{}\" allows privilege escalation",
                                    svc_name
                                ))
                                .description("Container does not have no-new-privileges set.")
                                .evidence(format!(
                                    "Service \"{}\": security_opt missing no-new-privileges:true",
                                    svc_name
                                ))
                                .remediation("Add security_opt: [\"no-new-privileges:true\"] to the service configuration")
                                .auto_fixable(true)
                                .owasp_asi("ASI05")
                                .maestro(MaestroLayer::L3)
                                .nist(NistAttackType::Misuse)
                                .build(),
                        );
                    }

                    // EXEC-007: Docker host network
                    if svc.network_mode.as_deref() == Some("host") {
                        findings.push(
                            AuditFinding::builder("SC-EXEC-007", Severity::High, "execution")
                                .title(format!(
                                    "Docker service \"{}\" uses host network mode",
                                    svc_name
                                ))
                                .description("Container shares the host network namespace, bypassing network isolation.")
                                .evidence(format!("Service \"{}\": network_mode = \"host\"", svc_name))
                                .remediation("Remove network_mode: \"host\" and use bridge networking")
                                .auto_fixable(true)
                                .owasp_asi("ASI05")
                                .maestro(MaestroLayer::L3)
                                .nist(NistAttackType::Misuse)
                                .build(),
                        );
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockAuditContext;
    use secureops_core::{
        DockerComposeConfig, DockerServiceConfig, ExecConfig, OpenClawConfig, SandboxConfig,
        ToolsConfig, ToolsExec,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    fn check() -> ExecutionCheck {
        ExecutionCheck::new(Arc::new(IocDatabase::default()))
    }

    fn ids(findings: &[AuditFinding]) -> Vec<String> {
        findings.iter().map(|f| f.id.clone()).collect()
    }

    #[tokio::test]
    async fn flags_approvals_off_host_gateway_and_sandbox() {
        let config = OpenClawConfig {
            exec: Some(ExecConfig {
                approvals: Some("off".to_string()),
                ..Default::default()
            }),
            tools: Some(ToolsConfig {
                exec: Some(ToolsExec {
                    host: Some("gateway".to_string()),
                }),
            }),
            sandbox: Some(SandboxConfig {
                mode: Some("workspace".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = MockAuditContext::new().with_config(config);
        let findings = check().run(&ctx, &AuditOptions::default()).await;
        let ids = ids(&findings);

        assert!(ids.contains(&"SC-EXEC-001".to_string()));
        assert!(ids.contains(&"SC-EXEC-002".to_string()));
        assert!(ids.contains(&"SC-EXEC-003".to_string()));

        let e003 = findings.iter().find(|f| f.id == "SC-EXEC-003").unwrap();
        assert_eq!(e003.evidence, "sandbox.mode = \"workspace\"");
        assert_eq!(
            e003.description,
            "Sandbox mode is \"workspace\". Not all commands run in a sandboxed environment."
        );

        let e001 = findings.iter().find(|f| f.id == "SC-EXEC-001").unwrap();
        assert_eq!(e001.severity, Severity::Critical);
        assert_eq!(e001.references, vec!["CVE-2026-25253".to_string()]);
    }

    #[tokio::test]
    async fn clean_config_only_flags_sandbox_when_mode_all() {
        // mode = "all", approvals = "always", host = "sandbox", no docker.
        let config = OpenClawConfig {
            exec: Some(ExecConfig {
                approvals: Some("always".to_string()),
                ..Default::default()
            }),
            tools: Some(ToolsConfig {
                exec: Some(ToolsExec {
                    host: Some("sandbox".to_string()),
                }),
            }),
            sandbox: Some(SandboxConfig {
                mode: Some("all".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = MockAuditContext::new().with_config(config);
        let findings = check().run(&ctx, &AuditOptions::default()).await;
        assert!(findings.is_empty(), "clean config should yield no findings");
    }

    #[tokio::test]
    async fn sandbox_undefined_when_block_absent() {
        // No sandbox block at all -> mode is "undefined" in the message.
        let ctx = MockAuditContext::new().with_config(OpenClawConfig::default());
        let findings = check().run(&ctx, &AuditOptions::default()).await;
        let e003 = findings
            .iter()
            .find(|f| f.id == "SC-EXEC-003")
            .expect("EXEC-003 should fire when sandbox missing");
        assert_eq!(e003.evidence, "sandbox.mode = \"undefined\"");
        assert_eq!(
            e003.description,
            "Sandbox mode is \"undefined\". Not all commands run in a sandboxed environment."
        );
        // No exec/tools blocks -> 001/002 must not fire.
        let ids = ids(&findings);
        assert!(!ids.contains(&"SC-EXEC-001".to_string()));
        assert!(!ids.contains(&"SC-EXEC-002".to_string()));
    }

    #[tokio::test]
    async fn flags_unhardened_docker_service() {
        // A single fully-unhardened service: emits EXEC-004/005/006/007.
        let mut services = HashMap::new();
        services.insert(
            "agent".to_string(),
            DockerServiceConfig {
                read_only: None,
                cap_drop: None,
                security_opt: None,
                network_mode: Some("host".to_string()),
                ..Default::default()
            },
        );
        let docker = DockerComposeConfig {
            services: Some(services),
            ..Default::default()
        };
        // Keep config clean so only docker findings (+ EXEC-003 default) surface.
        let config = OpenClawConfig {
            sandbox: Some(SandboxConfig {
                mode: Some("all".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = MockAuditContext::new()
            .with_config(config)
            .with_docker(docker);
        let findings = check().run(&ctx, &AuditOptions::default()).await;
        let ids = ids(&findings);

        assert!(ids.contains(&"SC-EXEC-004".to_string()));
        assert!(ids.contains(&"SC-EXEC-005".to_string()));
        assert!(ids.contains(&"SC-EXEC-006".to_string()));
        assert!(ids.contains(&"SC-EXEC-007".to_string()));

        let e004 = findings.iter().find(|f| f.id == "SC-EXEC-004").unwrap();
        assert_eq!(e004.title, "Docker service \"agent\" not read-only");
        assert_eq!(e004.evidence, "Service \"agent\": read_only is not set");

        let e007 = findings.iter().find(|f| f.id == "SC-EXEC-007").unwrap();
        assert_eq!(e007.severity, Severity::High);
        assert_eq!(e007.evidence, "Service \"agent\": network_mode = \"host\"");

        // A hardened service emits none of the docker findings.
        let mut hardened = HashMap::new();
        hardened.insert(
            "agent".to_string(),
            DockerServiceConfig {
                read_only: Some(true),
                cap_drop: Some(vec!["ALL".to_string()]),
                security_opt: Some(vec!["no-new-privileges:true".to_string()]),
                network_mode: None,
                ..Default::default()
            },
        );
        let ctx2 = MockAuditContext::new()
            .with_config(OpenClawConfig {
                sandbox: Some(SandboxConfig {
                    mode: Some("all".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .with_docker(DockerComposeConfig {
                services: Some(hardened),
                ..Default::default()
            });
        let clean = check().run(&ctx2, &AuditOptions::default()).await;
        assert!(
            clean.is_empty(),
            "hardened docker service yields no findings"
        );
    }
}

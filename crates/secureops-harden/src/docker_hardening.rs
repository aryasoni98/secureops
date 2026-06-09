//! Docker hardening (priority 4) — port of `hardening/docker-hardening.ts`.
//!
//! `check` emits `SC-DOCKER-INFO` when no docker-compose config is present, and
//! otherwise reuses `SC-EXEC-004` / `SC-EXEC-007` for non-read-only and
//! host-network services found in `ctx.docker_compose()`. `fix` writes a hardened
//! `docker-compose.secureops.yml` override (as pretty JSON) and pushes a
//! `docker-override` action.

use crate::HardeningModule;
use async_trait::async_trait;
use secureops_core::config::{
    DockerComposeConfig, DockerDeploy, DockerLimits, DockerNetwork, DockerResources,
    DockerServiceConfig,
};
use secureops_core::{AuditContext, AuditFinding, HardeningAction, HardeningResult, Severity};
use std::collections::HashMap;
use std::path::Path;

pub struct DockerHardening;

#[async_trait]
impl HardeningModule for DockerHardening {
    fn name(&self) -> &'static str {
        "docker-hardening"
    }

    fn priority(&self) -> u32 {
        4
    }

    async fn check(&self, ctx: &dyn AuditContext) -> Vec<AuditFinding> {
        let mut findings: Vec<AuditFinding> = Vec::new();
        let dc = ctx.docker_compose();

        // `!dc?.services` in TS: no compose config OR no services map.
        let services = match dc.and_then(|c| c.services.as_ref()) {
            Some(s) => s,
            None => {
                findings.push(
                    AuditFinding::builder("SC-DOCKER-INFO", Severity::Info, "execution")
                        .title("No Docker Compose configuration found")
                        .description(
                            "Docker hardening checks skipped — no docker-compose.yml detected.",
                        )
                        .evidence("No docker-compose configuration in context")
                        .remediation(
                            "If using Docker, provide docker-compose.yml for security analysis",
                        )
                        .owasp_asi("ASI05")
                        .build(),
                );
                return findings;
            }
        };

        for (name, svc) in services.iter() {
            // `!svc.read_only` — missing OR false.
            if svc.read_only != Some(true) {
                findings.push(
                    AuditFinding::builder("SC-EXEC-004", Severity::Medium, "execution")
                        .title(format!("Service \"{name}\" not read-only"))
                        .description("Will add read_only: true.")
                        .evidence("read_only not set")
                        .remediation("Add read_only: true")
                        .auto_fixable(true)
                        .owasp_asi("ASI05")
                        .build(),
                );
            }
            if svc.network_mode.as_deref() == Some("host") {
                findings.push(
                    AuditFinding::builder("SC-EXEC-007", Severity::High, "execution")
                        .title(format!("Service \"{name}\" uses host network"))
                        .description("Will switch to bridge network.")
                        .evidence("network_mode = \"host\"")
                        .remediation("Remove host network mode")
                        .auto_fixable(true)
                        .owasp_asi("ASI05")
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

        // Mirrors the TS try/catch: any I/O failure pushes a single error string.
        match write_override(ctx, backup_dir).await {
            Ok(()) => {
                applied.push(HardeningAction {
                    id: "docker-override".into(),
                    description: "Generated hardened docker-compose override".into(),
                    before: "no override".into(),
                    after:
                        "docker-compose.secureops.yml with read-only, cap-drop=ALL, no-new-privileges"
                            .into(),
                });
            }
            Err(err) => {
                errors.push(format!("Docker hardening error: {err}"));
            }
        }

        HardeningResult {
            module: "docker-hardening".into(),
            applied,
            skipped,
            errors,
        }
    }
}

/// Build the hardened override config, back up any existing override, and write
/// the new one as 2-space pretty JSON (port of the `fix` try-block body).
async fn write_override(ctx: &dyn AuditContext, backup_dir: &Path) -> std::io::Result<()> {
    let override_path = Path::new(ctx.state_dir()).join("docker-compose.secureops.yml");

    // Backup existing override if present (TS swallows the "no existing override"
    // error in its inner try/catch).
    let _ = tokio::fs::copy(
        &override_path,
        backup_dir.join("docker-compose.secureops.yml"),
    )
    .await;

    let override_config = hardened_override_config();

    // Write as YAML-like JSON (user should convert to YAML for Docker), matching
    // `JSON.stringify(overrideConfig, null, 2)` — 2-space pretty, no trailing
    // newline.
    let json = serde_json::to_string_pretty(&override_config).map_err(std::io::Error::other)?;
    tokio::fs::write(&override_path, json).await
}

/// The `overrideConfig` literal from the TS `fix` (`openclaw-gateway` service +
/// `restricted-net` network), built from the HARDENED_* constants.
fn hardened_override_config() -> DockerComposeConfig {
    let mut services = HashMap::new();
    services.insert(
        "openclaw-gateway".to_string(),
        DockerServiceConfig {
            read_only: Some(true),
            cap_drop: Some(vec!["ALL".to_string()]),
            security_opt: Some(vec!["no-new-privileges:true".to_string()]),
            networks: Some(vec!["restricted-net".to_string()]),
            volumes: Some(vec!["openclaw-data:/app/data".to_string()]),
            deploy: Some(DockerDeploy {
                resources: Some(DockerResources {
                    limits: Some(DockerLimits {
                        memory: Some("2G".to_string()),
                        cpus: Some("2.0".to_string()),
                    }),
                }),
            }),
            network_mode: None,
        },
    );

    let mut networks = HashMap::new();
    networks.insert(
        "restricted-net".to_string(),
        DockerNetwork {
            driver: Some("bridge".to_string()),
            internal: Some(false),
        },
    );

    DockerComposeConfig {
        services: Some(services),
        networks: Some(networks),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureops_core::config::OpenClawConfig;
    use secureops_core::context::FileInfo;
    use std::collections::HashMap;
    use tempfile::tempdir;

    /// Minimal local mock — only the accessors docker-hardening touches.
    struct MockCtx {
        state_dir: String,
        config: OpenClawConfig,
        platform: String,
        docker: Option<DockerComposeConfig>,
    }

    impl Default for MockCtx {
        fn default() -> Self {
            MockCtx {
                state_dir: String::new(),
                config: OpenClawConfig::default(),
                platform: "linux".to_string(),
                docker: None,
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
            &self.platform
        }
        fn deployment_mode(&self) -> &str {
            "standalone"
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
        fn docker_compose(&self) -> Option<&DockerComposeConfig> {
            self.docker.as_ref()
        }
    }

    fn service(read_only: Option<bool>, network_mode: Option<&str>) -> DockerServiceConfig {
        DockerServiceConfig {
            read_only,
            network_mode: network_mode.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn no_compose_emits_info_only() {
        let ctx = MockCtx::default();
        let findings = DockerHardening.check(&ctx).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "SC-DOCKER-INFO");
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(!findings[0].auto_fixable);
    }

    #[tokio::test]
    async fn empty_services_map_emits_no_findings() {
        // dc present with an empty services map -> the per-service loop runs zero
        // times, so no findings (and crucially NOT the INFO finding, which fires
        // only when services is absent).
        let ctx = MockCtx {
            docker: Some(DockerComposeConfig {
                services: Some(HashMap::new()),
                networks: None,
            }),
            ..Default::default()
        };
        let findings = DockerHardening.check(&ctx).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn insecure_service_emits_exec_004_and_007() {
        let mut services = HashMap::new();
        services.insert("gw".to_string(), service(Some(false), Some("host")));
        let ctx = MockCtx {
            docker: Some(DockerComposeConfig {
                services: Some(services),
                networks: None,
            }),
            ..Default::default()
        };
        let findings = DockerHardening.check(&ctx).await;
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"SC-EXEC-004"));
        assert!(ids.contains(&"SC-EXEC-007"));

        let m = findings.iter().find(|f| f.id == "SC-EXEC-004").unwrap();
        assert_eq!(m.severity, Severity::Medium);
        assert_eq!(m.title, "Service \"gw\" not read-only");
        assert!(m.auto_fixable);

        let h = findings.iter().find(|f| f.id == "SC-EXEC-007").unwrap();
        assert_eq!(h.severity, Severity::High);
        assert_eq!(h.title, "Service \"gw\" uses host network");
        assert_eq!(h.evidence, "network_mode = \"host\"");
    }

    #[tokio::test]
    async fn read_only_bridge_service_emits_nothing() {
        let mut services = HashMap::new();
        services.insert("gw".to_string(), service(Some(true), Some("bridge")));
        let ctx = MockCtx {
            docker: Some(DockerComposeConfig {
                services: Some(services),
                networks: None,
            }),
            ..Default::default()
        };
        let findings = DockerHardening.check(&ctx).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn fix_writes_override_and_pushes_action() {
        let dir = tempdir().unwrap();
        let state_dir = dir.path().to_string_lossy().to_string();
        let backup = dir.path().join("backup");
        tokio::fs::create_dir_all(&backup).await.unwrap();

        let ctx = MockCtx {
            state_dir: state_dir.clone(),
            ..Default::default()
        };

        let result = DockerHardening.fix(&ctx, &backup).await;
        assert_eq!(result.module, "docker-hardening");
        assert_eq!(result.applied.len(), 1);
        assert_eq!(result.applied[0].id, "docker-override");
        assert!(result.errors.is_empty());

        // The override file exists and parses back into the hardened config.
        let override_path = dir.path().join("docker-compose.secureops.yml");
        let content = tokio::fs::read_to_string(&override_path).await.unwrap();
        let parsed: DockerComposeConfig = serde_json::from_str(&content).unwrap();
        let svc = parsed
            .services
            .as_ref()
            .unwrap()
            .get("openclaw-gateway")
            .unwrap();
        assert_eq!(svc.read_only, Some(true));
        assert_eq!(svc.cap_drop, Some(vec!["ALL".to_string()]));
        assert_eq!(
            svc.security_opt,
            Some(vec!["no-new-privileges:true".to_string()])
        );
        assert!(parsed
            .networks
            .as_ref()
            .unwrap()
            .contains_key("restricted-net"));
    }
}

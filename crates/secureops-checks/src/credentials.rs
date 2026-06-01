//! Credentials category (PRODUCT.md A.4, B.2).
//!
//! Ports `auditCredentials` from `secureops/src/auditor.ts`: scans config and
//! state files for plaintext secrets, weak/default auth tokens, and over-broad
//! credential file permissions (SC-CRED-\*).

use async_trait::async_trait;
use secureops_core::{
    AuditContext, AuditFinding, AuditOptions, Check, IocDatabase, MaestroLayer, NistAttackType,
    Severity,
};
use std::sync::Arc;

use crate::patterns::API_KEY_PATTERNS;

/// Audits credential handling (`auditCredentials`). Emits `"credentials"` findings.
pub struct CredentialsCheck {
    db: Arc<IocDatabase>,
}

impl CredentialsCheck {
    pub fn new(db: Arc<IocDatabase>) -> Self {
        Self { db }
    }
}

/// Returns the final path component (port of Node's `path.basename`).
fn basename(p: &str) -> &str {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or(p)
}

/// Port of `scanForApiKeys`: recursively scan `.md`/`.json` files under the state
/// dir for API key patterns, skipping `.secureops*` and `node_modules` dirs.
async fn scan_for_api_keys(ctx: &dyn AuditContext) -> Vec<String> {
    const MAX_DEPTH: usize = 5;
    let mut matches: Vec<String> = Vec::new();
    // Recursion implemented iteratively (async fn can't recurse without boxing);
    // preserves depth-first, in-order traversal of the TS version.
    let mut stack: Vec<(String, usize)> = vec![(ctx.state_dir().to_string(), 0)];

    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        let entries = ctx.list_dir(&dir).await;
        // Collect children to push so DFS order matches the recursive TS version.
        let mut to_recurse: Vec<(String, usize)> = Vec::new();
        for entry in &entries {
            let full_path = format!("{}/{}", dir, entry);
            if entry.ends_with(".md") || entry.ends_with(".json") {
                if let Some(content) = ctx.read_file(&full_path).await {
                    if API_KEY_PATTERNS.iter().any(|p| p.is_match(&content)) {
                        matches.push(full_path.clone());
                    }
                }
            }
            // Recurse into subdirectories (but skip .secureops and node_modules)
            if !entry.starts_with(".secureops") && entry != "node_modules" {
                let children = ctx.list_dir(&full_path).await;
                if !children.is_empty() {
                    to_recurse.push((full_path, depth + 1));
                }
            }
        }
        // Push in reverse so they pop in original order (DFS, in source order).
        for item in to_recurse.into_iter().rev() {
            stack.push(item);
        }
    }

    matches
}

#[async_trait]
impl Check for CredentialsCheck {
    fn category(&self) -> &'static str {
        "credentials"
    }

    async fn run(&self, ctx: &dyn AuditContext, _opts: &AuditOptions) -> Vec<AuditFinding> {
        let _db = &*self.db;
        let mut findings: Vec<AuditFinding> = Vec::new();

        // CRED-001: State directory permissions
        let state_dir_perms = ctx.get_file_permissions(ctx.state_dir()).await;
        if let Some(perms) = state_dir_perms {
            if (perms & 0o077) != 0 {
                findings.push(AuditFinding {
                    id: "SC-CRED-001".to_string(),
                    severity: Severity::High,
                    category: "credentials".to_string(),
                    title: "State directory has excessive permissions".to_string(),
                    description: format!(
                        "~/.openclaw/ directory is accessible by group/other users ({:o}).",
                        perms
                    ),
                    evidence: format!("Permissions: {:o} (expected: 700)", perms),
                    remediation: "Run: chmod 700 ~/.openclaw/".to_string(),
                    auto_fixable: true,
                    references: vec![],
                    owasp_asi: "ASI03".to_string(),
                    maestro_layer: Some(MaestroLayer::L4),
                    nist_category: Some(NistAttackType::Privacy),
                });
            }
        }

        // CRED-002: Config file permissions
        let config_path = format!("{}/openclaw.json", ctx.state_dir());
        let config_perms = ctx.get_file_permissions(&config_path).await;
        if let Some(perms) = config_perms {
            if (perms & 0o077) != 0 {
                findings.push(AuditFinding {
                    id: "SC-CRED-002".to_string(),
                    severity: Severity::High,
                    category: "credentials".to_string(),
                    title: "Config file has excessive permissions".to_string(),
                    description: format!(
                        "openclaw.json is readable by group/other users ({:o}).",
                        perms
                    ),
                    evidence: format!("Permissions: {:o} (expected: 600)", perms),
                    remediation: "Run: chmod 600 ~/.openclaw/openclaw.json".to_string(),
                    auto_fixable: true,
                    references: vec![],
                    owasp_asi: "ASI03".to_string(),
                    maestro_layer: Some(MaestroLayer::L4),
                    nist_category: Some(NistAttackType::Privacy),
                });
            }
        }

        // CRED-003: .env file with plaintext API keys
        let env_path = format!("{}/.env", ctx.state_dir());
        let env_content = ctx.read_file(&env_path).await;
        if let Some(env_content) = env_content {
            let has_keys = API_KEY_PATTERNS.iter().any(|p| p.is_match(&env_content));
            if has_keys {
                findings.push(AuditFinding {
                    id: "SC-CRED-003".to_string(),
                    severity: Severity::High,
                    category: "credentials".to_string(),
                    title: "Plaintext API keys in .env file".to_string(),
                    description:
                        "API keys are stored in plaintext in .env file. These are targeted by infostealers."
                            .to_string(),
                    evidence: ".env file contains API key patterns".to_string(),
                    remediation:
                        "Encrypt .env using secureops credential-hardening or use a secrets manager"
                            .to_string(),
                    auto_fixable: true,
                    references: vec![],
                    owasp_asi: "ASI03".to_string(),
                    maestro_layer: Some(MaestroLayer::L4),
                    nist_category: Some(NistAttackType::Privacy),
                });
            }
        }

        // CRED-004: credentials/*.json permissions
        let creds_dir = format!("{}/credentials", ctx.state_dir());
        let cred_files = ctx.list_dir(&creds_dir).await;
        for file in &cred_files {
            if !file.ends_with(".json") {
                continue;
            }
            let file_path = format!("{}/{}", creds_dir, file);
            let perms = ctx.get_file_permissions(&file_path).await;
            if let Some(perms) = perms {
                if (perms & 0o077) != 0 {
                    findings.push(AuditFinding {
                        id: "SC-CRED-004".to_string(),
                        severity: Severity::High,
                        category: "credentials".to_string(),
                        title: format!("Credential file \"{}\" has excessive permissions", file),
                        description: format!(
                            "Credential file is readable by group/other users ({:o}).",
                            perms
                        ),
                        evidence: format!("{}: permissions {:o}", file_path, perms),
                        remediation: format!("Run: chmod 600 {}", file_path),
                        auto_fixable: true,
                        references: vec![],
                        owasp_asi: "ASI03".to_string(),
                        maestro_layer: Some(MaestroLayer::L4),
                        nist_category: Some(NistAttackType::Privacy),
                    });
                }
            }
        }

        // CRED-005: auth-profiles.json permissions
        let agents_dir = format!("{}/agents", ctx.state_dir());
        let agents = ctx.list_dir(&agents_dir).await;
        for agent in &agents {
            let auth_profile_path = format!("{}/{}/agent/auth-profiles.json", agents_dir, agent);
            let exists = ctx.file_exists(&auth_profile_path).await;
            if !exists {
                continue;
            }
            let perms = ctx.get_file_permissions(&auth_profile_path).await;
            if let Some(perms) = perms {
                if (perms & 0o077) != 0 {
                    findings.push(AuditFinding {
                        id: "SC-CRED-005".to_string(),
                        severity: Severity::High,
                        category: "credentials".to_string(),
                        title: format!(
                            "Auth profiles for agent \"{}\" have excessive permissions",
                            agent
                        ),
                        description: format!(
                            "auth-profiles.json is readable by group/other users ({:o}).",
                            perms
                        ),
                        evidence: format!("{}: permissions {:o}", auth_profile_path, perms),
                        remediation: format!("Run: chmod 600 {}", auth_profile_path),
                        auto_fixable: true,
                        references: vec![],
                        owasp_asi: "ASI03".to_string(),
                        maestro_layer: Some(MaestroLayer::L4),
                        nist_category: Some(NistAttackType::Privacy),
                    });
                }
            }
        }

        // CRED-006: OAuth tokens in plaintext
        for file in &cred_files {
            if !file.ends_with(".json") {
                continue;
            }
            let file_path = format!("{}/{}", creds_dir, file);
            let content = ctx.read_file(&file_path).await;
            if let Some(content) = content {
                if content.contains("\"access_token\"") || content.contains("\"refresh_token\"") {
                    findings.push(AuditFinding {
                        id: "SC-CRED-006".to_string(),
                        severity: Severity::Medium,
                        category: "credentials".to_string(),
                        title: format!("OAuth tokens in plaintext in \"{}\"", file),
                        description:
                            "OAuth access/refresh tokens are stored in plaintext, vulnerable to infostealer theft."
                                .to_string(),
                        evidence: format!("{} contains OAuth token fields", file_path),
                        remediation:
                            "Encrypt credential files using secureops credential-hardening"
                                .to_string(),
                        auto_fixable: true,
                        references: vec![],
                        owasp_asi: "ASI03".to_string(),
                        maestro_layer: Some(MaestroLayer::L4),
                        nist_category: Some(NistAttackType::Privacy),
                    });
                }
            }
        }

        // CRED-007: API keys in memory/soul files
        let memory_files = ["soul.md", "MEMORY.md", "SOUL.md"];
        for agent in &agents {
            for mem_file in &memory_files {
                let mem_path = format!("{}/{}/{}", agents_dir, agent, mem_file);
                let content = ctx.read_file(&mem_path).await;
                if let Some(content) = content {
                    let has_keys = API_KEY_PATTERNS.iter().any(|p| p.is_match(&content));
                    if has_keys {
                        findings.push(AuditFinding {
                            id: "SC-CRED-007".to_string(),
                            severity: Severity::Critical,
                            category: "credentials".to_string(),
                            title: format!("API keys found in memory file \"{}\"", mem_file),
                            description:
                                "API keys are present in LLM memory files. These leak credentials into the model context."
                                    .to_string(),
                            evidence: format!("{} contains API key patterns", mem_path),
                            remediation:
                                "Remove API keys from memory files and redact using secureops credential-hardening"
                                    .to_string(),
                            auto_fixable: true,
                            references: vec![],
                            owasp_asi: "ASI03".to_string(),
                            maestro_layer: Some(MaestroLayer::L4),
                            nist_category: Some(NistAttackType::Privacy),
                        });
                    }
                }
            }
        }

        // CRED-008: Scan all .md and .json files under state dir for API keys
        let all_files = scan_for_api_keys(ctx).await;
        for m in &all_files {
            // Don't duplicate findings already covered above
            if m.contains("soul.md") || m.contains("MEMORY.md") || m.contains("SOUL.md") {
                continue;
            }
            if m.contains(".env") {
                continue;
            }
            findings.push(AuditFinding {
                id: "SC-CRED-008".to_string(),
                severity: Severity::High,
                category: "credentials".to_string(),
                title: "API key found in configuration file".to_string(),
                description: format!("API key pattern detected in {}.", basename(m)),
                evidence: format!("File: {}", m),
                remediation: "Remove or redact API keys from this file".to_string(),
                auto_fixable: false,
                references: vec![],
                owasp_asi: "ASI03".to_string(),
                maestro_layer: Some(MaestroLayer::L4),
                nist_category: Some(NistAttackType::Privacy),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockAuditContext;
    use secureops_core::IocDatabase;

    fn check() -> CredentialsCheck {
        CredentialsCheck::new(Arc::new(IocDatabase::default()))
    }

    fn opts() -> AuditOptions {
        AuditOptions {
            deep: false,
            fix: false,
            json: false,
        }
    }

    fn ids(findings: &[AuditFinding]) -> Vec<String> {
        findings.iter().map(|f| f.id.clone()).collect()
    }

    #[tokio::test]
    async fn clean_config_yields_no_findings() {
        // No perms, no files, no dirs -> nothing fires.
        let ctx = MockAuditContext::new();
        let findings = check().run(&ctx, &opts()).await;
        assert!(
            findings.is_empty(),
            "expected no findings, got {:?}",
            ids(&findings)
        );
    }

    #[tokio::test]
    async fn proper_perms_yield_no_perm_findings() {
        // 700 state dir + 600 config -> no CRED-001/002.
        let ctx = MockAuditContext::new()
            .with_perms("/state", 0o700)
            .with_file("/state/openclaw.json", "{}")
            .with_perms("/state/openclaw.json", 0o600);
        let findings = check().run(&ctx, &opts()).await;
        assert!(!ids(&findings).contains(&"SC-CRED-001".to_string()));
        assert!(!ids(&findings).contains(&"SC-CRED-002".to_string()));
    }

    #[tokio::test]
    async fn excessive_perms_fire_cred_001_and_002() {
        let ctx = MockAuditContext::new()
            .with_perms("/state", 0o755)
            .with_file("/state/openclaw.json", "{}")
            .with_perms("/state/openclaw.json", 0o644);
        let findings = check().run(&ctx, &opts()).await;
        let got = ids(&findings);
        assert!(got.contains(&"SC-CRED-001".to_string()));
        assert!(got.contains(&"SC-CRED-002".to_string()));

        let f1 = findings.iter().find(|f| f.id == "SC-CRED-001").unwrap();
        assert_eq!(f1.severity, Severity::High);
        assert_eq!(f1.evidence, "Permissions: 755 (expected: 700)");
        assert_eq!(
            f1.description,
            "~/.openclaw/ directory is accessible by group/other users (755)."
        );
        assert_eq!(f1.maestro_layer, Some(MaestroLayer::L4));
        assert_eq!(f1.nist_category, Some(NistAttackType::Privacy));

        let f2 = findings.iter().find(|f| f.id == "SC-CRED-002").unwrap();
        assert_eq!(f2.evidence, "Permissions: 644 (expected: 600)");
    }

    #[tokio::test]
    async fn env_keys_and_memory_keys_fire() {
        // .env with key -> CRED-003 (and NOT CRED-008 because .env is excluded).
        // soul.md with key -> CRED-007.
        let ctx = MockAuditContext::new()
            .with_file(
                "/state/.env",
                "OPENAI_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz123",
            )
            .with_dir("/state", &["agents", ".env"])
            .with_dir("/state/agents", &["bot"])
            .with_dir("/state/agents/bot", &["soul.md"])
            .with_file(
                "/state/agents/bot/soul.md",
                "key: sk-ant-abcdefghijklmnopqrstuvwxyz123",
            );
        let findings = check().run(&ctx, &opts()).await;
        let got = ids(&findings);
        assert!(got.contains(&"SC-CRED-003".to_string()));
        assert!(got.contains(&"SC-CRED-007".to_string()));
        // .env must be excluded from CRED-008, and soul.md is also excluded.
        assert!(!got.contains(&"SC-CRED-008".to_string()));

        let f7 = findings.iter().find(|f| f.id == "SC-CRED-007").unwrap();
        assert_eq!(f7.severity, Severity::Critical);
        assert_eq!(f7.title, "API keys found in memory file \"soul.md\"");
    }

    #[tokio::test]
    async fn oauth_tokens_and_cred_perms_fire() {
        let ctx = MockAuditContext::new()
            .with_dir("/state/credentials", &["google.json"])
            .with_file(
                "/state/credentials/google.json",
                "{\"access_token\": \"abc\"}",
            )
            .with_perms("/state/credentials/google.json", 0o644);
        let findings = check().run(&ctx, &opts()).await;
        let got = ids(&findings);
        assert!(got.contains(&"SC-CRED-004".to_string()));
        assert!(got.contains(&"SC-CRED-006".to_string()));

        let f6 = findings.iter().find(|f| f.id == "SC-CRED-006").unwrap();
        assert_eq!(f6.severity, Severity::Medium);
        assert_eq!(f6.title, "OAuth tokens in plaintext in \"google.json\"");
        assert_eq!(
            f6.evidence,
            "/state/credentials/google.json contains OAuth token fields"
        );
    }
}

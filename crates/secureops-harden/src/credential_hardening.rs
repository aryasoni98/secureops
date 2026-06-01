//! Credential hardening (priority 2) — port of `hardening/credential-hardening.ts`.
//!
//! Locks down secrets on disk: `chmod 700` the state dir, `chmod 600` the
//! config / credential files / per-agent `auth-profiles.json`, and redacts
//! API keys from agent memory/soul files (backing each touched file up first).
//!
//! `.env` encryption: when a `.env` is present, it is backed up and encrypted
//! to `.env.enc` (AES-256-GCM, machine-keyed via
//! [`secureops_crypto::machinekey`]), pushing `cred-env-encrypt` — a faithful
//! port of the TS block (kept inside a `try`-equivalent: keystore failure skips
//! the action rather than erroring the run).
//!
//! Per the crate trait, this module also implements `check()` (emits
//! `SC-CRED-001` when the state directory is group/other-accessible).

use crate::HardeningModule;
use async_trait::async_trait;
use secureops_core::{AuditContext, AuditFinding, HardeningAction, HardeningResult, Severity};
use std::path::Path;

/// API-key prefixes redacted from memory/soul files (port of `API_KEY_PATTERNS`).
///
/// The TS uses JS regex; we match the same shapes with a tiny hand-rolled
/// scanner (no `regex` crate dep in this crate): a known prefix followed by
/// >= 20 chars of `[A-Za-z0-9_-]`. Order mirrors the TS array exactly.
const API_KEY_PREFIXES: &[&str] = &["sk-ant-", "sk-proj-", "sk-", "xoxb-", "xoxp-"];

const REDACTED: &str = "[REDACTED_BY_SECUREOPS]";

/// Is `b` part of the `[a-zA-Z0-9_-]` token character class?
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Replace every API-key-looking substring with `[REDACTED_BY_SECUREOPS]`
/// (port of `redactApiKeys`). Iterates the prefixes in the same order as the TS
/// `API_KEY_PATTERNS` array, applying each pattern's global replace in turn.
fn redact_api_keys(content: &str) -> String {
    let mut redacted = content.to_string();
    for prefix in API_KEY_PREFIXES {
        redacted = redact_one(&redacted, prefix);
    }
    redacted
}

/// Global replace for a single `<prefix>[A-Za-z0-9_-]{20,}` pattern.
fn redact_one(input: &str, prefix: &str) -> String {
    let bytes = input.as_bytes();
    let prefix_len = prefix.len();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if input[i..].starts_with(prefix) {
            // Count token chars following the prefix.
            let run_start = i + prefix_len;
            let mut j = run_start;
            while j < bytes.len() && is_token_char(bytes[j]) {
                j += 1;
            }
            if j - run_start >= 20 {
                out.push_str(REDACTED);
                i = j;
                continue;
            }
        }
        // Push this byte as part of the (UTF-8 safe) char it belongs to.
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// `chmod` that swallows errors, returning `true` only on success
/// (faithful port of `chmodSafe`). On non-unix platforms it is a no-op
/// returning `false`.
async fn chmod_safe(path: &Path, mode: u32) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .await
            .is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        false
    }
}

pub struct CredentialHardening;

#[async_trait]
impl HardeningModule for CredentialHardening {
    fn name(&self) -> &'static str {
        "credential-hardening"
    }

    fn priority(&self) -> u32 {
        2
    }

    async fn check(&self, ctx: &dyn AuditContext) -> Vec<AuditFinding> {
        let mut findings: Vec<AuditFinding> = Vec::new();

        let state_dir_perms = ctx.get_file_permissions(ctx.state_dir()).await;
        if let Some(perms) = state_dir_perms {
            if (perms & 0o077) != 0 {
                findings.push(AuditFinding {
                    id: "SC-CRED-001".to_string(),
                    severity: Severity::High,
                    category: "credentials".to_string(),
                    title: "State directory permissions too open".to_string(),
                    description: "Will chmod 700 the state directory.".to_string(),
                    evidence: format!("Permissions: {:o}", perms),
                    remediation: "chmod 700".to_string(),
                    auto_fixable: true,
                    references: vec![],
                    owasp_asi: "ASI03".to_string(),
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

        // The TS body is wrapped in one big try/catch; map that onto a single
        // Result boundary so an unexpected I/O error becomes the same error
        // string the TS would push.
        if let Err(e) = self.run_fix(ctx, backup_dir, &mut applied).await {
            errors.push(format!("Credential hardening error: {e}"));
        }

        HardeningResult {
            module: "credential-hardening".to_string(),
            applied,
            skipped,
            errors,
        }
    }
}

impl CredentialHardening {
    /// Body of `fix()`, separated so the outer `try { … } catch` semantics of
    /// the TS source map onto a single `Result` boundary.
    async fn run_fix(
        &self,
        ctx: &dyn AuditContext,
        backup_dir: &Path,
        applied: &mut Vec<HardeningAction>,
    ) -> std::io::Result<()> {
        let state_dir = Path::new(ctx.state_dir());

        // 1. Lock state directory permissions
        let state_dir_fixed = chmod_safe(state_dir, 0o700).await;
        if state_dir_fixed {
            applied.push(HardeningAction {
                id: "cred-statedir-perms".to_string(),
                description: "Set state directory permissions to 700".to_string(),
                before: "open".to_string(),
                after: "700".to_string(),
            });
        }

        // 2. Lock config file permissions
        let config_path = state_dir.join("openclaw.json");
        let config_fixed = chmod_safe(&config_path, 0o600).await;
        if config_fixed {
            applied.push(HardeningAction {
                id: "cred-config-perms".to_string(),
                description: "Set config file permissions to 600".to_string(),
                before: "open".to_string(),
                after: "600".to_string(),
            });
        }

        // 3. Lock credential files
        let creds_dir = state_dir.join("credentials");
        if let Ok(mut rd) = tokio::fs::read_dir(&creds_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let file = entry.file_name().to_string_lossy().to_string();
                if !file.ends_with(".json") {
                    continue;
                }
                let file_path = creds_dir.join(&file);
                // Backup (skip on error, like the TS inner try/catch).
                let _ = tokio::fs::copy(&file_path, backup_dir.join(format!("cred-{file}"))).await;
                let fixed = chmod_safe(&file_path, 0o600).await;
                if fixed {
                    applied.push(HardeningAction {
                        id: format!("cred-{file}-perms"),
                        description: format!("Set {file} permissions to 600"),
                        before: "open".to_string(),
                        after: "600".to_string(),
                    });
                }
            }
        }
        // else: no credentials directory — nothing to do.

        // 4. Lock auth-profiles
        let agents_dir = state_dir.join("agents");
        if let Ok(mut rd) = tokio::fs::read_dir(&agents_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let agent = entry.file_name().to_string_lossy().to_string();
                let auth_path = agents_dir
                    .join(&agent)
                    .join("agent")
                    .join("auth-profiles.json");
                // The TS checks fs.access first and only acts if the file exists.
                if tokio::fs::metadata(&auth_path).await.is_ok() {
                    let _ = tokio::fs::copy(
                        &auth_path,
                        backup_dir.join(format!("auth-profiles-{agent}.json")),
                    )
                    .await;
                    chmod_safe(&auth_path, 0o600).await;
                    applied.push(HardeningAction {
                        id: format!("cred-auth-{agent}"),
                        description: format!(
                            "Set auth-profiles.json permissions for agent \"{agent}\" to 600"
                        ),
                        before: "open".to_string(),
                        after: "600".to_string(),
                    });
                }
            }
        }
        // else: no agents directory.

        // 5. Encrypt .env file (AES-256-GCM, machine-keyed) — port of the TS
        //    `.env` block. Back up, derive the machine key via the keystore,
        //    encrypt to `.env.enc` (0o600), and record `cred-env-encrypt`.
        let env_path = state_dir.join(".env");
        if let Ok(env_content) = tokio::fs::read_to_string(&env_path).await {
            let _ = tokio::fs::copy(&env_path, backup_dir.join(".env")).await;
            match secureops_crypto::machinekey::ensure_keystore(ctx.state_dir()).await {
                Ok((machine_id, _)) => {
                    let enc = secureops_crypto::machinekey::encrypt(
                        &env_content,
                        &machine_id,
                        ctx.state_dir(),
                    );
                    let enc_path = format!("{}/.env.enc", ctx.state_dir());
                    if tokio::fs::write(&enc_path, &enc).await.is_ok() {
                        let _ = chmod_safe(Path::new(&enc_path), 0o600).await;
                        applied.push(HardeningAction {
                            id: "cred-env-encrypt".to_string(),
                            description: "Encrypted .env file".to_string(),
                            before: "plaintext".to_string(),
                            after: ".env.enc (AES-256-GCM)".to_string(),
                        });
                    }
                }
                Err(_) => { /* keystore unavailable: skip, like the TS catch */ }
            }
        }

        // 6. Redact API keys from memory/soul files
        if let Ok(mut rd) = tokio::fs::read_dir(&agents_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let agent = entry.file_name().to_string_lossy().to_string();
                for mem_file in ["soul.md", "SOUL.md", "MEMORY.md"] {
                    let mem_path = agents_dir.join(&agent).join(mem_file);
                    if let Ok(content) = tokio::fs::read_to_string(&mem_path).await {
                        let redacted = redact_api_keys(&content);
                        if redacted != content {
                            let _ = tokio::fs::copy(
                                &mem_path,
                                backup_dir.join(format!("{agent}-{mem_file}")),
                            )
                            .await;
                            tokio::fs::write(&mem_path, &redacted).await?;
                            applied.push(HardeningAction {
                                id: format!("cred-redact-{agent}-{mem_file}"),
                                description: format!(
                                    "Redacted API keys from {mem_file} for agent \"{agent}\""
                                ),
                                before: "contained API keys".to_string(),
                                after: "keys redacted".to_string(),
                            });
                        }
                    }
                }
            }
        }
        // else: no agents directory.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureops_core::OpenClawConfig;
    use std::collections::HashMap;

    /// Minimal in-crate mock — only implements the accessors the tests touch.
    struct MockCtx {
        state_dir: String,
        config: OpenClawConfig,
        perms: HashMap<String, u32>,
    }

    impl MockCtx {
        fn new(state_dir: &str) -> Self {
            MockCtx {
                state_dir: state_dir.to_string(),
                config: OpenClawConfig::default(),
                perms: HashMap::new(),
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
            "darwin-arm64"
        }
        fn deployment_mode(&self) -> &str {
            "local"
        }
        fn openclaw_version(&self) -> &str {
            "0.0.0"
        }
        async fn file_info(&self, path: &str) -> secureops_core::FileInfo {
            secureops_core::FileInfo {
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
        async fn get_file_permissions(&self, path: &str) -> Option<u32> {
            self.perms.get(path).copied()
        }
    }

    #[test]
    fn redact_api_keys_replaces_known_prefixes() {
        let input =
            "key sk-ant-abcdefghijklmnopqrstuvwxyz0123 and xoxb-ABCDEFGHIJKLMNOPQRSTUVWX done";
        let out = redact_api_keys(input);
        assert!(out.contains("[REDACTED_BY_SECUREOPS]"));
        assert!(!out.contains("sk-ant-abcdefghijklmnopqrstuvwxyz0123"));
        assert!(!out.contains("xoxb-ABCDEFGHIJKLMNOPQRSTUVWX"));
        // A short, non-matching token is left intact.
        let short = redact_api_keys("sk-abc");
        assert_eq!(short, "sk-abc");
    }

    #[tokio::test]
    async fn check_flags_open_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_string_lossy().to_string();
        let mut ctx = MockCtx::new(&sd);
        // group/other readable -> (perms & 0o077) != 0
        ctx.perms.insert(sd.clone(), 0o755);

        let findings = CredentialHardening.check(&ctx).await;
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.id, "SC-CRED-001");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.category, "credentials");
        assert_eq!(f.owasp_asi, "ASI03");
        assert!(f.auto_fixable);
        assert_eq!(f.evidence, "Permissions: 755");
        assert!(f.maestro_layer.is_none());
        assert!(f.nist_category.is_none());
    }

    #[tokio::test]
    async fn check_clean_state_dir_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_string_lossy().to_string();
        let mut ctx = MockCtx::new(&sd);
        ctx.perms.insert(sd.clone(), 0o700);

        let findings = CredentialHardening.check(&ctx).await;
        assert!(findings.is_empty());

        // No recorded permissions at all -> also no finding (None branch).
        let ctx2 = MockCtx::new(&sd);
        assert!(CredentialHardening.check(&ctx2).await.is_empty());
    }

    #[tokio::test]
    async fn fix_redacts_memory_and_encrypts_env() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path();
        let backup = dir.path().join("backup");
        tokio::fs::create_dir_all(&backup).await.unwrap();

        // openclaw.json present so cred-config-perms can fire on unix.
        tokio::fs::write(sd.join("openclaw.json"), "{}")
            .await
            .unwrap();

        // An agent with a memory file containing an API key.
        let agent_dir = sd.join("agents").join("alpha");
        tokio::fs::create_dir_all(&agent_dir).await.unwrap();
        let soul = agent_dir.join("soul.md");
        tokio::fs::write(&soul, "token: sk-ant-abcdefghijklmnopqrstuvwxyz0123 end")
            .await
            .unwrap();

        // A .env file: backed up + encrypted to .env.enc (cred-env-encrypt).
        tokio::fs::write(sd.join(".env"), "SECRET=1").await.unwrap();

        let ctx = MockCtx::new(&sd.to_string_lossy());
        let result = CredentialHardening.fix(&ctx, &backup).await;

        assert_eq!(result.module, "credential-hardening");
        assert!(result.errors.is_empty());

        // Memory redaction action present and file rewritten.
        let redact_id = "cred-redact-alpha-soul.md";
        assert!(
            result.applied.iter().any(|a| a.id == redact_id),
            "expected redaction action, got: {:?}",
            result.applied.iter().map(|a| &a.id).collect::<Vec<_>>()
        );
        let new_soul = tokio::fs::read_to_string(&soul).await.unwrap();
        assert!(new_soul.contains("[REDACTED_BY_SECUREOPS]"));
        assert!(!new_soul.contains("sk-ant-"));

        // .env backed up AND encrypted: cred-env-encrypt fired, .env.enc exists,
        // and it round-trips back to the original plaintext.
        assert!(tokio::fs::metadata(backup.join(".env")).await.is_ok());
        assert!(
            result.applied.iter().any(|a| a.id == "cred-env-encrypt"),
            "cred-env-encrypt should fire when .env present"
        );
        let enc = tokio::fs::read(sd.join(".env.enc")).await.unwrap();
        let (machine_id, _) = secureops_crypto::machinekey::ensure_keystore(&sd.to_string_lossy())
            .await
            .unwrap();
        let pt = secureops_crypto::machinekey::decrypt(&enc, &machine_id, &sd.to_string_lossy())
            .unwrap();
        assert_eq!(pt, "SECRET=1");
    }
}

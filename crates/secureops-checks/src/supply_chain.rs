//! Supply-chain category (PRODUCT.md A.4, B.2).
//!
//! Ports `auditSupplyChain` from `secureops/src/auditor.ts` (lines 920-1078):
//! inspects installed skills for dangerous code patterns, known-malicious file
//! hashes, young GitHub accounts, typosquatting and dangerous README
//! prerequisites (SC-SKILL-\*). Uses `secureops-intel` for IOC lookups +
//! hashing and the shared `crate::patterns::DANGEROUS_SKILL_PATTERNS`. Emits the
//! `"supply-chain"` category. MAESTRO L7.

use async_trait::async_trait;
use secureops_core::{
    AuditContext, AuditFinding, AuditOptions, Check, IocDatabase, MaestroLayer, NistAttackType,
    Severity,
};
use std::sync::{Arc, LazyLock};

/// The raw TypeScript `RegExp.source` strings for each entry of
/// `DANGEROUS_SKILL_PATTERNS`, index-aligned with
/// [`crate::patterns::DANGEROUS_SKILL_PATTERNS`].
///
/// The TS `SC-SKILL-002` evidence renders `matches ${pattern.source}`. JS
/// `.source` excludes the `/i` flag and keeps the literal `\/` escapes, so it is
/// **not** identical to the Rust `Regex::as_str()` of the shared patterns (which
/// store `(?i)base64.*decode` and `~/\.openclaw`). We keep this parallel table so
/// the evidence text is byte-for-byte faithful to the TS output while the actual
/// matching still uses the shared compiled regexes.
static DANGEROUS_SKILL_PATTERN_SOURCES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        r"child_process",
        r"\.exec\s*\(",
        r"\.spawn\s*\(",
        r"eval\s*\(",
        r"Function\s*\(",
        r"webhook\.site",
        r"reverse.shell",
        r"base64.*decode",
        r"curl\s+.*\|\s*sh",
        r"wget\s+.*\|\s*sh",
        r"~\/\.openclaw",
        r"~\/\.clawdbot",
        r"creds\.json",
        r"\.env",
        r"auth-profiles",
        r"LD_PRELOAD",
        r"DYLD_INSERT",
        r"NODE_OPTIONS",
    ]
});

/// Audits skill/plugin supply chain (`auditSupplyChain`). Emits `"supply-chain"`
/// findings.
pub struct SupplyChainCheck {
    db: Arc<IocDatabase>,
}

impl SupplyChainCheck {
    pub fn new(db: Arc<IocDatabase>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Check for SupplyChainCheck {
    fn category(&self) -> &'static str {
        "supply-chain"
    }

    async fn run(&self, ctx: &dyn AuditContext, _opts: &AuditOptions) -> Vec<AuditFinding> {
        let db = &*self.db;
        let mut findings: Vec<AuditFinding> = Vec::new();
        let skills = ctx.skills();

        // SC-001: Installed skills count
        let skill_names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        let installed_list = if skill_names.is_empty() {
            "none".to_string()
        } else {
            skill_names.join(", ")
        };
        findings.push(AuditFinding {
            id: "SC-SKILL-001".to_string(),
            severity: Severity::Info,
            category: "supply-chain".to_string(),
            title: format!("{} skill(s) installed", skills.len()),
            description: format!(
                "Found {} installed skills. Each skill has access to agent capabilities.",
                skills.len()
            ),
            evidence: format!("Installed skills: {}", installed_list),
            remediation: "Review each installed skill for necessity and trustworthiness"
                .to_string(),
            auto_fixable: false,
            references: vec![],
            owasp_asi: "ASI04".to_string(),
            maestro_layer: Some(MaestroLayer::L7),
            nist_category: Some(NistAttackType::Poisoning),
        });

        // SC-002..005: Scan each skill for dangerous patterns
        for skill in skills {
            let skill_dir = join(ctx.state_dir(), &["skills", &skill.name]);
            let skill_files = ctx.list_dir(&skill_dir).await;

            for file in &skill_files {
                let file_path = join(&skill_dir, &[file]);
                let content = match ctx.read_file(&file_path).await {
                    Some(c) if !c.is_empty() => c,
                    _ => continue,
                };

                // Check dangerous patterns
                for (idx, dsp) in crate::patterns::DANGEROUS_SKILL_PATTERNS.iter().enumerate() {
                    if dsp.pattern.is_match(&content) {
                        let source = DANGEROUS_SKILL_PATTERN_SOURCES
                            .get(idx)
                            .copied()
                            .unwrap_or_else(|| dsp.pattern.as_str());
                        findings.push(AuditFinding {
                            id: "SC-SKILL-002".to_string(),
                            severity: Severity::High,
                            category: "supply-chain".to_string(),
                            title: format!("Dangerous pattern in skill \"{}\"", skill.name),
                            description: format!(
                                "Found {} in {}. This may indicate malicious behavior.",
                                dsp.description, file
                            ),
                            evidence: format!("{}: matches {}", file_path, source),
                            remediation: "Review the skill source code and remove if suspicious"
                                .to_string(),
                            auto_fixable: false,
                            references: vec![],
                            owasp_asi: "ASI04".to_string(),
                            maestro_layer: Some(MaestroLayer::L7),
                            nist_category: Some(NistAttackType::Poisoning),
                        });
                    }
                }

                // Check hash against IOC database
                let file_hash = secureops_intel::hash_string(&content);
                if let Some(campaign) = secureops_intel::is_known_malicious_hash(db, &file_hash) {
                    findings.push(AuditFinding {
                        id: "SC-SKILL-003".to_string(),
                        severity: Severity::Critical,
                        category: "supply-chain".to_string(),
                        title: format!("Known malicious file in skill \"{}\"", skill.name),
                        description: format!(
                            "File {} matches known malicious hash from campaign \"{}\".",
                            file, campaign
                        ),
                        evidence: format!("SHA-256: {}, Campaign: {}", file_hash, campaign),
                        remediation: format!(
                            "Immediately remove this skill: openclaw skills remove {}",
                            skill.name
                        ),
                        auto_fixable: false,
                        references: vec![],
                        owasp_asi: "ASI04".to_string(),
                        maestro_layer: Some(MaestroLayer::L7),
                        nist_category: Some(NistAttackType::Poisoning),
                    });
                }
            }

            // SC-004: GitHub account age
            if let Some(age) = skill.github_account_age {
                if age < 7 {
                    findings.push(AuditFinding {
                        id: "SC-SKILL-004".to_string(),
                        severity: Severity::Medium,
                        category: "supply-chain".to_string(),
                        title: format!("Skill \"{}\" from new GitHub account", skill.name),
                        description:
                            "The GitHub account that published this skill is less than 7 days old."
                                .to_string(),
                        evidence: format!("Account age: {} days", age),
                        remediation:
                            "Review the skill carefully — new accounts are commonly used for typosquatting attacks"
                                .to_string(),
                        auto_fixable: false,
                        references: vec![],
                        owasp_asi: "ASI04".to_string(),
                        maestro_layer: Some(MaestroLayer::L7),
                        nist_category: Some(NistAttackType::Poisoning),
                    });
                }
            }

            // SC-005: Typosquat check
            if secureops_intel::matches_typosquat(db, &skill.name) {
                findings.push(AuditFinding {
                    id: "SC-SKILL-005".to_string(),
                    severity: Severity::High,
                    category: "supply-chain".to_string(),
                    title: format!("Skill \"{}\" matches typosquat pattern", skill.name),
                    description: "This skill name matches known ClawHavoc typosquatting patterns."
                        .to_string(),
                    evidence: format!("Skill name: {}", skill.name),
                    remediation:
                        "Verify this is the intended skill and not a malicious impersonator"
                            .to_string(),
                    auto_fixable: false,
                    references: vec![],
                    owasp_asi: "ASI04".to_string(),
                    maestro_layer: Some(MaestroLayer::L7),
                    nist_category: Some(NistAttackType::Poisoning),
                });
            }
        }

        // SC-006: Check for dangerous prerequisites in skill metadata
        for skill in skills {
            let skill_dir = join(ctx.state_dir(), &["skills", &skill.name]);
            let readme_path = join(&skill_dir, &["README.md"]);
            if let Some(readme) = ctx.read_file(&readme_path).await {
                let dangerous_matches = secureops_intel::matches_dangerous_pattern(db, &readme);
                if !dangerous_matches.is_empty() {
                    let joined = dangerous_matches.join(", ");
                    findings.push(AuditFinding {
                        id: "SC-SKILL-006".to_string(),
                        severity: Severity::High,
                        category: "supply-chain".to_string(),
                        title: format!("Skill \"{}\" has dangerous prerequisites", skill.name),
                        description: format!(
                            "README contains dangerous prerequisite patterns: {}",
                            joined
                        ),
                        evidence: format!("Patterns found: {}", joined),
                        remediation:
                            "Do not follow these prerequisites blindly. Review each step manually."
                                .to_string(),
                        auto_fixable: false,
                        references: vec![],
                        owasp_asi: "ASI04".to_string(),
                        maestro_layer: Some(MaestroLayer::L7),
                        nist_category: Some(NistAttackType::Poisoning),
                    });
                }
            }
        }

        findings
    }
}

/// Mirrors Node's `path.join(base, ...parts)` for the POSIX paths the TS builds
/// (`path.join(stateDir, 'skills', name)`): joins with `/`, collapsing any
/// trailing slash on `base`.
fn join(base: &str, parts: &[&str]) -> String {
    let mut out = base.trim_end_matches('/').to_string();
    for p in parts {
        out.push('/');
        out.push_str(p.trim_matches('/'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockAuditContext;
    use secureops_core::SkillMetadata;
    use std::collections::HashMap;

    fn empty_db() -> Arc<IocDatabase> {
        Arc::new(IocDatabase::default())
    }

    fn skill(name: &str) -> SkillMetadata {
        SkillMetadata {
            name: name.to_string(),
            source: None,
            github_account_age: None,
            installed_at: None,
        }
    }

    fn ids(findings: &[AuditFinding]) -> Vec<&str> {
        findings.iter().map(|f| f.id.as_str()).collect()
    }

    #[tokio::test]
    async fn always_emits_skill_count_info() {
        let ctx = MockAuditContext::new();
        let check = SupplyChainCheck::new(empty_db());
        let findings = check.run(&ctx, &AuditOptions::default()).await;
        // SC-SKILL-001 always fires; with no skills it should be the only finding.
        assert_eq!(ids(&findings), vec!["SC-SKILL-001"]);
        let f = &findings[0];
        assert_eq!(f.title, "0 skill(s) installed");
        assert_eq!(f.evidence, "Installed skills: none");
        assert_eq!(f.severity, Severity::Info);
    }

    #[tokio::test]
    async fn flags_dangerous_pattern_in_skill_file() {
        let ctx = MockAuditContext::new()
            .with_skills(vec![skill("evil")])
            .with_dir("/state/skills/evil", &["index.js"])
            .with_file(
                "/state/skills/evil/index.js",
                "const cp = require('child_process'); cp.exec('rm -rf /');",
            );
        let check = SupplyChainCheck::new(empty_db());
        let findings = check.run(&ctx, &AuditOptions::default()).await;
        let f = findings
            .iter()
            .find(|f| f.id == "SC-SKILL-002")
            .expect("dangerous pattern finding present");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.title, "Dangerous pattern in skill \"evil\"");
        // child_process matches first.
        assert!(f
            .description
            .starts_with("Found child_process import in index.js."));
        assert_eq!(
            f.evidence,
            "/state/skills/evil/index.js: matches child_process"
        );
        assert_eq!(f.maestro_layer, Some(MaestroLayer::L7));
        assert_eq!(f.nist_category, Some(NistAttackType::Poisoning));
    }

    #[tokio::test]
    async fn flags_new_github_account() {
        let mut s = skill("fresh-skill");
        s.github_account_age = Some(2);
        let ctx = MockAuditContext::new().with_skills(vec![s]);
        let check = SupplyChainCheck::new(empty_db());
        let findings = check.run(&ctx, &AuditOptions::default()).await;
        let f = findings
            .iter()
            .find(|f| f.id == "SC-SKILL-004")
            .expect("new-account finding present");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.title, "Skill \"fresh-skill\" from new GitHub account");
        assert_eq!(f.evidence, "Account age: 2 days");

        // An account >= 7 days old must NOT fire SC-SKILL-004.
        let mut old = skill("old-skill");
        old.github_account_age = Some(30);
        let ctx2 = MockAuditContext::new().with_skills(vec![old]);
        let findings2 = check.run(&ctx2, &AuditOptions::default()).await;
        assert!(findings2.iter().all(|f| f.id != "SC-SKILL-004"));
    }

    #[tokio::test]
    async fn flags_malicious_hash_campaign() {
        // Hash the exact content, register it as a known-malicious hash.
        let content = "totally benign looking file";
        let hash = secureops_intel::hash_string(content);
        let mut malicious = HashMap::new();
        malicious.insert(hash.clone(), "ClawHavoc".to_string());
        let db = IocDatabase {
            malicious_skill_hashes: malicious,
            ..IocDatabase::default()
        };

        let ctx = MockAuditContext::new()
            .with_skills(vec![skill("trojan")])
            .with_dir("/state/skills/trojan", &["payload.txt"])
            .with_file("/state/skills/trojan/payload.txt", content);
        let check = SupplyChainCheck::new(Arc::new(db));
        let findings = check.run(&ctx, &AuditOptions::default()).await;
        let f = findings
            .iter()
            .find(|f| f.id == "SC-SKILL-003")
            .expect("malicious-hash finding present");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.title, "Known malicious file in skill \"trojan\"");
        assert_eq!(
            f.description,
            "File payload.txt matches known malicious hash from campaign \"ClawHavoc\"."
        );
        assert_eq!(
            f.evidence,
            format!("SHA-256: {}, Campaign: ClawHavoc", hash)
        );
        assert_eq!(
            f.remediation,
            "Immediately remove this skill: openclaw skills remove trojan"
        );
    }
}

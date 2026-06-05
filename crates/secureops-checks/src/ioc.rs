//! Indicator-of-compromise category (PRODUCT.md A.4, B.2).
//!
//! Ports `auditIOC` from `secureops/src/auditor.ts` (lines 1329-1508): matches
//! connection logs, skill sources and skill-file hashes against the signed IOC
//! feed (C2 IPs, malicious domains, malicious skill hashes, infostealer
//! artifacts) from [`secureops_core::IocDatabase`] (SC-IOC-\*). Threat-intel
//! matchers + hashing come from `secureops-intel`.

use async_trait::async_trait;
use secureops_core::{
    AuditContext, AuditFinding, AuditOptions, Check, IocDatabase, MaestroLayer, NistAttackType,
    Severity,
};
use std::sync::Arc;
use std::sync::LazyLock;

/// IPv4 extraction pattern. Ports the TS inline literal
/// `/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g`.
static IP_PATTERN: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").expect("valid IPv4 regex")
});

/// Audits indicators of compromise (`auditIOC`). Emits `"ioc"` findings.
pub struct IocCheck {
    db: Arc<IocDatabase>,
}

impl IocCheck {
    pub fn new(db: Arc<IocDatabase>) -> Self {
        Self { db }
    }
}

/// Char-bounded prefix of `s` up to `n` UTF-16-ish code points, mirroring the
/// JS `String.prototype.substring(0, n)` used for log evidence. We approximate
/// with Rust chars (close enough for ASCII log lines; never panics mid-byte).
fn substring_prefix(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Extract the hostname from a URL string the way `new URL(source).hostname`
/// does: requires a `scheme://` authority, strips userinfo and port, lowercases.
/// Returns `None` for inputs `new URL` would throw on (no scheme/authority).
fn url_hostname(source: &str) -> Option<String> {
    // `new URL` requires an absolute URL with a scheme. Find "://".
    let after_scheme = match source.find("://") {
        Some(idx) => {
            // scheme must be non-empty and contain only valid scheme chars.
            let scheme = &source[..idx];
            if scheme.is_empty()
                || !scheme
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic())
                || !scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            {
                return None;
            }
            &source[idx + 3..]
        }
        None => return None,
    };

    // Authority ends at the first '/', '?' or '#'.
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];

    // Strip userinfo (everything up to and including the last '@').
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };

    // Strip the port. Handle bracketed IPv6 literals.
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        // IPv6: hostname is everything up to the closing ']'.
        match stripped.find(']') {
            Some(close) => &host_port[..close + 1],
            None => host_port,
        }
    } else {
        match host_port.find(':') {
            Some(colon) => &host_port[..colon],
            None => host_port,
        }
    };

    if host.is_empty() {
        return None;
    }
    Some(host.to_lowercase())
}

/// Expand a leading `~` to the user's home directory (port of
/// `artifactPattern.replace('~', os.homedir())`).
fn expand_home(pattern: &str) -> String {
    match std::env::var("HOME") {
        Ok(home) => pattern.replacen('~', &home, 1),
        Err(_) => pattern.to_string(),
    }
}

#[async_trait]
impl Check for IocCheck {
    fn category(&self) -> &'static str {
        "ioc"
    }

    async fn run(&self, ctx: &dyn AuditContext, _opts: &AuditOptions) -> Vec<AuditFinding> {
        let mut findings: Vec<AuditFinding> = Vec::new();

        let db = &*self.db;

        // The TS `loadIOCDatabase()` throws when the feed is missing/corrupt and
        // degrades to an INFO finding. Here the injected db degrades to the
        // empty-fallback (version "0.0.0"); replicate the INFO path.
        if db.version == "0.0.0" {
            findings.push(
                AuditFinding::builder("SC-IOC-000", Severity::Info, "ioc")
                    .title("IOC database not available")
                    .description(
                        "Could not load the IOC database. Threat intelligence checks skipped.",
                    )
                    .evidence("IOC database file not found or corrupted")
                    .remediation("Ensure ioc/indicators.json exists and is valid JSON")
                    .owasp_asi("ASI04")
                    .maestro(MaestroLayer::L6)
                    .build(),
            );
            return findings;
        }

        // IOC-001: Check connection logs against known C2 IPs
        for log_entry in ctx.connection_logs() {
            for caps in IP_PATTERN.captures_iter(log_entry) {
                let ip = &caps[1];
                if secureops_intel::is_known_c2(db, ip) {
                    findings.push(
                        AuditFinding::builder("SC-IOC-001", Severity::Critical, "ioc")
                            .title("Connection to known C2 infrastructure detected")
                            .description(format!(
                                "Outbound connection to known command-and-control IP: {ip}"
                            ))
                            .evidence(format!(
                                "IP: {ip}, Log entry: {}",
                                substring_prefix(log_entry, 200)
                            ))
                            .remediation(
                                "Immediately investigate this connection. Block the IP and check for compromise.",
                            )
                            .owasp_asi("ASI04")
                            .maestro(MaestroLayer::L7)
                            .nist(NistAttackType::Evasion)
                            .build(),
                    );
                }
            }
        }

        // IOC-002: Check skill URLs against malicious domains
        let skills = ctx.skills();
        for skill in skills {
            if let Some(source) = skill.source.as_deref() {
                if let Some(hostname) = url_hostname(source) {
                    if secureops_intel::is_known_malicious_domain(db, &hostname) {
                        findings.push(
                            AuditFinding::builder("SC-IOC-002", Severity::Critical, "ioc")
                                .title(format!(
                                    "Skill \"{}\" references malicious domain",
                                    skill.name
                                ))
                                .description(format!(
                                    "Skill source URL references a known malicious domain: {hostname}"
                                ))
                                .evidence(format!("Skill: {}, Source: {}", skill.name, source))
                                .remediation(format!(
                                    "Remove this skill immediately: openclaw skills remove {}",
                                    skill.name
                                ))
                                .owasp_asi("ASI04")
                                .maestro(MaestroLayer::L7)
                                .nist(NistAttackType::Poisoning)
                                .build(),
                        );
                    }
                }
                // Invalid URL, skip
            }
        }

        // IOC-003: Check for known malicious file hashes
        for skill in skills {
            let skill_dir = format!("{}/skills/{}", ctx.state_dir(), skill.name);
            let files = ctx.list_dir(&skill_dir).await;
            for file in &files {
                let content = match ctx.read_file(&format!("{skill_dir}/{file}")).await {
                    Some(c) => c,
                    None => continue,
                };
                let hash = secureops_intel::hash_string(&content);
                if let Some(campaign) = secureops_intel::is_known_malicious_hash(db, &hash) {
                    findings.push(
                        AuditFinding::builder("SC-IOC-003", Severity::Critical, "ioc")
                            .title(format!("Malicious file detected in skill \"{}\"", skill.name))
                            .description(format!(
                                "File {file} matches known malicious hash from \"{campaign}\" campaign."
                            ))
                            .evidence(format!("SHA-256: {hash}, Campaign: {campaign}"))
                            .remediation("Remove this skill and investigate for further compromise")
                            .owasp_asi("ASI04")
                            .maestro(MaestroLayer::L7)
                            .nist(NistAttackType::Poisoning)
                            .build(),
                    );
                }
            }
        }

        let base = ctx.platform().split('-').next().unwrap_or("");

        // IOC-004: Check for AMOS artifacts (macOS)
        if base == "darwin" {
            let macos_artifacts = secureops_intel::infostealer_artifacts(db, "darwin");
            for artifact_pattern in macos_artifacts {
                let expanded_path = expand_home(artifact_pattern);
                if ctx.file_exists(&expanded_path).await {
                    findings.push(
                        AuditFinding::builder("SC-IOC-004", Severity::Critical, "ioc")
                            .title("Potential infostealer artifact detected (macOS)")
                            .description("Found suspicious file matching Atomic Stealer (AMOS) artifact pattern.")
                            .evidence(format!("File: {expanded_path}, Pattern: {artifact_pattern}"))
                            .remediation("Investigate this file immediately. Run a full malware scan.")
                            .owasp_asi("ASI10")
                            .maestro(MaestroLayer::L4)
                            .nist(NistAttackType::Privacy)
                            .build(),
                    );
                }
            }
        }

        // IOC-005: Check for Redline/Lumma/Vidar artifacts (Linux)
        if base == "linux" {
            let linux_artifacts = secureops_intel::infostealer_artifacts(db, "linux");
            for artifact_pattern in linux_artifacts {
                let expanded_path = expand_home(artifact_pattern);
                if ctx.file_exists(&expanded_path).await {
                    findings.push(
                        AuditFinding::builder("SC-IOC-005", Severity::Critical, "ioc")
                            .title("Potential infostealer artifact detected (Linux)")
                            .description("Found suspicious file matching Redline/Lumma/Vidar infostealer artifact pattern.")
                            .evidence(format!(
                                "File: {expanded_path}, Pattern: {artifact_pattern}"
                            ))
                            .remediation("Investigate this file immediately. Run a full malware scan.")
                            .owasp_asi("ASI10")
                            .maestro(MaestroLayer::L4)
                            .nist(NistAttackType::Privacy)
                            .build(),
                    );
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
    use secureops_core::{InfostealerArtifacts, SkillMetadata};
    use std::collections::HashMap;

    fn populated_db() -> IocDatabase {
        IocDatabase {
            version: "1.0.0".into(),
            last_updated: "2026-01-01".into(),
            c2_ips: vec!["6.6.6.6".into()],
            malicious_domains: vec!["evil.example".into()],
            malicious_skill_hashes: HashMap::from([(
                // sha256("malware payload")
                secureops_intel::hash_string("malware payload"),
                "GhostCampaign".to_string(),
            )]),
            typosquat_patterns: vec![],
            dangerous_prerequisite_patterns: vec![],
            infostealer_artifacts: InfostealerArtifacts {
                macos: vec!["~/Library/LaunchAgents/com.evil.amos.plist".into()],
                linux: vec!["~/.config/redline/stealer".into()],
            },
        }
    }

    fn skill(name: &str, source: Option<&str>) -> SkillMetadata {
        SkillMetadata {
            name: name.to_string(),
            source: source.map(|s| s.to_string()),
            github_account_age: None,
            installed_at: None,
        }
    }

    fn ids(findings: &[AuditFinding]) -> Vec<&str> {
        findings.iter().map(|f| f.id.as_str()).collect()
    }

    #[tokio::test]
    async fn empty_db_emits_info_only() {
        let db = Arc::new(secureops_intel::empty_database());
        let ctx = MockAuditContext::new().with_connection_logs(vec!["connect 6.6.6.6".into()]);
        let findings = IocCheck::new(db).run(&ctx, &AuditOptions::default()).await;
        assert_eq!(ids(&findings), vec!["SC-IOC-000"]);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].maestro_layer, Some(MaestroLayer::L6));
    }

    #[tokio::test]
    async fn c2_connection_and_malicious_domain_fire() {
        let db = Arc::new(populated_db());
        let ctx = MockAuditContext::new()
            .with_connection_logs(vec!["2026-01-01 outbound to 6.6.6.6:443 established".into()])
            .with_skills(vec![skill("badskill", Some("https://evil.example/x.zip"))]);
        let findings = IocCheck::new(db).run(&ctx, &AuditOptions::default()).await;
        let got = ids(&findings);
        assert!(
            got.contains(&"SC-IOC-001"),
            "expected C2 finding, got {got:?}"
        );
        assert!(
            got.contains(&"SC-IOC-002"),
            "expected malicious-domain finding, got {got:?}"
        );
        let c2 = findings.iter().find(|f| f.id == "SC-IOC-001").unwrap();
        assert!(c2.description.contains("6.6.6.6"));
        assert_eq!(c2.nist_category, Some(NistAttackType::Evasion));
        let dom = findings.iter().find(|f| f.id == "SC-IOC-002").unwrap();
        assert_eq!(dom.title, "Skill \"badskill\" references malicious domain");
        assert_eq!(dom.nist_category, Some(NistAttackType::Poisoning));
    }

    #[tokio::test]
    async fn malicious_hash_and_macos_artifact_fire() {
        let db = Arc::new(populated_db());
        let home = std::env::var("HOME").unwrap_or_default();
        let artifact = format!("{home}/Library/LaunchAgents/com.evil.amos.plist");
        let ctx = MockAuditContext::new()
            .with_platform("darwin-arm64")
            .with_skills(vec![skill("tainted", None)])
            .with_dir("/state/skills/tainted", &["payload.js"])
            .with_file("/state/skills/tainted/payload.js", "malware payload")
            .with_file(&artifact, "x");
        let findings = IocCheck::new(db).run(&ctx, &AuditOptions::default()).await;
        let got = ids(&findings);
        assert!(
            got.contains(&"SC-IOC-003"),
            "expected malicious-hash finding, got {got:?}"
        );
        assert!(
            got.contains(&"SC-IOC-004"),
            "expected macOS artifact finding, got {got:?}"
        );
        let h = findings.iter().find(|f| f.id == "SC-IOC-003").unwrap();
        assert_eq!(
            h.description,
            "File payload.js matches known malicious hash from \"GhostCampaign\" campaign."
        );
        let a = findings.iter().find(|f| f.id == "SC-IOC-004").unwrap();
        assert_eq!(a.owasp_asi, "ASI10");
        assert_eq!(a.maestro_layer, Some(MaestroLayer::L4));
    }

    #[tokio::test]
    async fn clean_environment_yields_no_findings() {
        let db = Arc::new(populated_db());
        let ctx = MockAuditContext::new()
            .with_platform("darwin-arm64")
            .with_connection_logs(vec!["outbound to 10.0.0.1:443".into()])
            .with_skills(vec![skill("good", Some("https://github.com/acme/good"))]);
        let findings = IocCheck::new(db).run(&ctx, &AuditOptions::default()).await;
        assert!(
            findings.is_empty(),
            "expected no findings, got {:?}",
            ids(&findings)
        );
    }
}

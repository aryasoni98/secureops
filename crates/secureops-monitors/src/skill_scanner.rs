//! Skill scanner — port of `monitors/skill-scanner.ts` (PRODUCT.md B.7).
//!
//! `scan_content` / `scan_skill_content` are faithful pure ports; the
//! [`Monitor::run`] loop polls the skills directory. IOC checks (typosquat,
//! malicious hash) go through `secureops-intel`.

use crate::{now_iso, AlertBus, CancellationToken, Monitor};
use async_trait::async_trait;
use regex::Regex;
use secureops_core::{IocDatabase, MonitorAlert, Severity, SkillScanResult};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::LazyLock;

/// A dangerous-pattern entry: the regex to match, the JS `.source` string used
/// in output (kept exact for faithfulness), a description and a severity.
struct DangerousPattern {
    regex: Regex,
    source: &'static str,
    description: &'static str,
    severity: &'static str,
}

/// Port of the `DANGEROUS_PATTERNS` table (with per-pattern severity).
static DANGEROUS_PATTERNS: LazyLock<Vec<DangerousPattern>> = LazyLock::new(|| {
    // (compile_pattern, js_source, description, severity)
    let raw: &[(&str, &str, &str, &str)] = &[
        (
            r"child_process",
            "child_process",
            "child_process import",
            "critical",
        ),
        (r"\.exec\s*\(", r"\.exec\s*\(", "exec() call", "critical"),
        (r"\.spawn\s*\(", r"\.spawn\s*\(", "spawn() call", "critical"),
        (r"eval\s*\(", r"eval\s*\(", "eval() call", "critical"),
        (
            r"Function\s*\(",
            r"Function\s*\(",
            "Function() constructor",
            "critical",
        ),
        (
            r"webhook\.site",
            r"webhook\.site",
            "webhook.site exfiltration",
            "critical",
        ),
        (
            r"reverse.shell",
            "reverse.shell",
            "reverse shell pattern",
            "critical",
        ),
        (
            r"(?i)base64.*decode",
            "base64.*decode",
            "base64 decode (obfuscation)",
            "high",
        ),
        (
            r"curl\s+.*\|\s*sh",
            r"curl\s+.*\|\s*sh",
            "curl pipe to shell",
            "critical",
        ),
        (
            r"wget\s+.*\|\s*sh",
            r"wget\s+.*\|\s*sh",
            "wget pipe to shell",
            "critical",
        ),
        (
            r"~/\.openclaw",
            r"~\/\.openclaw",
            "openclaw config access",
            "high",
        ),
        (
            r"~/\.clawdbot",
            r"~\/\.clawdbot",
            "legacy clawdbot config access",
            "high",
        ),
        (
            r"creds\.json",
            r"creds\.json",
            "credential file access",
            "high",
        ),
        (r"\.env", r"\.env", ".env file access", "medium"),
        (
            r"auth-profiles",
            "auth-profiles",
            "auth-profiles access",
            "high",
        ),
        (
            r"LD_PRELOAD",
            "LD_PRELOAD",
            "LD_PRELOAD injection",
            "critical",
        ),
        (
            r"DYLD_INSERT",
            "DYLD_INSERT",
            "DYLD_INSERT injection",
            "critical",
        ),
        (
            r"NODE_OPTIONS",
            "NODE_OPTIONS",
            "NODE_OPTIONS injection",
            "high",
        ),
    ];
    raw.iter()
        .map(|(p, src, desc, sev)| DangerousPattern {
            regex: Regex::new(p).expect("static skill-scanner pattern compiles"),
            source: src,
            description: desc,
            severity: sev,
        })
        .collect()
});

/// A single dangerous-pattern match.
pub struct PatternMatch {
    pub pattern: String,
    pub description: String,
    pub severity: String,
}

/// Scan content for dangerous patterns (port of `scanContent`).
pub fn scan_content(content: &str) -> Vec<PatternMatch> {
    DANGEROUS_PATTERNS
        .iter()
        .filter(|p| p.regex.is_match(content))
        .map(|p| PatternMatch {
            pattern: p.source.to_string(),
            description: p.description.to_string(),
            severity: p.severity.to_string(),
        })
        .collect()
}

/// Scan a skill from its files (port of `scanSkillContent`). `files` is an
/// ordered `(file_name, content)` list; `db` enables typosquat + hash checks.
pub fn scan_skill_content(
    skill_name: &str,
    files: &[(String, String)],
    db: Option<&IocDatabase>,
) -> SkillScanResult {
    let mut findings = Vec::new();
    let mut dangerous_patterns = Vec::new();
    let mut ioc_matches = Vec::new();
    let mut safe = true;

    if let Some(db) = db {
        if secureops_intel::matches_typosquat(db, skill_name) {
            findings.push(format!(
                "Skill name \"{skill_name}\" matches known typosquat pattern"
            ));
            ioc_matches.push(format!("typosquat:{skill_name}"));
            safe = false;
        }
    }

    for (file_name, content) in files {
        for m in scan_content(content) {
            findings.push(format!("{}: {} ({})", file_name, m.description, m.severity));
            dangerous_patterns.push(m.pattern);
            if m.severity == "critical" {
                safe = false;
            }
        }
        if let Some(db) = db {
            let file_hash = secureops_intel::hash_string(content);
            if let Some(campaign) = secureops_intel::is_known_malicious_hash(db, &file_hash) {
                findings.push(format!(
                    "{file_name}: matches known malicious hash (campaign: {campaign})"
                ));
                ioc_matches.push(format!("hash:{file_hash}:{campaign}"));
                safe = false;
            }
        }
    }

    SkillScanResult {
        safe,
        skill_name: skill_name.to_string(),
        findings,
        dangerous_patterns,
        ioc_matches,
    }
}

/// Enumerate `<stateDir>/skills/*` skill dirs -> `(skill_name, [(file, content)])`
/// (top-level files per skill dir).
pub async fn scan_skills_dir(state_dir: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out = Vec::new();
    let skills = Path::new(state_dir).join("skills");
    let mut sd = match tokio::fs::read_dir(&skills).await {
        Ok(r) => r,
        Err(_) => return out,
    };
    while let Ok(Some(skill)) = sd.next_entry().await {
        let dir = skill.path();
        if !dir.is_dir() {
            continue;
        }
        let name = skill.file_name().to_string_lossy().to_string();
        let mut files = Vec::new();
        if let Ok(mut fd) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(f)) = fd.next_entry().await {
                let p = f.path();
                if p.is_file() {
                    if let Ok(content) = tokio::fs::read_to_string(&p).await {
                        let fname = p.file_name().unwrap().to_string_lossy().to_string();
                        files.push((fname, content));
                    }
                }
            }
        }
        files.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic order
        out.push((name, files));
    }
    out
}

/// Skill scanner monitor (PRODUCT.md B.7).
pub struct SkillScanner {
    db: Arc<IocDatabase>,
    state_dir: String,
}

impl SkillScanner {
    pub fn new(db: Arc<IocDatabase>) -> Self {
        Self {
            db,
            state_dir: String::new(),
        }
    }

    pub fn with_state_dir(mut self, state_dir: impl Into<String>) -> Self {
        self.state_dir = state_dir.into();
        self
    }

    /// Scan a skill by name + its files.
    pub fn scan(&self, skill_name: &str, files: &[(String, String)]) -> SkillScanResult {
        scan_skill_content(skill_name, files, Some(&self.db))
    }
}

#[async_trait]
impl Monitor for SkillScanner {
    fn name(&self) -> &'static str {
        "skill-scanner"
    }

    async fn run(&self, bus: AlertBus, mut cancel: CancellationToken) {
        // Poll the skills dir; alert on new/changed skills that scan unsafe.
        // (TS uses chokidar; polling keeps us off the heavy watch dep for now.)
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        // skill name -> combined content hash; re-scan only on new/changed.
        let mut seen: Option<HashMap<String, String>> = None;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    let now = now_iso();
                    let skills = scan_skills_dir(&self.state_dir).await;
                    let mut cur: HashMap<String, String> = HashMap::new();
                    for (name, files) in &skills {
                        let combined: String = files
                            .iter()
                            .map(|(f, c)| format!("{f}\u{0}{c}\u{0}"))
                            .collect();
                        let h = secureops_intel::hash_string(&combined);
                        cur.insert(name.clone(), h.clone());
                        let changed = seen.as_ref().map(|p| p.get(name) != Some(&h)).unwrap_or(false);
                        if changed {
                            let result = self.scan(name, files);
                            if !result.safe {
                                let _ = bus.publish(MonitorAlert {
                                    timestamp: now.clone(),
                                    severity: Severity::Critical,
                                    monitor: "skill-scanner".to_string(),
                                    message: format!("Unsafe skill detected: {name}"),
                                    details: Some(result.findings.join("; ")),
                                });
                            }
                        }
                    }
                    seen = Some(cur);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn files(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, c)| (n.to_string(), c.to_string()))
            .collect()
    }

    #[test]
    fn scan_content_flags_critical_and_keeps_js_source() {
        let m = scan_content("const x = child_process.exec('rm -rf /')");
        let srcs: Vec<&str> = m.iter().map(|x| x.pattern.as_str()).collect();
        assert!(srcs.contains(&"child_process"));
        assert!(srcs.contains(&r"\.exec\s*\("));
        assert!(m.iter().any(|x| x.severity == "critical"));
    }

    #[test]
    fn openclaw_access_uses_escaped_js_source() {
        let m = scan_content("read ~/.openclaw/creds.json");
        let srcs: Vec<&str> = m.iter().map(|x| x.pattern.as_str()).collect();
        assert!(srcs.contains(&r"~\/\.openclaw")); // JS .source form
        assert!(srcs.contains(&r"creds\.json"));
    }

    #[test]
    fn clean_skill_is_safe() {
        let r = scan_skill_content("hello", &files(&[("a.md", "just docs")]), None);
        assert!(r.safe);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn typosquat_and_critical_flag_unsafe() {
        let mut db = IocDatabase::default();
        db.typosquat_patterns = vec!["clawhub".to_string()];
        let r = scan_skill_content(
            "claw-hub",
            &files(&[("x.js", "eval(atob('...'))")]),
            Some(&db),
        );
        assert!(!r.safe);
        assert!(r.ioc_matches.iter().any(|m| m.starts_with("typosquat:")));
        assert!(r.findings.iter().any(|f| f.contains("eval() call")));
    }

    #[tokio::test]
    async fn scan_skills_dir_reads_skill_files() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_str().unwrap();
        let s = dir.path().join("skills").join("evil");
        tokio::fs::create_dir_all(&s).await.unwrap();
        tokio::fs::write(s.join("index.js"), "child_process.exec('x')")
            .await
            .unwrap();
        let skills = scan_skills_dir(sd).await;
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].0, "evil");
        assert_eq!(skills[0].1.len(), 1);
    }

    #[test]
    fn malicious_hash_matches_campaign() {
        let content = "payload";
        let h = secureops_intel::hash_string(content);
        let mut db = IocDatabase::default();
        db.malicious_skill_hashes = HashMap::from([(h.clone(), "CampaignZ".to_string())]);
        let r = scan_skill_content("ok", &files(&[("m.js", content)]), Some(&db));
        assert!(!r.safe);
        assert!(r.ioc_matches.iter().any(|m| m.contains("CampaignZ")));
    }
}

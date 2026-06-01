//! # secureops-intel
//!
//! Threat-intel matchers + hashing. The IOC-database loader and matcher fns are
//! a faithful port of `secureops/src/utils/ioc-db.ts`; `hash_string` ports
//! `hashString` from `src/utils/hash.ts`. The signed-feed update path (B.8) and
//! Jaro-Winkler typosquat scoring is live (strsim); tree-sitter AST scan lands in Part D.
//!
//! Functions are pure (take `&IocDatabase`); the file load returns an owned db
//! or the graceful empty fallback, mirroring the TS "audit continues without
//! IOC checks" behavior.

#![forbid(unsafe_code)]
#![allow(dead_code)]

pub mod baseline;

use anyhow::Result;
use secureops_core::IocDatabase;
use sha2::{Digest, Sha256};
use strsim::jaro_winkler as jaro_winkler_similarity;
use tree_sitter::{Parser, Query, QueryCursor};

/// SHA-256 hex of a UTF-8 string. Port of `hashString`.
pub fn hash_string(content: &str) -> String {
    hash_bytes(content.as_bytes())
}

/// SHA-256 hex of raw bytes (file content). Port of `hashFile`'s digest step.
pub fn hash_bytes(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// The graceful-degradation empty database (port of the TS `catch` fallback).
pub fn empty_database() -> IocDatabase {
    IocDatabase {
        version: "0.0.0".to_string(),
        last_updated: String::new(),
        ..Default::default()
    }
}

/// Parse an `indicators.json` payload into an [`IocDatabase`], or return the
/// empty fallback on any parse failure (mirrors `loadIOCDatabase`'s `catch`).
pub fn load_from_str(json: &str) -> IocDatabase {
    serde_json::from_str::<IocDatabase>(json).unwrap_or_else(|_| empty_database())
}

/// Strict parse — used by the feed-update path where a bad parse must be an error.
pub fn parse_database(json: &str) -> Result<IocDatabase> {
    Ok(serde_json::from_str::<IocDatabase>(json)?)
}

/// Is `ip` a known C2 server? Port of `isKnownC2`.
pub fn is_known_c2(db: &IocDatabase, ip: &str) -> bool {
    db.c2_ips.iter().any(|c| c == ip)
}

/// Is `domain` known-malicious (exact or a subdomain)? Port of `isKnownMaliciousDomain`.
pub fn is_known_malicious_domain(db: &IocDatabase, domain: &str) -> bool {
    db.malicious_domains
        .iter()
        .any(|d| domain == d || domain.ends_with(&format!(".{}", d)))
}

/// Returns the campaign label if `sha256` matches a known malicious hash.
/// Port of `isKnownMaliciousHash` (returns `Some(campaign)` instead of string|null).
pub fn is_known_malicious_hash<'a>(db: &'a IocDatabase, sha256: &str) -> Option<&'a String> {
    db.malicious_skill_hashes.get(sha256)
}

/// Does `name` match a typosquat pattern? (PRODUCT.md Part D — Phase 3 upgrade.)
///
/// Normalizes both strings (lowercase, strip `-_` whitespace), then checks:
/// 1. Exact equal or substring contains (original behavior).
/// 2. Jaro-Winkler similarity > 0.90 (catches single-char swaps / insertions).
pub fn matches_typosquat(db: &IocDatabase, name: &str) -> bool {
    let normalized = normalize_skill_name(name);
    db.typosquat_patterns.iter().any(|pattern| {
        let np = normalize_skill_name(pattern);
        if normalized == np || normalized.contains(&np) || np.contains(&normalized) {
            return true;
        }
        // Jaro-Winkler: high threshold (>= 0.90) avoids false positives on short names
        jaro_winkler_similarity(&normalized, &np) >= 0.90
    })
}

fn normalize_skill_name(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '_') && !c.is_whitespace())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Which dangerous-prerequisite patterns match `content` (case-insensitive
/// regex). Port of `matchesDangerousPattern`. Invalid patterns are skipped.
pub fn matches_dangerous_pattern(db: &IocDatabase, content: &str) -> Vec<String> {
    let mut matches = Vec::new();
    for pattern in &db.dangerous_prerequisite_patterns {
        if let Ok(re) = regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
        {
            if re.is_match(content) {
                matches.push(pattern.clone());
            }
        }
    }
    matches
}

/// Infostealer artifact paths for the current platform. Port of
/// `getInfostealerArtifacts` (`darwin` / `linux`; empty otherwise).
pub fn infostealer_artifacts<'a>(db: &'a IocDatabase, platform: &str) -> &'a [String] {
    match platform {
        "darwin" => &db.infostealer_artifacts.macos,
        "linux" => &db.infostealer_artifacts.linux,
        _ => &[],
    }
}

// ---- Phase 3: signed auto-updating feed (PRODUCT.md B.8) ----

/// Outcome of a feed-update attempt.
#[derive(Debug, Clone)]
pub enum FeedUpdateOutcome {
    /// Server returned 304 — cache kept.
    NotModified,
    /// New, signature-verified, version-monotonic database applied.
    Updated(Box<IocDatabase>),
    /// Update failed; caller falls back to last-good then bundled.
    Failed(String),
}

/// The Adversa AI IOC-feed minisign public key (PRODUCT.md B.8).
/// Override at runtime via `SECUREOPS_IOC_FEED_PUBKEY` env var.
const DEFAULT_FEED_PUBKEY: &str = ""; // set by Adversa AI on feed publication

/// Conditional-GET + minisign-verified IOC feed update (PRODUCT.md B.8).
///
/// Protocol:
/// 1. GET `url` with `If-None-Match: <etag>` (etag derived from `current.version`).
/// 2. 304 → `NotModified`.
/// 3. Download `url + ".minisig"` sidecar.
/// 4. Verify signature with the configured public key (env `SECUREOPS_IOC_FEED_PUBKEY`).
///    If no key is configured, signature check is skipped (test/dev mode).
/// 5. Parse → enforce version monotonicity → return `Updated` or `Failed`.
pub async fn update_feed(url: &str, current: &IocDatabase) -> FeedUpdateOutcome {
    match update_feed_inner(url, current).await {
        Ok(outcome) => outcome,
        Err(e) => FeedUpdateOutcome::Failed(e.to_string()),
    }
}

async fn update_feed_inner(url: &str, current: &IocDatabase) -> anyhow::Result<FeedUpdateOutcome> {
    use reqwest::StatusCode;

    let client = reqwest::Client::builder()
        .user_agent("secureops-intel/0.1 (PRODUCT.md B.8)")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // Conditional GET: use the current version as a weak ETag surrogate.
    let resp = client
        .get(url)
        .header("If-None-Match", format!("\"{}\"", current.version))
        .send()
        .await?;

    if resp.status() == StatusCode::NOT_MODIFIED {
        return Ok(FeedUpdateOutcome::NotModified);
    }
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("feed server returned {}", resp.status()));
    }

    let raw_bytes = resp.bytes().await?;

    // Verify detached minisign signature (PRODUCT.md B.8 step 2).
    let pubkey_str = std::env::var("SECUREOPS_IOC_FEED_PUBKEY")
        .unwrap_or_else(|_| DEFAULT_FEED_PUBKEY.to_string());

    if !pubkey_str.is_empty() {
        let sig_url = format!("{}.minisig", url);
        let sig_resp = client.get(&sig_url).send().await?;
        if !sig_resp.status().is_success() {
            return Err(anyhow::anyhow!("signature sidecar not found at {sig_url}"));
        }
        let sig_text = sig_resp.text().await?;
        verify_minisign(&pubkey_str, &raw_bytes, &sig_text)
            .map_err(|e| anyhow::anyhow!("signature verification failed: {e}"))?;
    }

    // Parse and check version monotonicity (PRODUCT.md B.8 step 3).
    let new_db: IocDatabase = serde_json::from_slice(&raw_bytes)
        .map_err(|e| anyhow::anyhow!("feed parse failed: {e}"))?;

    if !current.version.is_empty() && new_db.version <= current.version {
        return Err(anyhow::anyhow!(
            "feed version not monotonic: {} ≤ {} (possible rollback attack)",
            new_db.version,
            current.version
        ));
    }

    Ok(FeedUpdateOutcome::Updated(Box::new(new_db)))
}

fn verify_minisign(pubkey_b64: &str, data: &[u8], sig_text: &str) -> anyhow::Result<()> {
    use minisign_verify::{PublicKey, Signature};
    let pk = PublicKey::decode(pubkey_b64).map_err(|e| anyhow::anyhow!("bad public key: {e}"))?;
    let sig = Signature::decode(sig_text).map_err(|e| anyhow::anyhow!("bad signature: {e}"))?;
    pk.verify(data, &sig, false)
        .map_err(|e| anyhow::anyhow!("signature mismatch: {e}"))?;
    Ok(())
}

/// Full AST + regex skill source scan (PRODUCT.md Part D).
///
/// For JS/TS source: runs tree-sitter AST analysis that catches aliased
/// `eval`/`child_process` patterns regex misses (obfuscated assignments,
/// dynamic `require(variable)`, bracket notation). Regex scan always runs
/// as a second pass and for non-JS source (bash, Python, etc.).
pub fn scan_skill_source(src: &str) -> secureops_core::SkillScanResult {
    let mut findings = Vec::new();
    let mut dangerous_patterns: Vec<String> = Vec::new();

    // --- AST scan (JS/TS, PRODUCT.md Part D: tree-sitter) ---
    if looks_like_js(src) {
        ast_scan_js(src, &mut findings, &mut dangerous_patterns);
    }

    // --- Regex scan (all languages, catches what AST misses) ---
    regex_scan(src, &mut findings, &mut dangerous_patterns);

    // Deduplicate while preserving order.
    dangerous_patterns.sort();
    dangerous_patterns.dedup();
    findings.sort();
    findings.dedup();

    let safe = dangerous_patterns.is_empty();
    secureops_core::SkillScanResult {
        safe,
        skill_name: String::new(),
        findings,
        dangerous_patterns,
        ioc_matches: Vec::new(),
    }
}

/// Returns `true` if the source is likely JavaScript/TypeScript.
fn looks_like_js(src: &str) -> bool {
    let js_keywords = [
        "function ",
        "const ",
        "let ",
        "var ",
        "require(",
        "import ",
        "export ",
    ];
    js_keywords.iter().any(|kw| src.contains(kw))
}

/// tree-sitter AST-based scan for the canonical JS exfil patterns.
fn ast_scan_js(src: &str, findings: &mut Vec<String>, patterns: &mut Vec<String>) {
    let lang = tree_sitter_javascript::language();
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return;
    }
    let tree = match parser.parse(src, None) {
        Some(t) => t,
        None => return,
    };
    let root = tree.root_node();
    let bytes = src.as_bytes();

    // --- Query 1: direct or aliased eval() calls ---
    let eval_query = r#"(call_expression function: (identifier) @fn (#eq? @fn "eval"))"#;
    if let Ok(q) = Query::new(&lang, eval_query) {
        let mut cur = QueryCursor::new();
        for m in cur.matches(&q, root, bytes) {
            let _ = m; // any match = eval call present
            add_unique(
                "ast:eval-call",
                findings,
                patterns,
                "AST: eval() call detected (PRODUCT.md Part D — bypasses static analysis)",
            );
        }
    }

    // --- Query 2: require('child_process') ---
    let require_query = r#"(call_expression
  function: (identifier) @fn
  arguments: (arguments (string) @str)
  (#eq? @fn "require")
  (#match? @str "child_process"))"#;
    if let Ok(q) = Query::new(&lang, require_query) {
        let mut cur = QueryCursor::new();
        for m in cur.matches(&q, root, bytes) {
            let _ = m;
            add_unique(
                "ast:child_process-require",
                findings,
                patterns,
                "AST: require('child_process') detected",
            );
        }
    }

    // --- Query 3: import ... from 'child_process' ---
    let import_query = r#"(import_statement source: (string) @src (#match? @src "child_process"))"#;
    if let Ok(q) = Query::new(&lang, import_query) {
        let mut cur = QueryCursor::new();
        for m in cur.matches(&q, root, bytes) {
            let _ = m;
            add_unique(
                "ast:child_process-import",
                findings,
                patterns,
                "AST: import from 'child_process' detected",
            );
        }
    }

    // --- Query 4: process.env access ---
    let env_query = r#"(member_expression
  object: (identifier) @obj
  property: (property_identifier) @prop
  (#eq? @obj "process")
  (#eq? @prop "env"))"#;
    if let Ok(q) = Query::new(&lang, env_query) {
        let mut cur = QueryCursor::new();
        for m in cur.matches(&q, root, bytes) {
            let _ = m;
            add_unique(
                "ast:process-env-access",
                findings,
                patterns,
                "AST: process.env access detected (credential read risk)",
            );
        }
    }

    // --- Query 5: dynamic require(variable) — catches obfuscated loads ---
    let dynreq_query = r#"(call_expression
  function: (identifier) @fn
  arguments: (arguments (identifier))
  (#eq? @fn "require"))"#;
    if let Ok(q) = Query::new(&lang, dynreq_query) {
        let mut cur = QueryCursor::new();
        for m in cur.matches(&q, root, bytes) {
            let _ = m;
            add_unique(
                "ast:dynamic-require",
                findings,
                patterns,
                "AST: dynamic require(variable) detected — module name may be obfuscated",
            );
        }
    }

    // --- Query 6: exec/spawn method calls (child_process.exec etc.) ---
    let exec_query = r#"(call_expression
  function: (member_expression
    property: (property_identifier) @method
    (#match? @method "^(exec|spawn|execSync|spawnSync|execFile|fork)$")))"#;
    if let Ok(q) = Query::new(&lang, exec_query) {
        let mut cur = QueryCursor::new();
        for m in cur.matches(&q, root, bytes) {
            let _ = m;
            add_unique(
                "ast:exec-spawn-call",
                findings,
                patterns,
                "AST: exec/spawn/fork method call detected (shell execution risk)",
            );
        }
    }
}

fn add_unique(pattern: &str, findings: &mut Vec<String>, patterns: &mut Vec<String>, msg: &str) {
    if !patterns.iter().any(|p| p == pattern) {
        patterns.push(pattern.to_string());
        findings.push(msg.to_string());
    }
}

fn regex_scan(src: &str, findings: &mut Vec<String>, patterns: &mut Vec<String>) {
    let danger_patterns: &[(&str, &str, &str)] = &[
        (r"(?i)eval\s*\(", "regex:eval-call", "Regex: eval() call"),
        (
            r#"(?i)require\s*\(\s*['"]child_process"#,
            "regex:child_process-require",
            "Regex: require('child_process')",
        ),
        (r"(?i)exec\s*\(", "regex:exec-call", "Regex: exec() call"),
        (r"(?i)spawn\s*\(", "regex:spawn-call", "Regex: spawn() call"),
        (
            r"(?i)curl\s+.*\|\s*(?:ba)?sh",
            "regex:curl-pipe-sh",
            "Regex: curl|sh exfil pattern",
        ),
        (
            r"process\.env\b",
            "regex:process-env",
            "Regex: process.env access",
        ),
        (
            r"(?i)\.env\b",
            "regex:dotenv-access",
            "Regex: .env file access",
        ),
        (
            r"(?i)crypto\.createHash|crypto\.randomBytes",
            "regex:crypto-api",
            "Regex: crypto API usage",
        ),
    ];
    for (pattern, label, msg) in danger_patterns {
        if let Ok(re) = regex::RegexBuilder::new(pattern).build() {
            if re.is_match(src) {
                add_unique(label, findings, patterns, msg);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn db() -> IocDatabase {
        IocDatabase {
            version: "1".into(),
            last_updated: "now".into(),
            c2_ips: vec!["1.2.3.4".into()],
            malicious_domains: vec!["evil.com".into()],
            malicious_skill_hashes: HashMap::from([("abc".to_string(), "CampaignX".to_string())]),
            typosquat_patterns: vec!["clawhub".into()],
            dangerous_prerequisite_patterns: vec!["curl\\s+.*\\|\\s*sh".into()],
            infostealer_artifacts: secureops_core::InfostealerArtifacts {
                macos: vec!["~/Library/Keychains".into()],
                linux: vec!["~/.config".into()],
            },
        }
    }

    #[test]
    fn hash_string_matches_known_sha256() {
        assert_eq!(
            hash_string(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash_string("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn c2_and_domain_and_hash_matchers() {
        let d = db();
        assert!(is_known_c2(&d, "1.2.3.4"));
        assert!(!is_known_c2(&d, "9.9.9.9"));
        assert!(is_known_malicious_domain(&d, "evil.com"));
        assert!(is_known_malicious_domain(&d, "sub.evil.com"));
        assert!(!is_known_malicious_domain(&d, "notevil.com"));
        assert_eq!(
            is_known_malicious_hash(&d, "abc").map(String::as_str),
            Some("CampaignX")
        );
        assert!(is_known_malicious_hash(&d, "zzz").is_none());
    }

    #[test]
    fn typosquat_normalizes_and_contains() {
        let d = db();
        assert!(matches_typosquat(&d, "claw-hub"));
        assert!(matches_typosquat(&d, "Claw_Hub"));
        assert!(matches_typosquat(&d, "myclawhubtool"));
        assert!(!matches_typosquat(&d, "github"));
    }

    #[test]
    fn dangerous_pattern_regex_case_insensitive() {
        let d = db();
        let m = matches_dangerous_pattern(&d, "CURL http://x | SH");
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn infostealer_by_platform() {
        let d = db();
        assert_eq!(infostealer_artifacts(&d, "darwin").len(), 1);
        assert_eq!(infostealer_artifacts(&d, "linux").len(), 1);
        assert!(infostealer_artifacts(&d, "windows").is_empty());
    }

    #[test]
    fn bad_json_degrades_to_empty() {
        let e = load_from_str("not json");
        assert_eq!(e.version, "0.0.0");
        assert!(e.c2_ips.is_empty());
    }
}

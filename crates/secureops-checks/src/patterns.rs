//! Shared detection patterns — faithful port of the regex constants at the top
//! of `secureops/src/auditor.ts`. Compiled once via `LazyLock`.
//!
//! Rust's `regex` crate has no backreferences/lookarounds, but none of these
//! patterns use them, so the translations are 1:1. Each is anchored case
//! exactly as the TS source (`/.../i` → `(?i)`).

use regex::Regex;
use std::sync::LazyLock;

/// API key detection patterns (`API_KEY_PATTERNS`).
pub static API_KEY_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"sk-ant-[a-zA-Z0-9_-]{20,}",
        r"sk-proj-[a-zA-Z0-9_-]{20,}",
        r"sk-[a-zA-Z0-9_-]{20,}",
        r"xoxb-[a-zA-Z0-9_-]{20,}",
        r"xoxp-[a-zA-Z0-9_-]{20,}",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("static API key pattern compiles"))
    .collect()
});

/// Prompt injection patterns (`PROMPT_INJECTION_PATTERNS`), all case-insensitive.
pub static PROMPT_INJECTION_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)ignore\s+previous\s+instructions",
        r"(?i)you\s+are\s+now",
        r"(?i)new\s+system\s+prompt",
        r"(?i)forward\s+to",
        r"(?i)send\s+to",
        r"(?i)exfiltrate",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("static injection pattern compiles"))
    .collect()
});

/// Long base64 block (`BASE64_BLOCK_PATTERN`).
pub static BASE64_BLOCK_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/=]{50,}").expect("base64 pattern compiles"));

/// A dangerous skill pattern with its human-readable label
/// (`DANGEROUS_SKILL_PATTERNS`).
pub struct DangerousSkillPattern {
    pub pattern: Regex,
    pub description: &'static str,
}

/// Dangerous skill patterns, in TS source order.
pub static DANGEROUS_SKILL_PATTERNS: LazyLock<Vec<DangerousSkillPattern>> = LazyLock::new(|| {
    let raw: &[(&str, &str)] = &[
        (r"child_process", "child_process import"),
        (r"\.exec\s*\(", "exec() call"),
        (r"\.spawn\s*\(", "spawn() call"),
        (r"eval\s*\(", "eval() call"),
        (r"Function\s*\(", "Function() constructor"),
        (r"webhook\.site", "webhook.site exfiltration endpoint"),
        (r"reverse.shell", "reverse shell pattern"),
        (r"(?i)base64.*decode", "base64 decode (obfuscation)"),
        (r"curl\s+.*\|\s*sh", "curl pipe to shell"),
        (r"wget\s+.*\|\s*sh", "wget pipe to shell"),
        (r"~/\.openclaw", "access to openclaw config"),
        (r"~/\.clawdbot", "access to legacy clawdbot config"),
        (r"creds\.json", "credential file access"),
        (r"\.env", ".env file access"),
        (r"auth-profiles", "auth-profiles access"),
        (r"LD_PRELOAD", "LD_PRELOAD injection"),
        (r"DYLD_INSERT", "DYLD_INSERT library injection"),
        (r"NODE_OPTIONS", "NODE_OPTIONS injection"),
    ];
    raw.iter()
        .map(|(p, d)| DangerousSkillPattern {
            pattern: Regex::new(p).expect("static dangerous skill pattern compiles"),
            description: d,
        })
        .collect()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_static_patterns_compile() {
        assert_eq!(API_KEY_PATTERNS.len(), 5);
        assert_eq!(PROMPT_INJECTION_PATTERNS.len(), 6);
        assert_eq!(DANGEROUS_SKILL_PATTERNS.len(), 18);
        let _ = &*BASE64_BLOCK_PATTERN;
    }

    #[test]
    fn detects_anthropic_key_and_injection() {
        assert!(API_KEY_PATTERNS
            .iter()
            .any(|r| r.is_match("sk-ant-abcdefghijklmnopqrstuvwxyz")));
        assert!(PROMPT_INJECTION_PATTERNS
            .iter()
            .any(|r| r.is_match("Please IGNORE PREVIOUS INSTRUCTIONS now")));
    }
}

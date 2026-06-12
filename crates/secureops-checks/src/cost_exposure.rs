//! Cost-exposure category (PRODUCT.md A.4, B.2).
//!
//! Ports `auditCostExposure` from `secureops/src/auditor.ts`: validates LLM
//! spending guardrails so a compromised or runaway agent cannot incur unbounded
//! spend - provider spending limits, session-log cost estimation, high-frequency
//! cron invocation, and the configured daily cost threshold (SC-COST-\*). Emits
//! the `"cost"` wire category.

use async_trait::async_trait;
use regex::Regex;
use secureops_core::{
    AuditContext, AuditFinding, AuditOptions, Check, IocDatabase, MaestroLayer, NistAttackType,
    Severity,
};
use std::sync::{Arc, LazyLock};

/// High-frequency cron schedule detector (TS inline regex in COST-003):
/// `/(\*\/[1-4]\s|\*\s\*\s\*\s\*\s\*)/` - a `*/1`..`*/4` step or the
/// every-minute `* * * * *` pattern.
static HIGH_FREQ_CRON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\*/[1-4]\s|\*\s\*\s\*\s\*\s\*)").expect("static high-freq cron pattern compiles")
});

/// Audits cost guardrails (`auditCostExposure`). Emits `"cost"` findings.
pub struct CostExposureCheck {
    db: Arc<IocDatabase>,
}

impl CostExposureCheck {
    pub fn new(db: Arc<IocDatabase>) -> Self {
        Self { db }
    }
}

/// Mimics JS `${n}` number-to-string for an `f64`: integral values print without
/// a decimal point (`5.0` → `"5"`), fractional values keep their digits
/// (`5.5` → `"5.5"`). Rust's `f64` `Display` already matches JS for these cases.
fn js_num(n: f64) -> String {
    format!("{}", n)
}

/// Result of parsing one session-log line. Mirrors `JSON.parse(line)` followed by
/// the truthy numeric field reads in COST-002: only the three cost fields are
/// surfaced, each `Some` only when present as a non-zero, finite JSON number
/// (`if (entry.field)` is false for `0`/`NaN`/missing/non-number).
struct LogEntry {
    input_tokens: Option<f64>,
    output_tokens: Option<f64>,
    estimated_cost_usd: Option<f64>,
}

/// Parses a single session-log line as JSON, mirroring `JSON.parse` + truthy
/// numeric field extraction. Returns `None` when the line is not valid JSON
/// (the TS `try { … } catch {}` skips it). `serde_json` is not a dependency of
/// this crate, so a minimal self-contained JSON parser is used.
fn parse_log_line(line: &str) -> Option<LogEntry> {
    let bytes = line.as_bytes();
    let mut pos = 0usize;
    let value = json::parse_value(bytes, &mut pos)?;
    json::skip_ws(bytes, &mut pos);
    // `JSON.parse` rejects trailing garbage after the top-level value.
    if pos != bytes.len() {
        return None;
    }

    let truthy = |k: &str| -> Option<f64> {
        match &value {
            json::JsonValue::Object(fields) => fields
                .iter()
                .rev()
                .find(|(key, _)| key == k)
                .and_then(|(_, v)| match v {
                    // JS `if (n)` is false for 0 / NaN; non-numbers fail the guard.
                    json::JsonValue::Number(n) if *n != 0.0 && !n.is_nan() => Some(*n),
                    _ => None,
                }),
            _ => None,
        }
    };

    Some(LogEntry {
        input_tokens: truthy("inputTokens"),
        output_tokens: truthy("outputTokens"),
        estimated_cost_usd: truthy("estimatedCostUsd"),
    })
}

/// Minimal recursive-descent JSON parser - just enough to validate a line and
/// read top-level numeric fields, matching `JSON.parse` accept/reject behavior.
/// Not a public API; lives only to keep this crate free of a `serde_json` dep.
mod json {
    /// All JSON value kinds are represented for parser completeness, but only
    /// `Object`/`Number` are read by callers - the parser still has to walk
    /// past strings/bools/nulls/arrays to validate the surrounding object.
    #[allow(dead_code)]
    pub enum JsonValue {
        Object(Vec<(String, JsonValue)>),
        Array(Vec<JsonValue>),
        String(String),
        Number(f64),
        Bool(bool),
        Null,
    }

    pub fn skip_ws(b: &[u8], pos: &mut usize) {
        while *pos < b.len() && matches!(b[*pos], b' ' | b'\t' | b'\n' | b'\r') {
            *pos += 1;
        }
    }

    pub fn parse_value(b: &[u8], pos: &mut usize) -> Option<JsonValue> {
        skip_ws(b, pos);
        if *pos >= b.len() {
            return None;
        }
        match b[*pos] {
            b'{' => parse_object(b, pos),
            b'[' => parse_array(b, pos),
            b'"' => parse_string(b, pos).map(JsonValue::String),
            b't' | b'f' => parse_bool(b, pos),
            b'n' => parse_null(b, pos),
            b'-' | b'0'..=b'9' => parse_number(b, pos),
            _ => None,
        }
    }

    fn parse_object(b: &[u8], pos: &mut usize) -> Option<JsonValue> {
        *pos += 1; // consume '{'
        let mut fields = Vec::new();
        skip_ws(b, pos);
        if *pos < b.len() && b[*pos] == b'}' {
            *pos += 1;
            return Some(JsonValue::Object(fields));
        }
        loop {
            skip_ws(b, pos);
            if *pos >= b.len() || b[*pos] != b'"' {
                return None;
            }
            let key = parse_string(b, pos)?;
            skip_ws(b, pos);
            if *pos >= b.len() || b[*pos] != b':' {
                return None;
            }
            *pos += 1; // consume ':'
            let val = parse_value(b, pos)?;
            fields.push((key, val));
            skip_ws(b, pos);
            if *pos >= b.len() {
                return None;
            }
            match b[*pos] {
                b',' => {
                    *pos += 1;
                }
                b'}' => {
                    *pos += 1;
                    return Some(JsonValue::Object(fields));
                }
                _ => return None,
            }
        }
    }

    fn parse_array(b: &[u8], pos: &mut usize) -> Option<JsonValue> {
        *pos += 1; // consume '['
        let mut items = Vec::new();
        skip_ws(b, pos);
        if *pos < b.len() && b[*pos] == b']' {
            *pos += 1;
            return Some(JsonValue::Array(items));
        }
        loop {
            let val = parse_value(b, pos)?;
            items.push(val);
            skip_ws(b, pos);
            if *pos >= b.len() {
                return None;
            }
            match b[*pos] {
                b',' => {
                    *pos += 1;
                }
                b']' => {
                    *pos += 1;
                    return Some(JsonValue::Array(items));
                }
                _ => return None,
            }
        }
    }

    fn parse_string(b: &[u8], pos: &mut usize) -> Option<String> {
        *pos += 1; // consume opening '"'
        let mut out = String::new();
        while *pos < b.len() {
            let c = b[*pos];
            match c {
                b'"' => {
                    *pos += 1;
                    return Some(out);
                }
                b'\\' => {
                    *pos += 1;
                    if *pos >= b.len() {
                        return None;
                    }
                    match b[*pos] {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if *pos + 4 >= b.len() {
                                return None;
                            }
                            let hex = std::str::from_utf8(&b[*pos + 1..*pos + 5]).ok()?;
                            let code = u32::from_str_radix(hex, 16).ok()?;
                            out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                            *pos += 4;
                        }
                        _ => return None,
                    }
                    *pos += 1;
                }
                _ => {
                    // Copy a full UTF-8 scalar (bytes between ASCII boundaries).
                    let start = *pos;
                    *pos += 1;
                    while *pos < b.len() && (b[*pos] & 0xC0) == 0x80 {
                        *pos += 1;
                    }
                    out.push_str(std::str::from_utf8(&b[start..*pos]).ok()?);
                }
            }
        }
        None
    }

    fn parse_bool(b: &[u8], pos: &mut usize) -> Option<JsonValue> {
        if b[*pos..].starts_with(b"true") {
            *pos += 4;
            Some(JsonValue::Bool(true))
        } else if b[*pos..].starts_with(b"false") {
            *pos += 5;
            Some(JsonValue::Bool(false))
        } else {
            None
        }
    }

    fn parse_null(b: &[u8], pos: &mut usize) -> Option<JsonValue> {
        if b[*pos..].starts_with(b"null") {
            *pos += 4;
            Some(JsonValue::Null)
        } else {
            None
        }
    }

    fn parse_number(b: &[u8], pos: &mut usize) -> Option<JsonValue> {
        let start = *pos;
        if *pos < b.len() && b[*pos] == b'-' {
            *pos += 1;
        }
        while *pos < b.len() && b[*pos].is_ascii_digit() {
            *pos += 1;
        }
        if *pos < b.len() && b[*pos] == b'.' {
            *pos += 1;
            while *pos < b.len() && b[*pos].is_ascii_digit() {
                *pos += 1;
            }
        }
        if *pos < b.len() && (b[*pos] == b'e' || b[*pos] == b'E') {
            *pos += 1;
            if *pos < b.len() && (b[*pos] == b'+' || b[*pos] == b'-') {
                *pos += 1;
            }
            while *pos < b.len() && b[*pos].is_ascii_digit() {
                *pos += 1;
            }
        }
        let slice = std::str::from_utf8(&b[start..*pos]).ok()?;
        slice.parse::<f64>().ok().map(JsonValue::Number)
    }
}

#[async_trait]
impl Check for CostExposureCheck {
    fn category(&self) -> &'static str {
        "cost"
    }

    async fn run(&self, ctx: &dyn AuditContext, _opts: &AuditOptions) -> Vec<AuditFinding> {
        let _db = &*self.db;
        let mut findings: Vec<AuditFinding> = Vec::new();

        // COST-001: LLM provider spending limits
        let env_path = format!("{}/.env", ctx.state_dir());
        let env_content = ctx.read_file(&env_path).await;
        let has_spending_limits = match &env_content {
            Some(content) => {
                content.contains("SPENDING_LIMIT")
                    || content.contains("MAX_BUDGET")
                    || content.contains("COST_LIMIT")
            }
            None => false,
        };

        if !has_spending_limits {
            findings.push(
                AuditFinding::builder("SC-COST-001", Severity::Medium, "cost")
                    .title("No LLM provider spending limits configured")
                    .description("No spending limit environment variables found. Runaway API costs are possible.")
                    .evidence("No SPENDING_LIMIT, MAX_BUDGET, or COST_LIMIT variables in .env")
                    .remediation("Set spending limits via your LLM provider dashboard and add SPENDING_LIMIT to .env")
                    .owasp_asi("ASI08")
                    .maestro(MaestroLayer::L5)
                    .nist(NistAttackType::Misuse)
                    .build(),
            );
        }

        // COST-002: Estimate token usage from session logs
        let session_logs = ctx.session_logs();
        let mut total_tokens: f64 = 0.0;
        let mut total_cost: f64 = 0.0;
        for log_content in session_logs {
            for line in log_content.split('\n').filter(|l| !l.is_empty()) {
                if let Some(entry) = parse_log_line(line) {
                    if let Some(n) = entry.input_tokens {
                        total_tokens += n;
                    }
                    if let Some(n) = entry.output_tokens {
                        total_tokens += n;
                    }
                    if let Some(n) = entry.estimated_cost_usd {
                        total_cost += n;
                    }
                }
                // Skip non-JSON lines
            }
        }

        if total_cost > 0.0 {
            findings.push(
                AuditFinding::builder("SC-COST-002", Severity::Info, "cost")
                    .title("API cost usage detected in session logs")
                    .description(format!(
                        "Estimated total cost from recent sessions: ${:.2} ({} tokens)",
                        total_cost,
                        js_num(total_tokens)
                    ))
                    .evidence(format!(
                        "Total tokens: {}, Estimated cost: ${:.2}",
                        js_num(total_tokens),
                        total_cost
                    ))
                    .remediation("Set SPENDING_LIMIT, MAX_BUDGET, or COST_LIMIT in .env, then run \"secureops monitor\"")
                    .owasp_asi("ASI08")
                    .maestro(MaestroLayer::L5)
                    .nist(NistAttackType::Misuse)
                    .build(),
            );
        }

        // COST-003: High-frequency cron jobs
        // Check for cron-like invocation patterns in config
        let cron_path = format!("{}/crontab", ctx.state_dir());
        let cron_config = ctx.read_file(&cron_path).await;
        if let Some(cron_config) = cron_config.as_deref().filter(|c| !c.is_empty()) {
            // Check for intervals less than 5 minutes
            let has_high_freq = HIGH_FREQ_CRON.is_match(cron_config);
            if has_high_freq {
                findings.push(
                    AuditFinding::builder("SC-COST-003", Severity::High, "cost")
                        .title("High-frequency agent invocation detected")
                        .description("Cron jobs invoke the agent every few minutes. This can cause significant API costs.")
                        .evidence("Crontab contains high-frequency schedules")
                        .remediation("Increase the cron interval to at least every 15 minutes, or use event-driven triggers")
                        .owasp_asi("ASI08")
                        .maestro(MaestroLayer::L5)
                        .nist(NistAttackType::Misuse)
                        .build(),
                );
            }
        }

        // COST-004: Daily cost threshold
        let daily_threshold = ctx
            .config()
            .secureops
            .as_ref()
            .and_then(|s| s.cost.as_ref())
            .and_then(|c| c.daily_limit_usd)
            .unwrap_or(5.0);
        if total_cost > daily_threshold {
            findings.push(
                AuditFinding::builder("SC-COST-004", Severity::High, "cost")
                    .title("Daily cost threshold exceeded")
                    .description(format!(
                        "Estimated daily cost (${:.2}) exceeds threshold (${}).",
                        total_cost,
                        js_num(daily_threshold)
                    ))
                    .evidence(format!(
                        "Daily cost: ${:.2}, Threshold: ${}",
                        total_cost,
                        js_num(daily_threshold)
                    ))
                    .remediation("Review session logs for unexpected usage. Consider enabling the cost circuit breaker.")
                    .owasp_asi("ASI08")
                    .maestro(MaestroLayer::L5)
                    .nist(NistAttackType::Misuse)
                    .build(),
            );
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockAuditContext;
    use secureops_core::{CostLimits, OpenClawConfig, SecureOpsConfig};

    fn db() -> Arc<IocDatabase> {
        Arc::new(IocDatabase::default())
    }

    fn ids(findings: &[AuditFinding]) -> Vec<String> {
        findings.iter().map(|f| f.id.clone()).collect()
    }

    /// A bare context (no .env, no crontab, no session logs, default config)
    /// fires only COST-001 (no spending limits), and nothing else.
    #[tokio::test]
    async fn missing_spending_limits_fires_cost_001_only() {
        let ctx = MockAuditContext::new();
        let check = CostExposureCheck::new(db());
        let findings = check.run(&ctx, &AuditOptions::default()).await;
        let got = ids(&findings);
        assert!(got.contains(&"SC-COST-001".to_string()));
        assert!(!got.contains(&"SC-COST-002".to_string()));
        assert!(!got.contains(&"SC-COST-003".to_string()));
        assert!(!got.contains(&"SC-COST-004".to_string()));
    }

    /// A `.env` declaring a spending limit suppresses COST-001.
    #[tokio::test]
    async fn spending_limit_env_suppresses_cost_001() {
        let ctx = MockAuditContext::new().with_file("/state/.env", "SPENDING_LIMIT=100\n");
        let check = CostExposureCheck::new(db());
        let findings = check.run(&ctx, &AuditOptions::default()).await;
        assert!(!ids(&findings).contains(&"SC-COST-001".to_string()));
    }

    /// Session-log cost rolls up into COST-002, and exceeding the default $5
    /// daily threshold additionally fires COST-004 with faithful templating.
    #[tokio::test]
    async fn session_cost_fires_cost_002_and_004() {
        let logs = vec![
            "{\"inputTokens\":1000,\"outputTokens\":500,\"estimatedCostUsd\":4.0}\nnot-json\n{\"estimatedCostUsd\":2.5}"
                .to_string(),
        ];
        let ctx = MockAuditContext::new()
            .with_file("/state/.env", "SPENDING_LIMIT=1\n")
            .with_session_logs(logs);
        let check = CostExposureCheck::new(db());
        let findings = check.run(&ctx, &AuditOptions::default()).await;
        let got = ids(&findings);
        assert!(got.contains(&"SC-COST-002".to_string()));
        assert!(got.contains(&"SC-COST-004".to_string()));

        let f002 = findings.iter().find(|f| f.id == "SC-COST-002").unwrap();
        assert_eq!(
            f002.description,
            "Estimated total cost from recent sessions: $6.50 (1500 tokens)"
        );
        assert_eq!(f002.evidence, "Total tokens: 1500, Estimated cost: $6.50");

        let f004 = findings.iter().find(|f| f.id == "SC-COST-004").unwrap();
        assert_eq!(
            f004.description,
            "Estimated daily cost ($6.50) exceeds threshold ($5)."
        );
        assert_eq!(f004.evidence, "Daily cost: $6.50, Threshold: $5");
    }

    /// A configured higher daily threshold prevents COST-004 even when COST-002
    /// fires; a high-frequency crontab fires COST-003.
    #[tokio::test]
    async fn high_threshold_suppresses_004_and_cron_fires_003() {
        let config = OpenClawConfig {
            secureops: Some(SecureOpsConfig {
                cost: Some(CostLimits {
                    daily_limit_usd: Some(50.0),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let logs = vec!["{\"estimatedCostUsd\":3.0}".to_string()];
        let ctx = MockAuditContext::new()
            .with_config(config)
            .with_file("/state/.env", "MAX_BUDGET=1\n")
            .with_file("/state/crontab", "* * * * * openclaw run\n")
            .with_session_logs(logs);
        let check = CostExposureCheck::new(db());
        let findings = check.run(&ctx, &AuditOptions::default()).await;
        let got = ids(&findings);
        assert!(got.contains(&"SC-COST-002".to_string()));
        assert!(got.contains(&"SC-COST-003".to_string()));
        assert!(!got.contains(&"SC-COST-004".to_string()));
    }
}

//! Cost monitor + circuit breaker - port of `monitors/cost-monitor.ts`.
//!
//! The pure cost math (`parse_session_log`, `calculate_cost_for_window`,
//! `generate_cost_report`, `check_limits`) is faithful to the TS and injects
//! `now` so it is deterministic and unit-/cross-testable. The [`Monitor::run`]
//! loop is the runtime shell (poll every 60s instead of `setInterval`).

use crate::{AlertBus, CancellationToken, CircuitState, Monitor};
use async_trait::async_trait;
use secureops_core::{CostEntry, CostProjection, CostReport, MonitorAlert, Severity};
use std::sync::Arc;
use std::sync::Mutex;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::watch;

const HOUR_MS: i128 = 60 * 60 * 1000;
const DAY_MS: i128 = 24 * HOUR_MS;
const MONTH_MS: i128 = 30 * DAY_MS;

/// Approximate cost per token (USD), input/output (port of `TOKEN_COSTS`).
fn token_cost(model: &str) -> (f64, f64) {
    match model {
        "claude-opus-4" => (0.000015, 0.000075),
        "claude-sonnet-4" => (0.000003, 0.000015),
        "claude-haiku-4" => (0.0000008, 0.000004),
        "gpt-4" => (0.00003, 0.00006),
        "gpt-4o" => (0.0000025, 0.00001),
        _ => (0.000003, 0.000015), // "default"
    }
}

/// Spending limits + circuit-breaker toggle (port of the module's config vars).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub hourly_usd: f64,
    pub daily_usd: f64,
    pub monthly_usd: f64,
    pub circuit_breaker_enabled: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            hourly_usd: 2.0,
            daily_usd: 10.0,
            monthly_usd: 100.0,
            circuit_breaker_enabled: true,
        }
    }
}

/// Parse a JSONL session log into cost entries (port of `parseSessionLog`).
///
/// A line yields an entry when it has a truthy `inputTokens`, `outputTokens`, or
/// `model`. Missing `timestamp` falls back to `now` (TS uses `new Date()`).
pub fn parse_session_log(content: &str, now: &str) -> Vec<CostEntry> {
    let mut entries = Vec::new();
    for line in content.split('\n').filter(|l| !l.is_empty()) {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let input_tokens = v.get("inputTokens").and_then(|x| x.as_u64()).unwrap_or(0);
        let output_tokens = v.get("outputTokens").and_then(|x| x.as_u64()).unwrap_or(0);
        let model_field = v.get("model").and_then(|x| x.as_str());
        let truthy =
            input_tokens != 0 || output_tokens != 0 || model_field.is_some_and(|m| !m.is_empty());
        if !truthy {
            continue;
        }
        let model = model_field.unwrap_or("default").to_string();
        let (ci, co) = token_cost(&model);
        let estimated = (input_tokens as f64) * ci + (output_tokens as f64) * co;
        let timestamp = v
            .get("timestamp")
            .and_then(|x| x.as_str())
            .unwrap_or(now)
            .to_string();
        entries.push(CostEntry {
            timestamp,
            model,
            input_tokens,
            output_tokens,
            estimated_cost_usd: estimated,
        });
    }
    entries
}

use secureops_core::parse_ms as timestamp_ms;

/// Sum cost of entries within `window_ms` of `now_ms` (port of
/// `calculateCostForWindow`; unparseable timestamps are excluded, as in TS).
pub fn calculate_cost_for_window(entries: &[CostEntry], window_ms: i128, now_ms: i128) -> f64 {
    let cutoff = now_ms - window_ms;
    entries
        .iter()
        .filter_map(|e| timestamp_ms(&e.timestamp).map(|t| (t, e.estimated_cost_usd)))
        .filter(|(t, _)| *t >= cutoff)
        .map(|(_, c)| c)
        .sum()
}

/// Build a [`CostReport`] from entries (port of `generateCostReport`).
pub fn generate_cost_report(entries: &[CostEntry], now_ms: i128, tripped: bool) -> CostReport {
    let hourly = calculate_cost_for_window(entries, HOUR_MS, now_ms);
    let daily = calculate_cost_for_window(entries, DAY_MS, now_ms);
    let monthly = calculate_cost_for_window(entries, MONTH_MS, now_ms);
    let projected_daily = hourly * 24.0;
    let projected_monthly = projected_daily * 30.0;
    CostReport {
        hourly,
        daily,
        monthly,
        projection: CostProjection {
            daily: projected_daily,
            monthly: projected_monthly,
        },
        circuit_breaker_tripped: tripped,
        entries: entries.to_vec(),
    }
}

/// Outcome of a limit check: the alerts to publish and whether the breaker tripped.
pub struct CheckOutcome {
    pub alerts: Vec<MonitorAlert>,
    pub tripped: bool,
}

fn alert(
    severity: Severity,
    message: String,
    details: Option<String>,
    now_iso: &str,
) -> MonitorAlert {
    MonitorAlert {
        timestamp: now_iso.to_string(),
        severity,
        monitor: "cost-monitor".to_string(),
        message,
        details,
    }
}

/// Check spending limits and produce alerts (port of `checkLimits`).
///
/// Returns the alerts in TS emission order and whether the circuit breaker
/// tripped (hourly over limit with the breaker enabled).
pub fn check_limits(
    entries: &[CostEntry],
    limits: &Limits,
    now_ms: i128,
    now_iso: &str,
) -> CheckOutcome {
    let mut alerts = Vec::new();
    let mut tripped = false;

    let hourly = calculate_cost_for_window(entries, HOUR_MS, now_ms);
    let daily = calculate_cost_for_window(entries, DAY_MS, now_ms);
    let monthly = calculate_cost_for_window(entries, MONTH_MS, now_ms);

    if hourly > limits.hourly_usd {
        alerts.push(alert(
            Severity::Critical,
            format!(
                "Hourly spend (${:.2}) exceeds limit (${})",
                hourly, limits.hourly_usd
            ),
            Some(format!("Entries in window: {}", entries.len())),
            now_iso,
        ));
        if limits.circuit_breaker_enabled {
            tripped = true;
            alerts.push(alert(
                Severity::Critical,
                "Circuit breaker TRIPPED - pausing agent sessions".to_string(),
                Some(format!(
                    "Hourly spend: ${:.2}, Limit: ${}",
                    hourly, limits.hourly_usd
                )),
                now_iso,
            ));
        }
    }

    if daily > limits.daily_usd {
        alerts.push(alert(
            Severity::High,
            format!(
                "Daily spend (${:.2}) exceeds limit (${})",
                daily, limits.daily_usd
            ),
            None,
            now_iso,
        ));
    }

    if monthly > limits.monthly_usd {
        alerts.push(alert(
            Severity::High,
            format!(
                "Monthly spend (${:.2}) exceeds limit (${})",
                monthly, limits.monthly_usd
            ),
            None,
            now_iso,
        ));
    }

    // Spike detection: recent hour > 3x average and > $0.10.
    if !entries.is_empty() {
        let total: f64 = entries.iter().map(|e| e.estimated_cost_usd).sum();
        let avg = total / entries.len() as f64;
        let recent_total: f64 = entries
            .iter()
            .filter(|e| timestamp_ms(&e.timestamp).is_some_and(|t| now_ms - t < HOUR_MS))
            .map(|e| e.estimated_cost_usd)
            .sum();
        if recent_total > avg * 3.0 && recent_total > 0.1 {
            alerts.push(alert(
                Severity::High,
                format!(
                    "Unusual cost spike detected: ${:.2} in the last hour (3x normal)",
                    recent_total
                ),
                None,
                now_iso,
            ));
        }
    }

    CheckOutcome { alerts, tripped }
}

/// Cost-tracking monitor + circuit breaker (PRODUCT.md B.9 step 1).
pub struct CostMonitor {
    pub circuit: watch::Sender<CircuitState>,
    state_dir: String,
    limits: Limits,
    entries: Arc<Mutex<Vec<CostEntry>>>,
    tripped: Arc<Mutex<bool>>,
}

impl CostMonitor {
    /// Construct with a handle to the shared circuit-breaker channel.
    pub fn new(circuit: watch::Sender<CircuitState>) -> Self {
        Self {
            circuit,
            state_dir: String::new(),
            limits: Limits::default(),
            entries: Arc::new(Mutex::new(Vec::new())),
            tripped: Arc::new(Mutex::new(false)),
        }
    }

    pub fn with_state_dir(mut self, state_dir: impl Into<String>) -> Self {
        self.state_dir = state_dir.into();
        self
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Record a usage entry and return the updated rolling report (port of the
    /// external `addCostEntries` + `generateCostReport`). `now_ms` injected.
    pub fn record(&self, entry: CostEntry, now_ms: i128) -> CostReport {
        let mut entries = self.entries.lock().unwrap();
        entries.push(entry);
        let tripped = *self.tripped.lock().unwrap();
        generate_cost_report(&entries, now_ms, tripped)
    }

    pub fn is_tripped(&self) -> bool {
        *self.tripped.lock().unwrap()
    }
}

/// Scan `<stateDir>/agents/*/sessions/*.jsonl` and parse all cost entries
/// (port of the `start` log-scan; `now` fills missing timestamps).
pub async fn scan_state_dir(state_dir: &str, now: &str) -> Vec<CostEntry> {
    let mut out = Vec::new();
    let agents_dir = format!("{state_dir}/agents");
    let mut agents = match tokio::fs::read_dir(&agents_dir).await {
        Ok(r) => r,
        Err(_) => return out,
    };
    while let Ok(Some(agent)) = agents.next_entry().await {
        let sessions = agent.path().join("sessions");
        let mut sd = match tokio::fs::read_dir(&sessions).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        while let Ok(Some(f)) = sd.next_entry().await {
            let p = f.path();
            if p.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            if let Ok(content) = tokio::fs::read_to_string(&p).await {
                out.extend(parse_session_log(&content, now));
            }
        }
    }
    out
}

#[async_trait]
impl Monitor for CostMonitor {
    fn name(&self) -> &'static str {
        "cost"
    }

    async fn run(&self, bus: AlertBus, mut cancel: CancellationToken) {
        // First tick fires immediately (tokio interval semantics), so the
        // initial scan + limit check runs at startup.
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    let now = OffsetDateTime::now_utc();
                    let now_ms = now.unix_timestamp_nanos() / 1_000_000;
                    let now_iso = now.format(&Rfc3339).unwrap_or_default();
                    // Re-scan the session logs on every tick.
                    let entries = scan_state_dir(&self.state_dir, &now_iso).await;
                    *self.entries.lock().unwrap() = entries.clone();
                    let outcome = check_limits(&entries, &self.limits, now_ms, &now_iso);
                    if outcome.tripped {
                        *self.tripped.lock().unwrap() = true;
                        let _ = self.circuit.send(CircuitState::Tripped);
                    }
                    for a in outcome.alerts {
                        let _ = bus.publish(a);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(model: &str, inp: u64, out: u64, ts: &str) -> CostEntry {
        let (ci, co) = token_cost(model);
        CostEntry {
            timestamp: ts.to_string(),
            model: model.to_string(),
            input_tokens: inp,
            output_tokens: out,
            estimated_cost_usd: (inp as f64) * ci + (out as f64) * co,
        }
    }

    #[test]
    fn parse_session_log_extracts_entries_and_costs() {
        let now = "2026-05-29T12:00:00Z";
        let log = r#"{"timestamp":"2026-05-29T11:00:00Z","model":"gpt-4","inputTokens":1000,"outputTokens":500}
not-json
{"foo":"bar"}
{"model":"claude-opus-4","inputTokens":100,"outputTokens":0,"timestamp":"2026-05-29T11:30:00Z"}"#;
        let e = parse_session_log(log, now);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].model, "gpt-4");
        // 1000*0.00003 + 500*0.00006 = 0.03 + 0.03 = 0.06
        assert!((e[0].estimated_cost_usd - 0.06).abs() < 1e-9);
        assert_eq!(e[1].model, "claude-opus-4");
    }

    #[test]
    fn window_and_report_respect_cutoff() {
        let now = timestamp_ms("2026-05-29T12:00:00Z").unwrap();
        let entries = vec![
            entry("gpt-4", 1000, 0, "2026-05-29T11:30:00Z"), // 30min ago -> in hour
            entry("gpt-4", 1000, 0, "2026-05-28T11:30:00Z"), // ~24h+ ago -> not in hour
        ];
        let hourly = calculate_cost_for_window(&entries, HOUR_MS, now);
        assert!((hourly - 0.03).abs() < 1e-9);
        let report = generate_cost_report(&entries, now, false);
        assert!((report.hourly - 0.03).abs() < 1e-9);
        assert!(report.daily >= report.hourly);
        assert!((report.projection.daily - report.hourly * 24.0).abs() < 1e-9);
    }

    #[test]
    fn check_limits_trips_breaker_over_hourly() {
        let now_iso = "2026-05-29T12:00:00Z";
        let now = timestamp_ms(now_iso).unwrap();
        // One pricey entry in the last hour: 1e6 output tokens on opus = $75.
        let entries = vec![entry("claude-opus-4", 0, 1_000_000, "2026-05-29T11:59:00Z")];
        let limits = Limits::default(); // hourly 2.0
        let out = check_limits(&entries, &limits, now, now_iso);
        assert!(out.tripped);
        // hourly-over + breaker-tripped + daily-over + monthly-over alerts.
        let msgs: Vec<&str> = out.alerts.iter().map(|a| a.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("Hourly spend")));
        assert!(msgs.iter().any(|m| m.contains("Circuit breaker TRIPPED")));
        assert!(msgs.iter().any(|m| m.contains("Daily spend")));
        assert_eq!(out.alerts[0].monitor, "cost-monitor");
    }

    #[tokio::test]
    async fn scan_state_dir_reads_session_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_str().unwrap();
        let sessions = dir.path().join("agents").join("a1").join("sessions");
        tokio::fs::create_dir_all(&sessions).await.unwrap();
        tokio::fs::write(
            sessions.join("s.jsonl"),
            "{\"model\":\"gpt-4\",\"inputTokens\":1000,\"outputTokens\":0,\"timestamp\":\"2026-05-29T11:00:00Z\"}\n",
        )
        .await
        .unwrap();
        tokio::fs::write(sessions.join("ignore.txt"), "not scanned")
            .await
            .unwrap();
        let entries = scan_state_dir(sd, "2026-05-29T12:00:00Z").await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].model, "gpt-4");
    }

    #[test]
    fn under_limit_no_alerts() {
        let now_iso = "2026-05-29T12:00:00Z";
        let now = timestamp_ms(now_iso).unwrap();
        let entries = vec![entry("gpt-4", 100, 50, "2026-05-29T11:59:00Z")];
        let out = check_limits(&entries, &Limits::default(), now, now_iso);
        assert!(!out.tripped);
        assert!(out.alerts.is_empty());
    }
}

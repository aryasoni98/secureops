//! Behavioral baseline (directive G3) - faithful port of `logToolCall` /
//! `getBehavioralBaseline` from `src/index.ts`.
//!
//! Tool calls are appended as JSONL to
//! `<stateDir>/.secureops/behavioral/tool-calls.jsonl`; the baseline tallies
//! per-tool frequency within a rolling window. `now`/`now_ms` are injected for
//! determinism.

use std::collections::HashMap;
use std::path::Path;

/// Rolling behavioral statistics (port of the `getBehavioralBaseline` return).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct BehavioralStats {
    pub tool_frequency: HashMap<String, u64>,
    pub total_calls: u64,
    pub unique_tools: usize,
}

fn behavioral_log_path(state_dir: &str) -> std::path::PathBuf {
    Path::new(state_dir)
        .join(".secureops")
        .join("behavioral")
        .join("tool-calls.jsonl")
}

/// Append a tool-call entry (port of `logToolCall`). `now` is RFC3339.
pub async fn log_tool_call(
    state_dir: &str,
    tool: &str,
    data_path: Option<&str>,
    now: &str,
) -> std::io::Result<()> {
    let dir = Path::new(state_dir).join(".secureops").join("behavioral");
    tokio::fs::create_dir_all(&dir).await?;
    let entry = serde_json::json!({
        "timestamp": now,
        "tool": tool,
        "dataPath": data_path.unwrap_or(""),
    })
    .to_string();
    let path = dir.join("tool-calls.jsonl");
    // Append by read-modify-write (avoids the tokio `io-util` feature).
    let mut existing = tokio::fs::read_to_string(&path).await.unwrap_or_default();
    existing.push_str(&entry);
    existing.push('\n');
    tokio::fs::write(&path, existing).await
}

/// Tally tool-call frequency within the last `window_minutes` (port of
/// `getBehavioralBaseline`). Missing log → empty stats; unparseable lines/
/// timestamps are skipped.
pub async fn get_behavioral_baseline(
    state_dir: &str,
    window_minutes: i64,
    now_ms: i128,
) -> BehavioralStats {
    let content = match tokio::fs::read_to_string(behavioral_log_path(state_dir)).await {
        Ok(c) => c,
        Err(_) => return BehavioralStats::default(),
    };
    let cutoff = now_ms - (window_minutes as i128) * 60_000;
    let mut frequency: HashMap<String, u64> = HashMap::new();
    let mut total = 0u64;
    for line in content.split('\n').filter(|l| !l.is_empty()) {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ts = v.get("timestamp").and_then(|x| x.as_str()).unwrap_or("");
        let ms = match secureops_core::parse_ms(ts) {
            Some(t) => t,
            None => continue,
        };
        if ms >= cutoff {
            let tool = v
                .get("tool")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            *frequency.entry(tool).or_insert(0) += 1;
            total += 1;
        }
    }
    let unique_tools = frequency.len();
    BehavioralStats {
        tool_frequency: frequency,
        total_calls: total,
        unique_tools,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(ts: &str) -> i128 {
        secureops_core::parse_ms(ts).unwrap()
    }

    #[tokio::test]
    async fn log_then_baseline_counts_within_window() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_str().unwrap();
        log_tool_call(sd, "read_file", Some("/a"), "2026-05-29T12:00:00Z")
            .await
            .unwrap();
        log_tool_call(sd, "read_file", None, "2026-05-29T12:10:00Z")
            .await
            .unwrap();
        log_tool_call(sd, "exec", None, "2026-05-29T12:20:00Z")
            .await
            .unwrap();

        let now = ms("2026-05-29T12:30:00Z");
        let stats = get_behavioral_baseline(sd, 60, now).await;
        assert_eq!(stats.total_calls, 3);
        assert_eq!(stats.unique_tools, 2);
        assert_eq!(stats.tool_frequency.get("read_file"), Some(&2));
        assert_eq!(stats.tool_frequency.get("exec"), Some(&1));
    }

    #[tokio::test]
    async fn baseline_excludes_outside_window() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_str().unwrap();
        log_tool_call(sd, "old", None, "2026-05-29T10:00:00Z")
            .await
            .unwrap();
        log_tool_call(sd, "recent", None, "2026-05-29T12:29:00Z")
            .await
            .unwrap();
        let now = ms("2026-05-29T12:30:00Z");
        let stats = get_behavioral_baseline(sd, 60, now).await; // window: 11:30+
        assert_eq!(stats.total_calls, 1);
        assert_eq!(stats.tool_frequency.get("recent"), Some(&1));
    }

    #[tokio::test]
    async fn missing_log_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let stats = get_behavioral_baseline(dir.path().to_str().unwrap(), 60, 0).await;
        assert_eq!(stats, BehavioralStats::default());
    }
}

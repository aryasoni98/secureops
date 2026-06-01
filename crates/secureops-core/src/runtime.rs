//! Runtime value types shared by monitors, hardening and the daemon.
//!
//! Port of the monitor / cost / hardening / skill-scan interfaces in
//! `src/types.ts`. Behavior (the actual tokio monitors, AlertBus, hardening
//! modules) lives in `secureops-monitors` / future hardening crates; these are
//! the data shapes that cross the JSON / IPC boundary.

use crate::types::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A monitor alert emitted onto the AlertBus and persisted to SQLite.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MonitorAlert {
    pub timestamp: String,
    pub severity: Severity,
    pub monitor: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub details: Option<String>,
}

/// Snapshot of a monitor's state.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MonitorStatus {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_check: Option<String>,
    pub alerts: Vec<MonitorAlert>,
}

/// One cost-tracking entry.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CostEntry {
    pub timestamp: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub estimated_cost_usd: f64,
}

/// Rolling cost report + circuit-breaker state.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CostReport {
    pub hourly: f64,
    pub daily: f64,
    pub monthly: f64,
    pub projection: CostProjection,
    pub circuit_breaker_tripped: bool,
    pub entries: Vec<CostEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CostProjection {
    pub daily: f64,
    pub monthly: f64,
}

/// Result of scanning a single skill.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SkillScanResult {
    pub safe: bool,
    pub skill_name: String,
    pub findings: Vec<String>,
    pub dangerous_patterns: Vec<String>,
    pub ioc_matches: Vec<String>,
}

/// Behavioral baseline entry (directive G3).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralBaseline {
    pub tool_call_frequency: HashMap<String, u64>,
    pub typical_tools: Vec<String>,
    pub typical_data_paths: Vec<String>,
    pub window_minutes: u64,
    pub last_updated: String,
}

// ---- Hardening ----

/// A single hardening action taken (before/after for rollback + audit).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HardeningAction {
    pub id: String,
    pub description: String,
    pub before: String,
    pub after: String,
}

/// Result of running one hardening module.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HardeningResult {
    pub module: String,
    pub applied: Vec<HardeningAction>,
    pub skipped: Vec<HardeningAction>,
    pub errors: Vec<String>,
}

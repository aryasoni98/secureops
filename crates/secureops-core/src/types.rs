//! Audit finding / report value types — the JSON wire contract.
//!
//! Faithful port of `src/types.ts`. Field names are pinned to the TypeScript
//! shapes via serde renames; do not change them without updating the TS shim.

use serde::{Deserialize, Serialize};

/// Severity levels for audit findings. Serializes UPPERCASE (`"CRITICAL"`, …).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// CSA MAESTRO 7-layer agentic-AI threat model. Serializes `"L1"`..`"L7"`.
///
/// Declaration order is significant: derived `Ord` gives L1 < L2 < … < L7, which
/// matches the lexical sort the TS cross-layer pass performs on the layer labels.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum MaestroLayer {
    L1,
    L2,
    L3,
    L4,
    L5,
    L6,
    L7,
}

impl MaestroLayer {
    /// The on-the-wire label, e.g. `"L4"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            MaestroLayer::L1 => "L1",
            MaestroLayer::L2 => "L2",
            MaestroLayer::L3 => "L3",
            MaestroLayer::L4 => "L4",
            MaestroLayer::L5 => "L5",
            MaestroLayer::L6 => "L6",
            MaestroLayer::L7 => "L7",
        }
    }
}

/// NIST AI 100-2 E2025 GenAI attack types. Serializes lowercase.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum NistAttackType {
    Evasion,
    Poisoning,
    Privacy,
    Misuse,
}

/// A single audit finding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuditFinding {
    pub id: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
    pub auto_fixable: bool,
    pub references: Vec<String>,
    pub owasp_asi: String,
    /// CSA MAESTRO layer (L1–L7). Omitted from JSON when absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub maestro_layer: Option<MaestroLayer>,
    /// NIST AI 100-2 E2025 GenAI attack type. Omitted from JSON when absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nist_category: Option<NistAttackType>,
}

/// Summary counts of findings by severity.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuditSummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
    pub auto_fixable: u32,
}

/// Full audit report — the top-level JSON document.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuditReport {
    pub timestamp: String,
    pub openclaw_version: String,
    pub secureops_version: String,
    pub platform: String,
    pub deployment_mode: String,
    pub score: u32,
    pub findings: Vec<AuditFinding>,
    pub summary: AuditSummary,
}

impl AuditReport {
    /// Serialize as pretty JSON, matching `formatJsonReport` (2-space indent).
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("AuditReport is always serializable")
    }
}

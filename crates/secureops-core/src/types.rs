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

impl AuditFinding {
    /// Start building a finding from its three always-present fields. Optional
    /// fields default to: `auto_fixable = false`, `references = []`,
    /// `maestro_layer = None`, `nist_category = None`; `title`/`description`/
    /// `evidence`/`remediation`/`owasp_asi` start empty and are set via the
    /// chainable setters. Produces a value byte-identical to the struct literal,
    /// without the repeated `.to_string()` / `Some(..)` / `vec![]` boilerplate.
    pub fn builder(
        id: impl Into<String>,
        severity: Severity,
        category: impl Into<String>,
    ) -> FindingBuilder {
        FindingBuilder {
            inner: AuditFinding {
                id: id.into(),
                severity,
                category: category.into(),
                title: String::new(),
                description: String::new(),
                evidence: String::new(),
                remediation: String::new(),
                auto_fixable: false,
                references: Vec::new(),
                owasp_asi: String::new(),
                maestro_layer: None,
                nist_category: None,
            },
        }
    }
}

/// Chainable builder for [`AuditFinding`] (see [`AuditFinding::builder`]).
#[derive(Clone, Debug)]
pub struct FindingBuilder {
    inner: AuditFinding,
}

impl FindingBuilder {
    /// Set the human-readable title.
    pub fn title(mut self, v: impl Into<String>) -> Self {
        self.inner.title = v.into();
        self
    }
    /// Set the description.
    pub fn description(mut self, v: impl Into<String>) -> Self {
        self.inner.description = v.into();
        self
    }
    /// Set the evidence string.
    pub fn evidence(mut self, v: impl Into<String>) -> Self {
        self.inner.evidence = v.into();
        self
    }
    /// Set the remediation guidance.
    pub fn remediation(mut self, v: impl Into<String>) -> Self {
        self.inner.remediation = v.into();
        self
    }
    /// Set the OWASP ASI mapping (e.g. `"ASI03"`).
    pub fn owasp_asi(mut self, v: impl Into<String>) -> Self {
        self.inner.owasp_asi = v.into();
        self
    }
    /// Mark the finding as auto-fixable (default `false`).
    pub fn auto_fixable(mut self, v: bool) -> Self {
        self.inner.auto_fixable = v;
        self
    }
    /// Set the references list (default empty).
    pub fn references<I, S>(mut self, refs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.inner.references = refs.into_iter().map(Into::into).collect();
        self
    }
    /// Set the CSA MAESTRO layer. Accepts a bare `MaestroLayer` or an
    /// `Option<MaestroLayer>` (so callers with a dynamic optional layer can pass
    /// it directly).
    pub fn maestro(mut self, layer: impl Into<Option<MaestroLayer>>) -> Self {
        self.inner.maestro_layer = layer.into();
        self
    }
    /// Set the NIST GenAI attack type. Accepts a bare `NistAttackType` or an
    /// `Option<NistAttackType>`.
    pub fn nist(mut self, attack: impl Into<Option<NistAttackType>>) -> Self {
        self.inner.nist_category = attack.into();
        self
    }
    /// Finalize into an [`AuditFinding`].
    pub fn build(self) -> AuditFinding {
        self.inner
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_is_byte_identical_to_struct_literal() {
        let literal = AuditFinding {
            id: "SC-GW-001".to_string(),
            severity: Severity::Critical,
            category: "gateway".to_string(),
            title: "Gateway not bound to loopback".to_string(),
            description: "desc".to_string(),
            evidence: "ev".to_string(),
            remediation: "fix".to_string(),
            auto_fixable: true,
            references: vec!["CVE-2026-25253".to_string()],
            owasp_asi: "ASI03".to_string(),
            maestro_layer: Some(MaestroLayer::L4),
            nist_category: Some(NistAttackType::Evasion),
        };
        let built = AuditFinding::builder("SC-GW-001", Severity::Critical, "gateway")
            .title("Gateway not bound to loopback")
            .description("desc")
            .evidence("ev")
            .remediation("fix")
            .auto_fixable(true)
            .references(["CVE-2026-25253"])
            .owasp_asi("ASI03")
            .maestro(MaestroLayer::L4)
            .nist(NistAttackType::Evasion)
            .build();
        assert_eq!(built, literal);
        assert_eq!(
            serde_json::to_string(&built).unwrap(),
            serde_json::to_string(&literal).unwrap()
        );
    }

    #[test]
    fn builder_defaults_match_minimal_literal() {
        let literal = AuditFinding {
            id: "X".to_string(),
            severity: Severity::Info,
            category: "c".to_string(),
            title: String::new(),
            description: String::new(),
            evidence: String::new(),
            remediation: String::new(),
            auto_fixable: false,
            references: vec![],
            owasp_asi: String::new(),
            maestro_layer: None,
            nist_category: None,
        };
        let built = AuditFinding::builder("X", Severity::Info, "c").build();
        assert_eq!(built, literal);
    }
}

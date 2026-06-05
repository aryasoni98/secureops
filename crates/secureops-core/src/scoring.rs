//! Scoring and the MAESTRO cross-layer compound-risk pass.
//!
//! Faithful port of `SEVERITY_DEDUCTIONS`, `calculateScore`, `computeSummary`
//! and `auditCrossLayerRisk` from `src/auditor.ts`.

use crate::types::{AuditFinding, AuditSummary, MaestroLayer, NistAttackType, Severity};
use std::collections::BTreeSet;

/// Per-severity score deduction. CRITICAL 15 / HIGH 8 / MEDIUM 3 / LOW 1 / INFO 0.
pub fn severity_deduction(sev: Severity) -> u32 {
    match sev {
        Severity::Critical => 15,
        Severity::High => 8,
        Severity::Medium => 3,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

/// `score = 100 − Σ deductions`, saturating at 0.
pub fn calculate_score(findings: &[AuditFinding]) -> u32 {
    let mut score: i32 = 100;
    for f in findings {
        score -= severity_deduction(f.severity) as i32;
    }
    score.max(0) as u32
}

/// Tally findings by severity and count auto-fixable ones.
pub fn compute_summary(findings: &[AuditFinding]) -> AuditSummary {
    let mut s = AuditSummary::default();
    for f in findings {
        match f.severity {
            Severity::Critical => s.critical += 1,
            Severity::High => s.high += 1,
            Severity::Medium => s.medium += 1,
            Severity::Low => s.low += 1,
            Severity::Info => s.info += 1,
        }
        if f.auto_fixable {
            s.auto_fixable += 1;
        }
    }
    s
}

/// MAESTRO cross-layer compound-risk pass.
///
/// Collects the unique MAESTRO layers that carry a non-INFO finding; if ≥3
/// distinct layers are affected, emits `SC-CROSS-001` (HIGH). The `BTreeSet`
/// yields the layers already sorted, matching the TS `Array.from(set).sort()`.
pub fn cross_layer_risk(findings: &[AuditFinding]) -> Vec<AuditFinding> {
    let mut affected: BTreeSet<MaestroLayer> = BTreeSet::new();
    for f in findings {
        if let Some(layer) = f.maestro_layer {
            if f.severity != Severity::Info {
                affected.insert(layer);
            }
        }
    }

    let mut out = Vec::new();
    if affected.len() >= 3 {
        let layers = affected
            .iter()
            .map(|l| l.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        out.push(
            AuditFinding::builder("SC-CROSS-001", Severity::High, "cross-layer")
                .title("Cross-layer compound attack surface detected")
                .description(format!(
                    "Findings span {} MAESTRO layers ({}). Compound attack surfaces enable chained exploits (e.g., supply chain → agent compromise → credential theft).",
                    affected.len(),
                    layers
                ))
                .evidence(format!("Affected layers: {}", layers))
                .remediation("Address findings in each affected layer to reduce the compound attack surface. Prioritize layers with CRITICAL/HIGH findings.")
                .references([
                    "https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro",
                ])
                .owasp_asi("ASI10")
                .maestro(MaestroLayer::L6)
                .nist(NistAttackType::Evasion)
                .build(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(sev: Severity, layer: Option<MaestroLayer>, auto: bool) -> AuditFinding {
        AuditFinding {
            id: "SC-TEST-001".into(),
            severity: sev,
            category: "test".into(),
            title: "t".into(),
            description: "d".into(),
            evidence: "e".into(),
            remediation: "r".into(),
            auto_fixable: auto,
            references: vec![],
            owasp_asi: "ASI01".into(),
            maestro_layer: layer,
            nist_category: None,
        }
    }

    #[test]
    fn score_deducts_per_severity_and_saturates() {
        assert_eq!(calculate_score(&[]), 100);
        assert_eq!(
            calculate_score(&[finding(Severity::Critical, None, false)]),
            85
        );
        assert_eq!(
            calculate_score(&[
                finding(Severity::High, None, false),
                finding(Severity::Medium, None, false),
                finding(Severity::Low, None, false),
            ]),
            100 - 8 - 3 - 1
        );
        // Ten criticals = 150 deduction, saturates at 0 (never negative).
        let many: Vec<_> = (0..10)
            .map(|_| finding(Severity::Critical, None, false))
            .collect();
        assert_eq!(calculate_score(&many), 0);
    }

    #[test]
    fn summary_counts_by_severity_and_autofixable() {
        let f = vec![
            finding(Severity::Critical, None, true),
            finding(Severity::High, None, false),
            finding(Severity::High, None, true),
            finding(Severity::Info, None, false),
        ];
        let s = compute_summary(&f);
        assert_eq!(s.critical, 1);
        assert_eq!(s.high, 2);
        assert_eq!(s.info, 1);
        assert_eq!(s.auto_fixable, 2);
    }

    #[test]
    fn cross_layer_fires_at_three_distinct_noninfo_layers() {
        // 2 distinct layers -> no compound finding.
        let two = vec![
            finding(Severity::High, Some(MaestroLayer::L3), false),
            finding(Severity::High, Some(MaestroLayer::L4), false),
        ];
        assert!(cross_layer_risk(&two).is_empty());

        // 3 distinct layers -> one SC-CROSS-001.
        let three = vec![
            finding(Severity::High, Some(MaestroLayer::L4), false),
            finding(Severity::Medium, Some(MaestroLayer::L3), false),
            finding(Severity::High, Some(MaestroLayer::L7), false),
        ];
        let out = cross_layer_risk(&three);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "SC-CROSS-001");
        assert_eq!(out[0].severity, Severity::High);
        // Layers are sorted: "L3, L4, L7".
        assert!(out[0].evidence.contains("L3, L4, L7"));
    }

    #[test]
    fn info_findings_do_not_count_toward_cross_layer() {
        let f = vec![
            finding(Severity::Info, Some(MaestroLayer::L1), false),
            finding(Severity::Info, Some(MaestroLayer::L2), false),
            finding(Severity::Info, Some(MaestroLayer::L3), false),
        ];
        assert!(cross_layer_risk(&f).is_empty());
    }

    #[test]
    fn finding_json_uses_camelcase_wire_names() {
        let f = finding(Severity::Critical, Some(MaestroLayer::L4), true);
        let j = serde_json::to_value(&f).unwrap();
        // Frozen wire contract (PRODUCT.md A.5).
        assert_eq!(j["autoFixable"], true);
        assert_eq!(j["owaspAsi"], "ASI01");
        assert_eq!(j["maestroLayer"], "L4");
        assert_eq!(j["severity"], "CRITICAL");
        // Absent optionals are omitted, not null.
        assert!(j.get("nistCategory").is_none());
    }

    #[test]
    fn nist_category_serializes_lowercase() {
        let mut f = finding(Severity::High, None, false);
        f.nist_category = Some(NistAttackType::Poisoning);
        let j = serde_json::to_value(&f).unwrap();
        assert_eq!(j["nistCategory"], "poisoning");
    }
}

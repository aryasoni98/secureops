//! **Compliance control mapping** (beta blocker: the reports endpoint accepted
//! `?framework=cis|soc2|pci` but ignored it and returned the same raw findings).
//!
//! This module maps a tenant's findings onto named controls of a chosen
//! framework and computes pass/fail coverage. The mapping is keyword-driven
//! over the finding title + cloud (the platform `Finding` is intentionally thin;
//! richer SC-*/control metadata flows in from `secureops-checks` over time), but
//! it is a *real* evaluation: each control reports the findings that implicate
//! it, its status, and the framework now changes the output.
//!
//! Supported frameworks: `cis` (CIS-style cloud baseline), `soc2` (Trust
//! Services Criteria), `pci` (PCI-DSS v4 requirement families). Unknown
//! frameworks fall back to `cis`.

use serde::Serialize;

use crate::models::{Finding, Severity};

/// A single control's evaluation result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlResult {
    pub id: String,
    pub title: String,
    /// `pass` (no implicating open findings) | `fail` | `not_applicable`.
    pub status: String,
    /// Highest severity among implicating findings (`null` when pass).
    pub max_severity: Option<String>,
    /// Finding ids that implicate this control.
    pub findings: Vec<String>,
}

/// The full report returned to clients.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReport {
    pub framework: String,
    pub framework_label: String,
    pub total_controls: usize,
    pub passing: usize,
    pub failing: usize,
    /// Percentage of evaluated (non-N/A) controls that pass, 0-100.
    pub score: u32,
    pub controls: Vec<ControlResult>,
    pub unmapped_findings: usize,
}

struct ControlDef {
    id: &'static str,
    title: &'static str,
    /// Lower-cased keywords; a finding implicates the control if its title or
    /// cloud contains any.
    keywords: &'static [&'static str],
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

fn catalog(framework: &str) -> (&'static str, &'static [ControlDef]) {
    match framework {
        "soc2" => ("SOC 2 Trust Services Criteria", SOC2),
        "pci" => ("PCI-DSS v4.0", PCI),
        _ => ("CIS Cloud Foundations Benchmark", CIS),
    }
}

const CIS: &[ControlDef] = &[
    ControlDef {
        id: "CIS-1.x",
        title: "Identity & Access Management (MFA, root, least privilege)",
        keywords: &["iam", "mfa", "root", "privilege", "access key", "policy"],
    },
    ControlDef {
        id: "CIS-2.x",
        title: "Logging & monitoring (CloudTrail, audit logs)",
        keywords: &["cloudtrail", "logging", "audit", "monitor", "trail"],
    },
    ControlDef {
        id: "CIS-3.x",
        title: "Storage protection (public buckets, encryption at rest)",
        keywords: &[
            "s3",
            "bucket",
            "blob",
            "gcs",
            "storage",
            "encryption",
            "public",
        ],
    },
    ControlDef {
        id: "CIS-4.x",
        title: "Network security (security groups, NSG, open ports)",
        keywords: &[
            "security group",
            "nsg",
            "firewall",
            "0.0.0.0",
            "ssh",
            "rdp",
            "ingress",
            "egress",
            "port",
        ],
    },
    ControlDef {
        id: "CIS-5.x",
        title: "Key & secret management (KMS, rotation)",
        keywords: &["kms", "secret", "key rotation", "credential"],
    },
];

const SOC2: &[ControlDef] = &[
    ControlDef {
        id: "CC6.1",
        title: "Logical access controls restrict access",
        keywords: &[
            "iam",
            "access",
            "mfa",
            "privilege",
            "public",
            "open",
            "ssh",
            "rdp",
        ],
    },
    ControlDef {
        id: "CC6.6",
        title: "Boundary protection / network segmentation",
        keywords: &[
            "security group",
            "nsg",
            "firewall",
            "0.0.0.0",
            "ingress",
            "egress",
            "port",
        ],
    },
    ControlDef {
        id: "CC6.7",
        title: "Encryption of data in transit and at rest",
        keywords: &["encryption", "tls", "unencrypted", "cleartext"],
    },
    ControlDef {
        id: "CC7.2",
        title: "Detection & monitoring of security events",
        keywords: &[
            "cloudtrail",
            "logging",
            "audit",
            "monitor",
            "trail",
            "detection",
        ],
    },
    ControlDef {
        id: "CC7.1",
        title: "Vulnerability & configuration management",
        keywords: &["misconfig", "vulnerab", "cve", "outdated", "exposed"],
    },
];

const PCI: &[ControlDef] = &[
    ControlDef {
        id: "PCI-1",
        title: "Install and maintain network security controls",
        keywords: &[
            "security group",
            "nsg",
            "firewall",
            "0.0.0.0",
            "ingress",
            "port",
        ],
    },
    ControlDef {
        id: "PCI-3",
        title: "Protect stored account data (encryption at rest)",
        keywords: &[
            "encryption",
            "s3",
            "bucket",
            "storage",
            "unencrypted",
            "public",
        ],
    },
    ControlDef {
        id: "PCI-4",
        title: "Protect cardholder data in transit (strong crypto)",
        keywords: &["tls", "in transit", "cleartext", "encryption"],
    },
    ControlDef {
        id: "PCI-7",
        title: "Restrict access by business need to know",
        keywords: &["iam", "access", "privilege", "policy"],
    },
    ControlDef {
        id: "PCI-8",
        title: "Identify users and authenticate access (MFA)",
        keywords: &["mfa", "password", "root", "credential", "authentication"],
    },
    ControlDef {
        id: "PCI-10",
        title: "Log and monitor all access",
        keywords: &["cloudtrail", "logging", "audit", "monitor", "trail"],
    },
];

/// Evaluate a tenant's findings against a framework's controls.
pub fn evaluate(framework: &str, findings: &[Finding]) -> ComplianceReport {
    let fw = match framework {
        "soc2" | "pci" | "cis" => framework,
        _ => "cis",
    };
    let (label, defs) = catalog(fw);

    let mut controls = Vec::with_capacity(defs.len());
    let mut passing = 0usize;
    let mut failing = 0usize;
    let mut mapped_ids = std::collections::HashSet::new();

    for def in defs {
        let mut hits = Vec::new();
        let mut max_sev: Option<Severity> = None;
        for f in findings {
            // Only open/confirmed/escalated findings count against a control;
            // dismissed ones are explicitly accepted risk.
            if matches!(f.status.as_str(), "dismissed") {
                continue;
            }
            let hay = format!(
                "{} {}",
                f.title.to_lowercase(),
                f.cloud.clone().unwrap_or_default().to_lowercase()
            );
            if def.keywords.iter().any(|k| hay.contains(k)) {
                hits.push(f.id.to_string());
                mapped_ids.insert(f.id);
                max_sev = Some(match max_sev {
                    Some(m) if severity_rank(m) >= severity_rank(f.severity) => m,
                    _ => f.severity,
                });
            }
        }
        let status = if hits.is_empty() { "pass" } else { "fail" };
        if hits.is_empty() {
            passing += 1;
        } else {
            failing += 1;
        }
        controls.push(ControlResult {
            id: def.id.to_string(),
            title: def.title.to_string(),
            status: status.to_string(),
            max_severity: max_sev.map(|s| severity_str(s).to_string()),
            findings: hits,
        });
    }

    let total = controls.len();
    let score = if total == 0 {
        100
    } else {
        ((passing as f64 / total as f64) * 100.0).round() as u32
    };
    let unmapped = findings
        .iter()
        .filter(|f| f.status != "dismissed" && !mapped_ids.contains(&f.id))
        .count();

    ComplianceReport {
        framework: fw.to_string(),
        framework_label: label.to_string(),
        total_controls: total,
        passing,
        failing,
        score,
        controls,
        unmapped_findings: unmapped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn f(title: &str, cloud: &str, sev: Severity, status: &str) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            tenant_id: "t".into(),
            scan_id: None,
            title: title.into(),
            severity: sev,
            status: status.into(),
            cloud: Some(cloud.into()),
            blast_radius: 0,
        }
    }

    #[test]
    fn framework_changes_control_set() {
        let cis = evaluate("cis", &[]);
        let soc2 = evaluate("soc2", &[]);
        let pci = evaluate("pci", &[]);
        assert_eq!(cis.framework, "cis");
        assert_eq!(soc2.framework, "soc2");
        assert_eq!(pci.framework, "pci");
        // Each catalog is distinct.
        assert_ne!(cis.total_controls, 0);
        assert_ne!(soc2.controls[0].id, cis.controls[0].id);
    }

    #[test]
    fn open_public_bucket_fails_storage_control() {
        let findings = vec![f(
            "S3 bucket allUsers public read",
            "aws",
            Severity::High,
            "open",
        )];
        let r = evaluate("cis", &findings);
        let storage = r.controls.iter().find(|c| c.id == "CIS-3.x").unwrap();
        assert_eq!(storage.status, "fail");
        assert_eq!(storage.max_severity.as_deref(), Some("high"));
        assert!(r.failing >= 1);
        assert!(r.score < 100);
    }

    #[test]
    fn dismissed_findings_do_not_fail_controls() {
        let findings = vec![f("S3 bucket public", "aws", Severity::High, "dismissed")];
        let r = evaluate("cis", &findings);
        assert_eq!(r.failing, 0);
        assert_eq!(r.score, 100);
    }

    #[test]
    fn unknown_framework_falls_back_to_cis() {
        assert_eq!(evaluate("hipaa", &[]).framework, "cis");
    }
}

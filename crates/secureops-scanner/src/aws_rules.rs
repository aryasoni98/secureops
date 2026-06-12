//! Pure AWS audit rules - no SDK types, no network, no feature gate.
//!
//! The gated [`crate::aws::AwsCollector`] fetches cloud state into the plain
//! observation structs below; the `evaluate_*` functions turn observations
//! into [`CollectorFinding`]s. Keeping rules SDK-free means they compile and
//! test on every platform/CI leg, while only the fetch layer needs the `aws`
//! feature (and credentials).

use secureops_api::models::Severity;

use crate::CollectorFinding;

/// What the collector observed about one S3 bucket.
#[derive(Debug, Clone)]
pub struct S3BucketObservation {
    pub name: String,
    /// `Some(true)` when all four public-access-block flags are enabled,
    /// `Some(false)` when a config exists but is partial, `None` when the
    /// bucket has no public-access-block configuration at all.
    pub public_access_block_all: Option<bool>,
    /// Default (server-side) encryption configured.
    pub encrypted: bool,
}

/// World-open ingress entries observed on one security group.
#[derive(Debug, Clone)]
pub struct SecurityGroupObservation {
    pub id: String,
    pub name: String,
    /// `(from_port, to_port, cidr)` ingress rules whose source is
    /// `0.0.0.0/0` or `::/0`. Port `-1..-1` means "all traffic".
    pub world_open: Vec<(i32, i32, String)>,
}

/// Account-wide observations (CloudTrail, root credentials).
#[derive(Debug, Clone, Default)]
pub struct AccountObservation {
    /// Number of CloudTrail trails visible to the caller.
    pub cloudtrail_trail_count: usize,
    /// Root-account MFA state from `GetAccountSummary`; `None` when the
    /// caller lacked `iam:GetAccountSummary`.
    pub root_mfa_enabled: Option<bool>,
}

fn finding(title: String, severity: Severity, blast: i64) -> CollectorFinding {
    CollectorFinding {
        title,
        severity,
        cloud: Some("aws".into()),
        blast_radius: blast,
    }
}

/// S3: missing full public-access block, missing default encryption.
pub fn evaluate_s3(buckets: &[S3BucketObservation]) -> Vec<CollectorFinding> {
    let mut out = Vec::new();
    for b in buckets {
        if b.public_access_block_all != Some(true) {
            let detail = match b.public_access_block_all {
                None => "has no public-access-block configuration",
                Some(_) => "has an incomplete public-access-block configuration",
            };
            out.push(finding(
                format!("S3 bucket '{}' {detail}", b.name),
                Severity::High,
                70,
            ));
        }
        if !b.encrypted {
            out.push(finding(
                format!("S3 bucket '{}' has no default encryption", b.name),
                Severity::Medium,
                40,
            ));
        }
    }
    out
}

/// Whether a `(from, to)` port range covers `port`. AWS uses `-1` (or an
/// unset range on `-1` protocol rules) to mean "all traffic".
fn range_covers(from: i32, to: i32, port: i32) -> bool {
    (from == -1 && to == -1) || (from <= port && port <= to)
}

/// EC2: ingress open to the world. SSH/RDP exposure is critical; anything
/// else world-open is high.
pub fn evaluate_security_groups(groups: &[SecurityGroupObservation]) -> Vec<CollectorFinding> {
    let mut out = Vec::new();
    for g in groups {
        for (from, to, cidr) in &g.world_open {
            let (label, severity, blast) = if range_covers(*from, *to, 22) {
                ("SSH (22)", Severity::Critical, 90)
            } else if range_covers(*from, *to, 3389) {
                ("RDP (3389)", Severity::Critical, 90)
            } else {
                ("ingress", Severity::High, 60)
            };
            let ports = if *from == -1 {
                "all ports".to_string()
            } else if from == to {
                format!("port {from}")
            } else {
                format!("ports {from}-{to}")
            };
            out.push(finding(
                format!(
                    "Security group '{}' ({}) opens {label} to {cidr} ({ports})",
                    g.name, g.id
                ),
                severity,
                blast,
            ));
        }
    }
    out
}

/// Account level: CloudTrail coverage and root MFA.
pub fn evaluate_account(acct: &AccountObservation) -> Vec<CollectorFinding> {
    let mut out = Vec::new();
    if acct.cloudtrail_trail_count == 0 {
        out.push(finding(
            "CloudTrail is not enabled in this account/region".into(),
            Severity::High,
            80,
        ));
    }
    if acct.root_mfa_enabled == Some(false) {
        out.push(finding(
            "Root account has no MFA device".into(),
            Severity::Critical,
            95,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(name: &str, pab: Option<bool>, encrypted: bool) -> S3BucketObservation {
        S3BucketObservation {
            name: name.into(),
            public_access_block_all: pab,
            encrypted,
        }
    }

    #[test]
    fn s3_compliant_bucket_yields_no_findings() {
        let out = evaluate_s3(&[bucket("good", Some(true), true)]);
        assert!(out.is_empty());
    }

    #[test]
    fn s3_missing_pab_and_encryption_yield_two_findings() {
        let out = evaluate_s3(&[bucket("bad", None, false)]);
        assert_eq!(out.len(), 2);
        assert!(out[0].title.contains("no public-access-block"));
        assert_eq!(out[0].severity, Severity::High);
        assert!(out[1].title.contains("no default encryption"));
        assert_eq!(out[1].severity, Severity::Medium);
    }

    #[test]
    fn s3_partial_pab_flagged_distinctly() {
        let out = evaluate_s3(&[bucket("partial", Some(false), true)]);
        assert_eq!(out.len(), 1);
        assert!(out[0].title.contains("incomplete public-access-block"));
    }

    #[test]
    fn sg_world_ssh_is_critical() {
        let g = SecurityGroupObservation {
            id: "sg-1".into(),
            name: "web".into(),
            world_open: vec![(22, 22, "0.0.0.0/0".into())],
        };
        let out = evaluate_security_groups(&[g]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Critical);
        assert!(out[0].title.contains("SSH (22)"));
    }

    #[test]
    fn sg_all_traffic_range_covers_ssh() {
        let g = SecurityGroupObservation {
            id: "sg-2".into(),
            name: "open".into(),
            world_open: vec![(-1, -1, "::/0".into())],
        };
        let out = evaluate_security_groups(&[g]);
        assert_eq!(out[0].severity, Severity::Critical);
        assert!(out[0].title.contains("all ports"));
    }

    #[test]
    fn sg_world_http_is_high_not_critical() {
        let g = SecurityGroupObservation {
            id: "sg-3".into(),
            name: "lb".into(),
            world_open: vec![(80, 80, "0.0.0.0/0".into())],
        };
        let out = evaluate_security_groups(&[g]);
        assert_eq!(out[0].severity, Severity::High);
    }

    #[test]
    fn sg_range_spanning_rdp_is_critical() {
        let g = SecurityGroupObservation {
            id: "sg-4".into(),
            name: "wide".into(),
            world_open: vec![(3000, 4000, "0.0.0.0/0".into())],
        };
        let out = evaluate_security_groups(&[g]);
        assert_eq!(out[0].severity, Severity::Critical);
        assert!(out[0].title.contains("RDP"));
    }

    #[test]
    fn account_no_trail_no_root_mfa() {
        let out = evaluate_account(&AccountObservation {
            cloudtrail_trail_count: 0,
            root_mfa_enabled: Some(false),
        });
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|f| f.title.contains("CloudTrail")));
        assert!(out
            .iter()
            .any(|f| f.title.contains("Root account") && f.severity == Severity::Critical));
    }

    #[test]
    fn account_unknown_root_mfa_not_flagged() {
        let out = evaluate_account(&AccountObservation {
            cloudtrail_trail_count: 1,
            root_mfa_enabled: None,
        });
        assert!(out.is_empty());
    }
}

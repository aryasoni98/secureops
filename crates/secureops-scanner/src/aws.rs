//! Live **AWS read-only collector** (gated `aws` feature).
//!
//! Fetches account state via the AWS SDK and evaluates it with the pure rules
//! in [`crate::aws_rules`]. Every API call is read-only; the minimal IAM
//! policy for the scanner role is:
//!
//! ```text
//! s3:ListAllMyBuckets, s3:GetBucketPublicAccessBlock,
//! s3:GetEncryptionConfiguration, ec2:DescribeSecurityGroups,
//! cloudtrail:DescribeTrails, iam:GetAccountSummary
//! ```
//!
//! Fetch failures are *fail-honest*: a check that cannot be assessed (e.g.
//! access denied on one bucket) is skipped with a warning rather than
//! reported as a violation - findings are only emitted on positive evidence.

use async_trait::async_trait;
use aws_sdk_s3::error::ProvideErrorMetadata;

use crate::aws_rules::{
    evaluate_account, evaluate_s3, evaluate_security_groups, AccountObservation,
    S3BucketObservation, SecurityGroupObservation,
};
use crate::{Collector, CollectorFinding, ScanJob};

/// Hard cap on buckets assessed per scan (keeps API fan-out bounded).
const MAX_BUCKETS: usize = 200;
/// Hard cap on security groups assessed per scan.
const MAX_SECURITY_GROUPS: usize = 1000;

/// Read-only AWS posture collector.
pub struct AwsCollector {
    s3: aws_sdk_s3::Client,
    ec2: aws_sdk_ec2::Client,
    iam: aws_sdk_iam::Client,
    cloudtrail: aws_sdk_cloudtrail::Client,
}

impl AwsCollector {
    /// Build clients from the ambient AWS config (env / profile / IMDS).
    pub async fn from_env() -> Self {
        let cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Self {
            s3: aws_sdk_s3::Client::new(&cfg),
            ec2: aws_sdk_ec2::Client::new(&cfg),
            iam: aws_sdk_iam::Client::new(&cfg),
            cloudtrail: aws_sdk_cloudtrail::Client::new(&cfg),
        }
    }

    async fn observe_s3(&self) -> Vec<S3BucketObservation> {
        let buckets = match self.s3.list_buckets().send().await {
            Ok(out) => out.buckets.unwrap_or_default(),
            Err(e) => {
                tracing::warn!(error=%e, "aws: ListBuckets failed - skipping S3 checks");
                return Vec::new();
            }
        };
        if buckets.len() > MAX_BUCKETS {
            tracing::warn!(
                total = buckets.len(),
                cap = MAX_BUCKETS,
                "aws: bucket count exceeds cap - assessing first {MAX_BUCKETS} only"
            );
        }

        let mut out = Vec::new();
        for b in buckets.into_iter().take(MAX_BUCKETS) {
            let Some(name) = b.name else { continue };

            let pab = match self.s3.get_public_access_block().bucket(&name).send().await {
                Ok(r) => {
                    let all = r.public_access_block_configuration.is_some_and(|c| {
                        c.block_public_acls.unwrap_or(false)
                            && c.ignore_public_acls.unwrap_or(false)
                            && c.block_public_policy.unwrap_or(false)
                            && c.restrict_public_buckets.unwrap_or(false)
                    });
                    Some(all)
                }
                Err(e) if e.code() == Some("NoSuchPublicAccessBlockConfiguration") => None,
                Err(e) => {
                    tracing::warn!(bucket=%name, error=%e, "aws: GetPublicAccessBlock failed - skipping bucket");
                    continue;
                }
            };

            let encrypted = match self.s3.get_bucket_encryption().bucket(&name).send().await {
                Ok(_) => true,
                Err(e) if e.code() == Some("ServerSideEncryptionConfigurationNotFoundError") => {
                    false
                }
                Err(e) => {
                    tracing::warn!(bucket=%name, error=%e, "aws: GetBucketEncryption failed - skipping bucket");
                    continue;
                }
            };

            out.push(S3BucketObservation {
                name,
                public_access_block_all: pab,
                encrypted,
            });
        }
        out
    }

    async fn observe_security_groups(&self) -> Vec<SecurityGroupObservation> {
        let mut pages = self.ec2.describe_security_groups().into_paginator().send();
        let mut out = Vec::new();
        loop {
            let page = match pages.try_next().await {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(error=%e, "aws: DescribeSecurityGroups failed - skipping EC2 checks");
                    break;
                }
            };
            for sg in page.security_groups.unwrap_or_default() {
                let mut world_open = Vec::new();
                for perm in sg.ip_permissions.unwrap_or_default() {
                    let from = perm.from_port.unwrap_or(-1);
                    let to = perm.to_port.unwrap_or(-1);
                    for r in perm.ip_ranges.unwrap_or_default() {
                        if r.cidr_ip.as_deref() == Some("0.0.0.0/0") {
                            world_open.push((from, to, "0.0.0.0/0".to_string()));
                        }
                    }
                    for r in perm.ipv6_ranges.unwrap_or_default() {
                        if r.cidr_ipv6.as_deref() == Some("::/0") {
                            world_open.push((from, to, "::/0".to_string()));
                        }
                    }
                }
                if !world_open.is_empty() {
                    out.push(SecurityGroupObservation {
                        id: sg.group_id.unwrap_or_default(),
                        name: sg.group_name.unwrap_or_default(),
                        world_open,
                    });
                }
                if out.len() >= MAX_SECURITY_GROUPS {
                    tracing::warn!(
                        cap = MAX_SECURITY_GROUPS,
                        "aws: security-group cap reached - truncating assessment"
                    );
                    return out;
                }
            }
        }
        out
    }

    async fn observe_account(&self) -> AccountObservation {
        let cloudtrail_trail_count = match self.cloudtrail.describe_trails().send().await {
            Ok(r) => r.trail_list.unwrap_or_default().len(),
            Err(e) => {
                tracing::warn!(error=%e, "aws: DescribeTrails failed - skipping CloudTrail check");
                // `1` suppresses the "no trail" finding: absence was not proven.
                1
            }
        };
        let root_mfa_enabled = match self.iam.get_account_summary().send().await {
            Ok(r) => r
                .summary_map
                .as_ref()
                .and_then(|m| m.get(&aws_sdk_iam::types::SummaryKeyType::AccountMfaEnabled))
                .map(|v| *v == 1),
            Err(e) => {
                tracing::warn!(error=%e, "aws: GetAccountSummary failed - skipping root-MFA check");
                None
            }
        };
        AccountObservation {
            cloudtrail_trail_count,
            root_mfa_enabled,
        }
    }
}

#[async_trait]
impl Collector for AwsCollector {
    async fn collect(&self, job: &ScanJob) -> anyhow::Result<Vec<CollectorFinding>> {
        if job.scope != "aws" && job.scope != "all" {
            tracing::info!(scope=%job.scope, "aws collector: scope not aws/all - nothing to do");
            return Ok(Vec::new());
        }
        let buckets = self.observe_s3().await;
        let groups = self.observe_security_groups().await;
        let account = self.observe_account().await;

        let mut findings = evaluate_s3(&buckets);
        findings.extend(evaluate_security_groups(&groups));
        findings.extend(evaluate_account(&account));
        tracing::info!(
            buckets = buckets.len(),
            security_groups = groups.len(),
            findings = findings.len(),
            "aws collector: assessment complete"
        );
        Ok(findings)
    }
}

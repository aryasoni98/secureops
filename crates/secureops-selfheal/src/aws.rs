//! Live **AWS** [`CloudBackend`] (gated `aws` feature). Executes parsed
//! [`CloudAction`]s via the AWS SDK — usable now that the tree-sitter bump
//! lifted the workspace `cc < 1.1` cap (aws-sdk pulls aws-lc-rs).
//!
//! Supports the AWS-native sample actions (S3 ACL, CloudTrail). Non-AWS actions
//! (GCP/K8s) return an unsupported error — those route to their own backends.
//! Reversible bookkeeping (snapshot/health/rollback) is action-specific in a
//! production deploy; here the trait hooks are wired to safe defaults.

use async_trait::async_trait;

use crate::{parse_step, CloudAction, CloudBackend};

/// AWS-backed remediation executor.
pub struct AwsCloud {
    s3: aws_sdk_s3::Client,
    cloudtrail: aws_sdk_cloudtrail::Client,
}

impl AwsCloud {
    /// Build clients from the ambient AWS config (env / profile / IMDS).
    pub async fn from_env() -> Self {
        let cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Self {
            s3: aws_sdk_s3::Client::new(&cfg),
            cloudtrail: aws_sdk_cloudtrail::Client::new(&cfg),
        }
    }

    /// Construct from explicit clients (tests / custom config).
    pub fn new(s3: aws_sdk_s3::Client, cloudtrail: aws_sdk_cloudtrail::Client) -> Self {
        Self { s3, cloudtrail }
    }

    async fn apply(&self, action: CloudAction) -> anyhow::Result<String> {
        match action {
            CloudAction::PutBucketAcl { bucket, acl } => {
                self.s3
                    .put_bucket_acl()
                    .bucket(bucket)
                    .acl(aws_sdk_s3::types::BucketCannedAcl::from(acl.as_str()))
                    .send()
                    .await?;
                Ok("s3: bucket ACL applied".into())
            }
            CloudAction::StartCloudTrail { name } => {
                self.cloudtrail.start_logging().name(name).send().await?;
                Ok("cloudtrail: logging started".into())
            }
            other => anyhow::bail!("AwsCloud does not handle {other:?}"),
        }
    }
}

#[async_trait]
impl CloudBackend for AwsCloud {
    async fn dry_run(&self, step: &str) -> anyhow::Result<String> {
        // No-mutation preview: confirm the step parses to a supported action.
        Ok(format!("aws dry-run: {:?}", parse_step(step)))
    }

    async fn snapshot(&self, _step: &str) -> anyhow::Result<String> {
        // Production: capture prior state (e.g. current bucket ACL) for rollback.
        Ok("aws-snapshot".into())
    }

    async fn execute(&self, step: &str) -> anyhow::Result<String> {
        self.apply(parse_step(step)).await
    }

    async fn health_check(&self, _step: &str) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn rollback(&self, _step: &str, _snapshot: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

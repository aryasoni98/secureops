//! The `AuditContext` trait - dependency injection for every environment touch.
//!
//! Port of the `AuditContext` interface in `src/types.ts`. Checks receive
//! `&dyn AuditContext` and never touch the filesystem directly, so they stay
//! unit-testable against an in-memory mock. The real `tokio::fs`-backed impl
//! lives in the `secureops-fs` crate (Ring 0/1); the daemon (Ring 2) supplies
//! its own. Keeping I/O behind this trait is what lets `core` and `checks` stay
//! I/O-free per PRODUCT.md A.4.

use crate::config::{DockerComposeConfig, OpenClawConfig};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// File info for auditing (permissions, content, existence, size).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub permissions: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exists: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size: Option<u64>,
}

/// Channel configuration (Slack/Discord-style routing surface).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChannelConfig {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dm_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub group_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub allowlist: Option<Vec<String>>,
}

/// Skill metadata used by the supply-chain / skill-scan checks.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SkillMetadata {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub github_account_age: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub installed_at: Option<String>,
}

/// Dependency-injected view of the host the agent runs on.
///
/// Sync getters expose already-loaded config/metadata; async methods perform
/// the actual filesystem reads (mocked in tests, `tokio::fs` in production).
#[async_trait]
pub trait AuditContext: Send + Sync {
    fn state_dir(&self) -> &str;
    fn config(&self) -> &OpenClawConfig;
    fn platform(&self) -> &str;
    fn deployment_mode(&self) -> &str;
    fn openclaw_version(&self) -> &str;

    async fn file_info(&self, path: &str) -> FileInfo;
    async fn read_file(&self, path: &str) -> Option<String>;
    async fn list_dir(&self, path: &str) -> Vec<String>;
    async fn file_exists(&self, path: &str) -> bool;
    /// Unix mode bits (e.g. `0o600`), or `None` when unavailable.
    async fn get_file_permissions(&self, path: &str) -> Option<u32>;

    fn channels(&self) -> &[ChannelConfig] {
        &[]
    }
    fn skills(&self) -> &[SkillMetadata] {
        &[]
    }
    fn docker_compose(&self) -> Option<&DockerComposeConfig> {
        None
    }
    fn session_logs(&self) -> &[String] {
        &[]
    }
    fn connection_logs(&self) -> &[String] {
        &[]
    }
}

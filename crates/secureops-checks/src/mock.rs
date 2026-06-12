//! In-memory [`AuditContext`] for unit-testing checks without touching disk.
//!
//! Not part of the production path - exposed (doc-hidden) so each category
//! module's `#[cfg(test)]` block can build a context with exactly the files,
//! permissions, config and metadata that finding needs.

#![doc(hidden)]

use async_trait::async_trait;
use secureops_core::{
    AuditContext, ChannelConfig, DockerComposeConfig, FileInfo, OpenClawConfig, SkillMetadata,
};
use std::collections::HashMap;

/// Configurable mock implementing [`AuditContext`].
#[derive(Default)]
pub struct MockAuditContext {
    pub state_dir: String,
    pub config: OpenClawConfig,
    pub platform: String,
    pub deployment_mode: String,
    pub openclaw_version: String,
    /// path -> file content
    pub files: HashMap<String, String>,
    /// path -> unix mode bits (e.g. 0o600)
    pub perms: HashMap<String, u32>,
    /// dir path -> entry names
    pub dirs: HashMap<String, Vec<String>>,
    pub channels: Vec<ChannelConfig>,
    pub skills: Vec<SkillMetadata>,
    pub docker: Option<DockerComposeConfig>,
    pub session_logs: Vec<String>,
    pub connection_logs: Vec<String>,
}

impl MockAuditContext {
    /// Sensible defaults matching `createAuditContext` (darwin/native/unknown).
    pub fn new() -> Self {
        Self {
            state_dir: "/state".to_string(),
            platform: "darwin-arm64".to_string(),
            deployment_mode: "native".to_string(),
            openclaw_version: "unknown".to_string(),
            ..Default::default()
        }
    }

    pub fn with_config(mut self, config: OpenClawConfig) -> Self {
        self.config = config;
        self
    }
    pub fn with_platform(mut self, platform: &str) -> Self {
        self.platform = platform.to_string();
        self
    }
    pub fn with_file(mut self, path: &str, content: &str) -> Self {
        self.files.insert(path.to_string(), content.to_string());
        self
    }
    pub fn with_perms(mut self, path: &str, mode: u32) -> Self {
        self.perms.insert(path.to_string(), mode);
        self
    }
    pub fn with_dir(mut self, path: &str, entries: &[&str]) -> Self {
        self.dirs.insert(
            path.to_string(),
            entries.iter().map(|s| s.to_string()).collect(),
        );
        self
    }
    pub fn with_skills(mut self, skills: Vec<SkillMetadata>) -> Self {
        self.skills = skills;
        self
    }
    pub fn with_channels(mut self, channels: Vec<ChannelConfig>) -> Self {
        self.channels = channels;
        self
    }
    pub fn with_docker(mut self, docker: DockerComposeConfig) -> Self {
        self.docker = Some(docker);
        self
    }
    pub fn with_connection_logs(mut self, logs: Vec<String>) -> Self {
        self.connection_logs = logs;
        self
    }
    pub fn with_session_logs(mut self, logs: Vec<String>) -> Self {
        self.session_logs = logs;
        self
    }
}

#[async_trait]
impl AuditContext for MockAuditContext {
    fn state_dir(&self) -> &str {
        &self.state_dir
    }
    fn config(&self) -> &OpenClawConfig {
        &self.config
    }
    fn platform(&self) -> &str {
        &self.platform
    }
    fn deployment_mode(&self) -> &str {
        &self.deployment_mode
    }
    fn openclaw_version(&self) -> &str {
        &self.openclaw_version
    }

    async fn file_info(&self, path: &str) -> FileInfo {
        if let Some(content) = self.files.get(path) {
            FileInfo {
                path: path.to_string(),
                permissions: self.perms.get(path).copied(),
                content: None,
                exists: Some(true),
                size: Some(content.len() as u64),
            }
        } else {
            FileInfo {
                path: path.to_string(),
                exists: Some(false),
                ..Default::default()
            }
        }
    }

    async fn read_file(&self, path: &str) -> Option<String> {
        self.files.get(path).cloned()
    }

    async fn list_dir(&self, path: &str) -> Vec<String> {
        self.dirs.get(path).cloned().unwrap_or_default()
    }

    async fn file_exists(&self, path: &str) -> bool {
        self.files.contains_key(path) || self.dirs.contains_key(path)
    }

    async fn get_file_permissions(&self, path: &str) -> Option<u32> {
        self.perms.get(path).copied()
    }

    fn channels(&self) -> &[ChannelConfig] {
        &self.channels
    }
    fn skills(&self) -> &[SkillMetadata] {
        &self.skills
    }
    fn docker_compose(&self) -> Option<&DockerComposeConfig> {
        self.docker.as_ref()
    }
    fn session_logs(&self) -> &[String] {
        &self.session_logs
    }
    fn connection_logs(&self) -> &[String] {
        &self.connection_logs
    }
}

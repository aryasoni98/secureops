//! The OpenClaw configuration tree that SecureOps audits.
//!
//! Faithful port of the config interfaces in `src/types.ts`. Every field is
//! optional (matching the TS `?` optionals) and skipped from JSON when `None`,
//! so a round-trip through this model never injects keys the TS tool wouldn't.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Gateway configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct GatewayConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Legacy flat auth token (pre-2026 configs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<GatewayAuth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mdns: Option<MdnsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_ui: Option<ControlUiConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_proxies: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct GatewayAuth {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct MdnsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct ControlUiConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dangerously_disable_device_auth: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_insecure_auth: Option<bool>,
}

/// Execution configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct ExecConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approvals: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_approve: Option<Vec<String>>,
}

/// Sandbox configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct SandboxConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_access: Option<String>,
}

/// Tools configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct ToolsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<ToolsExec>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct ToolsExec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// Session configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct SessionConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dm_scope: Option<String>,
}

/// Logging configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct LoggingConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redact_sensitive: Option<String>,
}

/// Failure mode for graceful degradation (directive G4).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    BlockAll,
    SafeMode,
    ReadOnly,
}

/// Risk profile names for per-workload security (directive G8).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskProfile {
    Strict,
    Standard,
    Permissive,
}

/// SecureOps-specific configuration block.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct SecureOpsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitors: Option<MonitorsToggle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<CostLimits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemorySettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills: Option<SkillsSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_mode: Option<FailureMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_profile: Option<RiskProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_profiles: Option<HashMap<String, RiskProfileDef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavioral: Option<BehavioralSettings>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct MonitorsToggle {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct CostLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hourly_limit_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily_limit_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_limit_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_breaker_enabled: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct MemorySettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_checks: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_injection_scan: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_levels: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct SkillsSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_unaudited: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_on_install: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ioc_check_enabled: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct NetworkSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_allowlist_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_allowlist: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct RiskProfileDef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_mode: Option<FailureMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cost_per_session: Option<f64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct BehavioralSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deviation_threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_minutes: Option<u64>,
}

/// Full OpenClaw configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct OpenClawConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secureops: Option<SecureOpsConfig>,
}

impl OpenClawConfig {
    /// Active failure mode (directive G4), defaulting to `block_all`
    /// (port of `getFailureMode`).
    pub fn failure_mode(&self) -> FailureMode {
        self.secureops
            .as_ref()
            .and_then(|s| s.failure_mode)
            .unwrap_or(FailureMode::BlockAll)
    }

    /// Active risk profile (directive G8), defaulting to `standard`
    /// (port of `getRiskProfile`).
    pub fn risk_profile(&self) -> RiskProfile {
        self.secureops
            .as_ref()
            .and_then(|s| s.risk_profile)
            .unwrap_or(RiskProfile::Standard)
    }
}

// ---- Docker compose model (audited by the supply-chain / docker checks) ----

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case", default)]
pub struct DockerServiceConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_drop: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_opt: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networks: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deploy: Option<DockerDeploy>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case", default)]
pub struct DockerDeploy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<DockerResources>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case", default)]
pub struct DockerResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<DockerLimits>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case", default)]
pub struct DockerLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpus: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case", default)]
pub struct DockerNetwork {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case", default)]
pub struct DockerComposeConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<HashMap<String, DockerServiceConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networks: Option<HashMap<String, DockerNetwork>>,
}

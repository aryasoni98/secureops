//! IOC database + integrity-baseline value types.
//!
//! Port of `IOCDatabase`, `HashBaseline` and `BaselineComparison` from
//! `src/types.ts`. The loading/verification logic (signed feed, monotonicity,
//! graceful fallback - PRODUCT.md B.8) lives in `secureops-intel`; these are
//! just the on-disk shapes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Bundled / fetched indicator database (`ioc/indicators.json`).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IocDatabase {
    pub version: String,
    pub last_updated: String,
    pub c2_ips: Vec<String>,
    pub malicious_domains: Vec<String>,
    /// hash -> human-readable label.
    pub malicious_skill_hashes: HashMap<String, String>,
    pub typosquat_patterns: Vec<String>,
    pub dangerous_prerequisite_patterns: Vec<String>,
    pub infostealer_artifacts: InfostealerArtifacts,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct InfostealerArtifacts {
    pub macos: Vec<String>,
    pub linux: Vec<String>,
}

/// SHA-256 baseline of tracked files for drift/integrity checking.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HashBaseline {
    pub timestamp: String,
    /// path -> hex SHA-256.
    pub files: HashMap<String, String>,
}

/// Result of comparing a current scan against a stored baseline.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BaselineComparison {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub removed: Vec<String>,
}

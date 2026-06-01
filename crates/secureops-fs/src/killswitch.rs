//! Kill switch (directive G2 — CSA / CoSAI) — port of the `isKillSwitchActive` /
//! `activateKillSwitch` / `deactivateKillSwitch` functions in `src/index.ts`.
//!
//! The kill switch is a single file at `<stateDir>/.secureops/killswitch`. Its
//! presence blocks all tool calls; the daemon checks it first on startup (B.4
//! step 1) and refuses to bring up enforcement when present. The file contract
//! is shared with the TS tool (PRODUCT.md A.5), so the JSON shape is frozen.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Contents of the killswitch file.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KillSwitchRecord {
    pub activated: String,
    pub reason: String,
    pub activated_by: String,
}

/// Path to the killswitch file: `<stateDir>/.secureops/killswitch`.
pub fn kill_switch_path(state_dir: &str) -> PathBuf {
    PathBuf::from(state_dir)
        .join(".secureops")
        .join("killswitch")
}

/// Is the kill switch active? (file exists). Port of `isKillSwitchActive`.
pub async fn is_kill_switch_active(state_dir: &str) -> bool {
    tokio::fs::metadata(kill_switch_path(state_dir))
        .await
        .is_ok()
}

/// Activate the kill switch — writes the record (blocks all tool calls). Port of
/// `activateKillSwitch`. `now` is an injected RFC3339 timestamp; `reason`
/// defaults to `"Manual activation"`.
pub async fn activate_kill_switch(
    state_dir: &str,
    reason: Option<&str>,
    now: &str,
) -> std::io::Result<()> {
    let sc_dir = PathBuf::from(state_dir).join(".secureops");
    tokio::fs::create_dir_all(&sc_dir).await?;
    let record = KillSwitchRecord {
        activated: now.to_string(),
        reason: reason.unwrap_or("Manual activation").to_string(),
        activated_by: "secureops-cli".to_string(),
    };
    let content = serde_json::to_string_pretty(&record).map_err(std::io::Error::other)?;
    tokio::fs::write(sc_dir.join("killswitch"), content).await
}

/// Deactivate the kill switch — removes the file (resumes normal operation).
/// Port of `deactivateKillSwitch` (already-inactive is not an error).
pub async fn deactivate_kill_switch(state_dir: &str) -> std::io::Result<()> {
    match tokio::fs::remove_file(kill_switch_path(state_dir)).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn activate_then_detect_then_deactivate() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_str().unwrap();

        assert!(!is_kill_switch_active(sd).await);

        activate_kill_switch(sd, Some("breach"), "2026-05-29T00:00:00Z")
            .await
            .unwrap();
        assert!(is_kill_switch_active(sd).await);

        // File shape matches the TS contract (camelCase, activatedBy).
        let raw = tokio::fs::read_to_string(kill_switch_path(sd))
            .await
            .unwrap();
        let rec: KillSwitchRecord = serde_json::from_str(&raw).unwrap();
        assert_eq!(rec.reason, "breach");
        assert_eq!(rec.activated_by, "secureops-cli");
        assert!(raw.contains("\"activatedBy\""));

        deactivate_kill_switch(sd).await.unwrap();
        assert!(!is_kill_switch_active(sd).await);
        // Deactivating again is not an error.
        deactivate_kill_switch(sd).await.unwrap();
    }

    #[tokio::test]
    async fn default_reason_when_none() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_str().unwrap();
        activate_kill_switch(sd, None, "2026-05-29T00:00:00Z")
            .await
            .unwrap();
        let raw = tokio::fs::read_to_string(kill_switch_path(sd))
            .await
            .unwrap();
        let rec: KillSwitchRecord = serde_json::from_str(&raw).unwrap();
        assert_eq!(rec.reason, "Manual activation");
    }
}

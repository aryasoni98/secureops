//! Credential monitor — port of `monitors/credential-monitor.ts`.
//!
//! The TS module watches the credentials dir + `.env` with chokidar and alerts
//! on new/changed/deleted files and over-permissive modes. The verifiable core
//! is the permission check (`(mode & 0o077) != 0`); the watch loop is the
//! runtime shell (polling here instead of chokidar).

use crate::{now_iso, AlertBus, CancellationToken, Monitor};
use async_trait::async_trait;
use secureops_core::{basename, is_group_or_other_accessible, MonitorAlert, Severity};
use std::collections::HashMap;
use std::path::Path;

#[cfg(unix)]
async fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::metadata(path)
        .await
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
async fn file_mode(_path: &Path) -> Option<u32> {
    None
}

/// Map of current credential files -> permission bits: the `credentials/`
/// directory entries plus `.env` (port of the chokidar watch set).
pub async fn scan_credentials(state_dir: &str) -> HashMap<String, u32> {
    let mut out = HashMap::new();
    let creds = Path::new(state_dir).join("credentials");
    if let Ok(mut rd) = tokio::fs::read_dir(&creds).await {
        while let Ok(Some(e)) = rd.next_entry().await {
            let p = e.path();
            let mode = file_mode(&p).await.unwrap_or(0);
            out.insert(p.to_string_lossy().to_string(), mode);
        }
    }
    let env = Path::new(state_dir).join(".env");
    if tokio::fs::metadata(&env).await.is_ok() {
        let mode = file_mode(&env).await.unwrap_or(0);
        out.insert(env.to_string_lossy().to_string(), mode);
    }
    out
}

/// Alert if a credential file's mode is group/other-accessible
/// (`(mode & 0o077) != 0`) — port of the chokidar `change` handler check.
/// `mode` is the permission bits (already masked to `0o777`).
pub fn permission_alert(path: &str, mode: u32, now_iso: &str) -> Option<MonitorAlert> {
    if is_group_or_other_accessible(mode) {
        Some(MonitorAlert {
            timestamp: now_iso.to_string(),
            severity: Severity::Critical,
            monitor: "credential-monitor".to_string(),
            message: format!(
                "Credential file permissions are too open: {} ({:o})",
                basename(path),
                mode
            ),
            details: Some(format!("Path: {}, Permissions: {:o}", path, mode)),
        })
    } else {
        None
    }
}

/// Alert for a newly-appeared credential file (port of the `add` handler).
pub fn new_file_alert(path: &str, now_iso: &str) -> MonitorAlert {
    MonitorAlert {
        timestamp: now_iso.to_string(),
        severity: Severity::High,
        monitor: "credential-monitor".to_string(),
        message: format!("New credential file detected: {}", basename(path)),
        details: Some(format!("Path: {}", path)),
    }
}

/// Alert for a deleted credential file (port of the `unlink` handler).
pub fn deleted_file_alert(path: &str, now_iso: &str) -> MonitorAlert {
    MonitorAlert {
        timestamp: now_iso.to_string(),
        severity: Severity::Medium,
        monitor: "credential-monitor".to_string(),
        message: format!("Credential file deleted: {}", basename(path)),
        details: Some(format!("Path: {}", path)),
    }
}

/// Credential-access monitor (PRODUCT.md B.6).
pub struct CredentialMonitor {
    state_dir: String,
}

impl CredentialMonitor {
    pub fn new() -> Self {
        Self {
            state_dir: String::new(),
        }
    }

    pub fn with_state_dir(mut self, state_dir: impl Into<String>) -> Self {
        self.state_dir = state_dir.into();
        self
    }
}

impl Default for CredentialMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Monitor for CredentialMonitor {
    fn name(&self) -> &'static str {
        "credential"
    }

    async fn run(&self, bus: AlertBus, mut cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        // First tick seeds the known set without alerting (mirrors chokidar
        // `ignoreInitial: true`); subsequent ticks diff against it.
        let mut prev: Option<HashMap<String, u32>> = None;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    let now = now_iso();
                    let cur = scan_credentials(&self.state_dir).await;
                    if let Some(prev_map) = &prev {
                        for (path, mode) in &cur {
                            match prev_map.get(path) {
                                None => {
                                    let _ = bus.publish(new_file_alert(path, &now));
                                    if let Some(a) = permission_alert(path, *mode, &now) {
                                        let _ = bus.publish(a);
                                    }
                                }
                                Some(pm) if pm != mode => {
                                    if let Some(a) = permission_alert(path, *mode, &now) {
                                        let _ = bus.publish(a);
                                    }
                                }
                                _ => {}
                            }
                        }
                        for path in prev_map.keys() {
                            if !cur.contains_key(path) {
                                let _ = bus.publish(deleted_file_alert(path, &now));
                            }
                        }
                    }
                    prev = Some(cur);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn over_open_perms_alert_critical_octal() {
        let a = permission_alert("/s/credentials/key", 0o644, "t").unwrap();
        assert_eq!(a.severity, Severity::Critical);
        assert!(a.message.contains("key (644)"));
        assert!(a.details.unwrap().contains("Permissions: 644"));
    }

    #[test]
    fn locked_down_perms_no_alert() {
        assert!(permission_alert("/s/credentials/key", 0o600, "t").is_none());
        assert!(permission_alert("/s/credentials/key", 0o700, "t").is_none());
    }

    #[tokio::test]
    async fn scan_credentials_lists_creds_and_env() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().to_str().unwrap();
        tokio::fs::create_dir_all(dir.path().join("credentials"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("credentials").join("api.key"), "k")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join(".env"), "SECRET=1")
            .await
            .unwrap();
        let map = scan_credentials(sd).await;
        assert_eq!(map.len(), 2);
        assert!(map.keys().any(|p| p.ends_with("/credentials/api.key")));
        assert!(map.keys().any(|p| p.ends_with("/.env")));
    }

    #[test]
    fn add_and_delete_alerts_use_basename() {
        assert_eq!(
            new_file_alert("/s/credentials/api.key", "t").message,
            "New credential file detected: api.key"
        );
        assert_eq!(
            deleted_file_alert("/s/credentials/api.key", "t").severity,
            Severity::Medium
        );
    }
}

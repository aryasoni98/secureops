//! Network hardening (priority 5) — port of `hardening/network-hardening.ts`.
//!
//! Emits the single informational finding `SC-NET-001` in `check()`, and in
//! `fix()` generates firewall scripts under `<stateDir>/.secureops/network/`:
//! iptables (`net-iptables`) on Linux, pf (`net-pf`) on macOS, otherwise a
//! skipped `net-platform` action; plus a `net-blocklist` C2 IP file when the
//! IOC blocklist is non-empty. The platform branch keys on `ctx.platform()`
//! base string ("linux" / "darwin") per PRODUCT.md, so both branches compile
//! on every host.

use crate::HardeningModule;
use async_trait::async_trait;
use secureops_core::{
    AuditContext, AuditFinding, HardeningAction, HardeningResult, IocDatabase, Severity,
};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default egress allowlist (port of the TS `EGRESS_ALLOWLIST` constant).
const EGRESS_ALLOWLIST: [&str; 5] = [
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.together.xyz",
    "openrouter.ai",
];

/// Format a Unix timestamp (seconds + millis) as `new Date().toISOString()`
/// would: `YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC, millisecond precision). Pure-std so
/// the crate needs no extra time dependency; mirrors the JS ISO-8601 string
/// embedded verbatim in the generated script headers.
fn iso8601(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, m, d, hour, minute, second, millis
    )
}

/// Current time as an ISO-8601 string (`new Date().toISOString()`).
fn now_iso8601() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    iso8601(dur.as_secs(), dur.subsec_millis())
}

/// Generate the iptables rules script (port of `generateIptablesScript`).
fn generate_iptables_script(allowlist: &[String], blocklist: &[String]) -> String {
    let mut lines: Vec<String> = vec![
        "#!/bin/bash".to_string(),
        "# SecureOps Network Hardening - iptables rules".to_string(),
        "# Review carefully before applying!".to_string(),
        format!("# Generated: {}", now_iso8601()),
        "".to_string(),
        "# Block known C2 IPs".to_string(),
    ];

    for ip in blocklist {
        lines.push(format!("iptables -A OUTPUT -d {} -j DROP", ip));
    }

    lines.push("".to_string());
    lines.push("# Egress allowlist (uncomment to enforce)".to_string());
    lines.push(
        "# WARNING: This will restrict ALL outbound traffic to only allowed destinations"
            .to_string(),
    );
    for domain in allowlist {
        lines.push(format!(
            "# iptables -A OUTPUT -d {} -p tcp --dport 443 -j ACCEPT",
            domain
        ));
    }
    lines.push(
        "# iptables -A OUTPUT -p tcp --dport 443 -j DROP  # Block all other HTTPS".to_string(),
    );

    lines.join("\n")
}

/// Generate the pf (macOS) rules script (port of `generatePfScript`).
fn generate_pf_script(allowlist: &[String], blocklist: &[String]) -> String {
    let mut lines: Vec<String> = vec![
        "# SecureOps Network Hardening - pf rules (macOS)".to_string(),
        "# Review carefully before applying!".to_string(),
        format!("# Generated: {}", now_iso8601()),
        "# Add these rules to /etc/pf.conf".to_string(),
        "".to_string(),
        "# Block known C2 IPs".to_string(),
    ];

    for ip in blocklist {
        lines.push(format!("block out quick on en0 to {}", ip));
    }

    lines.push("".to_string());
    lines.push("# Egress allowlist (uncomment to enforce)".to_string());
    for domain in allowlist {
        lines.push(format!(
            "# pass out on en0 proto tcp to {} port 443",
            domain
        ));
    }
    lines.push("# block out on en0 proto tcp to any port 443  # Block all other HTTPS".to_string());

    lines.join("\n")
}

/// chmod helper (port of the shared `chmodSafe`): returns true on success, and
/// is a no-op returning false on non-unix platforms.
async fn chmod_safe(path: &Path, mode: u32) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .await
            .is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        false
    }
}

/// Network hardening module. Holds the IOC database so `fix()` can build the
/// C2 blocklist from `c2_ips` (the TS module calls `loadIOCDatabase()`).
pub struct NetworkHardening {
    pub ioc: Arc<IocDatabase>,
}

impl NetworkHardening {
    pub fn new(ioc: Arc<IocDatabase>) -> Self {
        Self { ioc }
    }
}

#[async_trait]
impl HardeningModule for NetworkHardening {
    fn name(&self) -> &'static str {
        "network-hardening"
    }

    fn priority(&self) -> u32 {
        5
    }

    async fn check(&self, ctx: &dyn AuditContext) -> Vec<AuditFinding> {
        let mut findings: Vec<AuditFinding> = Vec::new();

        findings.push(
            AuditFinding::builder("SC-NET-001", Severity::Info, "network")
                .title("Network hardening available")
                .description("SecureOps can generate egress allowlist and C2 blocklist scripts.")
                .evidence(format!("Platform: {}", ctx.platform()))
                .remediation("Run \"secureops harden\" to generate network rules")
                .auto_fixable(true)
                .owasp_asi("ASI05")
                .build(),
        );

        findings
    }

    async fn fix(&self, ctx: &dyn AuditContext, _backup_dir: &Path) -> HardeningResult {
        let mut applied: Vec<HardeningAction> = Vec::new();
        let mut skipped: Vec<HardeningAction> = Vec::new();
        let errors: Vec<String> = Vec::new();

        // C2 blocklist from the injected IOC database (TS: `db.c2_ips`). The CLI
        // supplies the same bundled `indicators.json` the TS `loadIOCDatabase`
        // reads, so `net-blocklist` fires identically.
        let blocklist: Vec<String> = self.ioc.c2_ips.clone();

        let allowlist: Vec<String> = ctx
            .config()
            .secureops
            .as_ref()
            .and_then(|s| s.network.as_ref())
            .and_then(|n| n.egress_allowlist.as_ref())
            .cloned()
            .unwrap_or_else(|| EGRESS_ALLOWLIST.iter().map(|s| s.to_string()).collect());

        // Platform branch keys on the `ctx.platform()` base string (the part
        // before the first '-', e.g. "linux"/"darwin"), mirroring the TS
        // `os.platform()` values "linux"/"darwin".
        let platform = ctx.platform().split('-').next().unwrap_or("").to_string();

        let script_dir = Path::new(ctx.state_dir())
            .join(".secureops")
            .join("network");
        let _ = tokio::fs::create_dir_all(&script_dir).await;

        if platform == "linux" {
            let script = generate_iptables_script(&allowlist, &blocklist);
            let script_path = script_dir.join("egress-rules.sh");
            if tokio::fs::write(&script_path, &script).await.is_ok() {
                let _ = chmod_safe(&script_path, 0o700).await;
            }
            applied.push(HardeningAction {
                id: "net-iptables".to_string(),
                description: "Generated iptables egress rules script".to_string(),
                before: "no rules".to_string(),
                after: script_path.to_string_lossy().to_string(),
            });
        } else if platform == "darwin" {
            let script = generate_pf_script(&allowlist, &blocklist);
            let script_path = script_dir.join("pf-rules.conf");
            if tokio::fs::write(&script_path, &script).await.is_ok() {
                let _ = chmod_safe(&script_path, 0o600).await;
            }
            applied.push(HardeningAction {
                id: "net-pf".to_string(),
                description: "Generated pf egress rules (macOS)".to_string(),
                before: "no rules".to_string(),
                after: script_path.to_string_lossy().to_string(),
            });
        } else {
            skipped.push(HardeningAction {
                id: "net-platform".to_string(),
                description: "Network rules generation skipped — unsupported platform".to_string(),
                before: format!("platform: {}", platform),
                after: "skipped".to_string(),
            });
        }

        // Generate C2 blocklist file (only when the blocklist is non-empty).
        if !blocklist.is_empty() {
            let blocklist_path = script_dir.join("c2-blocklist.txt");
            let _ = tokio::fs::write(&blocklist_path, format!("{}\n", blocklist.join("\n"))).await;
            applied.push(HardeningAction {
                id: "net-blocklist".to_string(),
                description: "Generated C2 IP blocklist file".to_string(),
                before: "no blocklist".to_string(),
                after: format!("{} IPs blocked", blocklist.len()),
            });
        }

        HardeningResult {
            module: "network-hardening".to_string(),
            applied,
            skipped,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureops_core::{FileInfo, OpenClawConfig};

    /// Minimal in-memory `AuditContext` mock for the network module's tests.
    struct MockCtx {
        state_dir: String,
        platform: String,
        config: OpenClawConfig,
    }

    #[async_trait]
    impl AuditContext for MockCtx {
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
            "single-tenant"
        }
        fn openclaw_version(&self) -> &str {
            "0.0.0"
        }
        async fn file_info(&self, path: &str) -> FileInfo {
            FileInfo {
                path: path.to_string(),
                ..Default::default()
            }
        }
        async fn read_file(&self, _path: &str) -> Option<String> {
            None
        }
        async fn list_dir(&self, _path: &str) -> Vec<String> {
            Vec::new()
        }
        async fn file_exists(&self, _path: &str) -> bool {
            false
        }
        async fn get_file_permissions(&self, _path: &str) -> Option<u32> {
            None
        }
    }

    fn ctx(state_dir: &str, platform: &str) -> MockCtx {
        MockCtx {
            state_dir: state_dir.to_string(),
            platform: platform.to_string(),
            config: OpenClawConfig::default(),
        }
    }

    /// Module with an empty IOC database (no C2 blocklist).
    fn module() -> NetworkHardening {
        NetworkHardening::new(Arc::new(IocDatabase::default()))
    }

    /// Module whose IOC database carries C2 IPs.
    fn module_with_c2(ips: &[&str]) -> NetworkHardening {
        let mut db = IocDatabase::default();
        db.c2_ips = ips.iter().map(|s| s.to_string()).collect();
        NetworkHardening::new(Arc::new(db))
    }

    #[tokio::test]
    async fn check_always_emits_sc_net_001_info() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(dir.path().to_str().unwrap(), "darwin-arm64");
        let findings = module().check(&c).await;
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.id, "SC-NET-001");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.category, "network");
        assert!(f.auto_fixable);
        assert_eq!(f.owasp_asi, "ASI05");
        // Evidence reports the raw platform string from the context.
        assert_eq!(f.evidence, "Platform: darwin-arm64");
        assert!(f.maestro_layer.is_none());
        assert!(f.nist_category.is_none());
    }

    #[tokio::test]
    async fn fix_on_darwin_generates_pf_rules() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().to_str().unwrap();
        let c = ctx(state, "darwin");
        let result = module().fix(&c, dir.path()).await;

        assert_eq!(result.module, "network-hardening");
        assert!(result.errors.is_empty());
        // Empty blocklist => only the pf action fires, no net-blocklist.
        let ids: Vec<&str> = result.applied.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["net-pf"]);
        assert!(result.skipped.is_empty());

        // The pf rules file exists with the default allowlist commented in.
        let pf_path = dir
            .path()
            .join(".secureops")
            .join("network")
            .join("pf-rules.conf");
        let body = tokio::fs::read_to_string(&pf_path).await.unwrap();
        assert!(body.starts_with("# SecureOps Network Hardening - pf rules (macOS)"));
        assert!(body.contains("# pass out on en0 proto tcp to api.anthropic.com port 443"));
    }

    #[tokio::test]
    async fn fix_on_linux_generates_iptables_rules() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().to_str().unwrap();
        let c = ctx(state, "linux-x64");
        let result = module().fix(&c, dir.path()).await;

        let ids: Vec<&str> = result.applied.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["net-iptables"]);
        assert!(result.skipped.is_empty());

        let sh_path = dir
            .path()
            .join(".secureops")
            .join("network")
            .join("egress-rules.sh");
        let body = tokio::fs::read_to_string(&sh_path).await.unwrap();
        assert!(body.starts_with("#!/bin/bash"));
        assert!(
            body.contains("# iptables -A OUTPUT -d api.openai.com -p tcp --dport 443 -j ACCEPT")
        );
    }

    #[tokio::test]
    async fn fix_on_unknown_platform_skips() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().to_str().unwrap();
        let c = ctx(state, "win32");
        let result = module().fix(&c, dir.path()).await;

        assert!(result.applied.is_empty());
        let ids: Vec<&str> = result.skipped.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["net-platform"]);
        assert_eq!(result.skipped[0].before, "platform: win32");
        assert_eq!(result.skipped[0].after, "skipped");
    }

    #[tokio::test]
    async fn fix_with_c2_ips_emits_blocklist() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().to_str().unwrap();
        let c = ctx(state, "darwin");
        let result = module_with_c2(&["91.92.242.30"]).fix(&c, dir.path()).await;

        let ids: Vec<&str> = result.applied.iter().map(|a| a.id.as_str()).collect();
        // pf action plus the C2 blocklist action (TS: db.c2_ips non-empty).
        assert_eq!(ids, vec!["net-pf", "net-blocklist"]);
        let blk = &result.applied[1];
        assert_eq!(blk.after, "1 IPs blocked");

        let blocklist_path = dir
            .path()
            .join(".secureops")
            .join("network")
            .join("c2-blocklist.txt");
        let body = tokio::fs::read_to_string(&blocklist_path).await.unwrap();
        assert_eq!(body, "91.92.242.30\n");
    }
}

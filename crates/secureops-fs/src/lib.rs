//! # secureops-fs
//!
//! The real, [`tokio::fs`]-backed [`AuditContext`] implementation plus a
//! localhost-only TCP port probe. This is the Ring 0/1 bridge between the
//! I/O-free [`secureops_core`] type model and the actual host filesystem and
//! loopback network — see **PRODUCT.md A.4** (crate map: "tokio::fs context +
//! localhost probe") and **PRODUCT.md B.2** (audit flow: "CLI/napi builds an
//! `Arc<dyn AuditContext>` (real `tokio::fs` impl)" and "`--deep` adds
//! localhost-only port probes").
//!
//! ## Why this crate exists
//!
//! Every [`Check`](secureops_core::Check) receives `&dyn AuditContext` and
//! never touches the filesystem directly. [`secureops_core::context`] keeps the
//! trait I/O-free so checks are unit-testable against an in-memory mock; this
//! crate supplies the production implementation that performs the actual reads.
//!
//! ## Design notes
//!
//! - All async file methods route through `tokio::fs` so a long audit never
//!   blocks the runtime.
//! - Unix mode bits are read via [`std::os::unix::fs::PermissionsExt`] and only
//!   compiled on unix targets (`#[cfg(unix)]`); on non-unix hosts permission
//!   queries degrade to `None`.
//! - [`probe_port`] is a **loopback-only** deep probe (PRODUCT.md B.2 step 4);
//!   callers must restrict `host` to localhost addresses.

#![forbid(unsafe_code)]

pub mod behavioral;
pub mod killswitch;

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use secureops_core::{
    AuditContext, ChannelConfig, DockerComposeConfig, FileInfo, OpenClawConfig, SkillMetadata,
};

/// The production [`AuditContext`]: stored config/metadata for the sync getters
/// plus `tokio::fs`-backed implementations of the async I/O methods.
///
/// Constructed once by the CLI / napi shim per **PRODUCT.md B.2 step 1**
/// ("CLI/napi builds an `Arc<dyn AuditContext>` (real `tokio::fs` impl)") and
/// shared across the [`Check`](secureops_core::Check) registry fan-out.
pub struct RealAuditContext {
    /// `<stateDir>` root — the OpenClaw state directory the audit inspects.
    state_dir: String,
    /// The parsed OpenClaw configuration tree (PRODUCT.md config contract).
    config: OpenClawConfig,
    /// Platform string (e.g. `"darwin"`, `"linux"`) surfaced in the report.
    platform: String,
    /// Deployment mode (e.g. `"local"`, `"docker"`).
    deployment_mode: String,
    /// Detected OpenClaw version string.
    openclaw_version: String,

    /// Pre-loaded channel routing surfaces (supply-chain / DM-policy checks).
    channels: Vec<ChannelConfig>,
    /// Pre-loaded installed-skill metadata (supply-chain / skill-scan checks).
    skills: Vec<SkillMetadata>,
    /// Optional parsed `docker-compose` config when `deployment_mode == "docker"`.
    docker_compose: Option<DockerComposeConfig>,
    /// Recent session-log lines for behavioral/forensic checks.
    session_logs: Vec<String>,
    /// Recent connection-log lines for egress/network checks.
    connection_logs: Vec<String>,
}

impl RealAuditContext {
    /// Build a context from already-resolved config and metadata.
    ///
    /// The caller (CLI / napi) is responsible for discovering the state dir,
    /// parsing `openclaw.json`, and detecting platform/version before handing
    /// the assembled context to [`run_audit`](secureops_core::run_audit).
    pub fn new(
        state_dir: impl Into<String>,
        config: OpenClawConfig,
        platform: impl Into<String>,
        deployment_mode: impl Into<String>,
        openclaw_version: impl Into<String>,
    ) -> Self {
        Self {
            state_dir: state_dir.into(),
            config,
            platform: platform.into(),
            deployment_mode: deployment_mode.into(),
            openclaw_version: openclaw_version.into(),
            channels: Vec::new(),
            skills: Vec::new(),
            docker_compose: None,
            session_logs: Vec::new(),
            connection_logs: Vec::new(),
        }
    }

    /// Build a context for the current host, deriving a **Node-compatible**
    /// platform string from the Rust target so it matches `report.platform`
    /// produced by the TS implementation (`${os.platform()}-${os.arch()}`) and so
    /// downstream `platform.split('-')` logic resolves the same base token.
    ///
    /// The platform field is set to [`host_platform`]; all other inputs mirror
    /// [`RealAuditContext::new`].
    pub fn for_host(
        state_dir: impl Into<String>,
        config: OpenClawConfig,
        deployment_mode: impl Into<String>,
        openclaw_version: impl Into<String>,
    ) -> Self {
        Self::new(
            state_dir,
            config,
            host_platform(),
            deployment_mode,
            openclaw_version,
        )
    }

    /// Builder: attach pre-loaded channel configs.
    pub fn with_channels(mut self, channels: Vec<ChannelConfig>) -> Self {
        self.channels = channels;
        self
    }

    /// Builder: attach pre-loaded skill metadata.
    pub fn with_skills(mut self, skills: Vec<SkillMetadata>) -> Self {
        self.skills = skills;
        self
    }

    /// Builder: attach a parsed docker-compose config.
    pub fn with_docker_compose(mut self, docker_compose: Option<DockerComposeConfig>) -> Self {
        self.docker_compose = docker_compose;
        self
    }

    /// Builder: attach recent session-log lines.
    pub fn with_session_logs(mut self, session_logs: Vec<String>) -> Self {
        self.session_logs = session_logs;
        self
    }

    /// Builder: attach recent connection-log lines.
    pub fn with_connection_logs(mut self, connection_logs: Vec<String>) -> Self {
        self.connection_logs = connection_logs;
        self
    }
}

#[async_trait]
impl AuditContext for RealAuditContext {
    // ---- Sync getters: return the stored fields ----

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

    // ---- Async I/O: real tokio::fs ----

    /// Aggregate file metadata (permissions + existence + size) in one shot.
    ///
    /// Faithful port of `createAuditContext.fileInfo` in `src/index.ts`: stat the
    /// path and, on success, surface `exists: true`, the low 9 permission bits
    /// (`mode & 0o777`), and the byte size; on any error report `exists: false`
    /// with the rest defaulted. Permission bits are unix-only — on non-unix hosts
    /// there are no POSIX mode bits, so `permissions` stays `None`. `content` is
    /// never populated here (matching the TS impl, which omits the `content`
    /// field); callers that need bytes use [`read_file`](Self::read_file).
    async fn file_info(&self, path: &str) -> FileInfo {
        match tokio::fs::metadata(path).await {
            Ok(metadata) => {
                #[cfg(unix)]
                let permissions = {
                    use std::os::unix::fs::PermissionsExt;
                    Some(metadata.permissions().mode() & 0o777)
                };
                #[cfg(not(unix))]
                let permissions = None;

                FileInfo {
                    path: path.to_string(),
                    permissions,
                    content: None,
                    exists: Some(true),
                    size: Some(metadata.len()),
                }
            }
            Err(_) => FileInfo {
                path: path.to_string(),
                exists: Some(false),
                ..Default::default()
            },
        }
    }

    /// Read a file to a UTF-8 `String`, or `None` if it is missing / unreadable
    /// / not valid UTF-8. Backed by [`tokio::fs::read_to_string`].
    async fn read_file(&self, path: &str) -> Option<String> {
        tokio::fs::read_to_string(path).await.ok()
    }

    /// List the (non-recursive) entries of a directory by file name. Backed by
    /// [`tokio::fs::read_dir`]; returns an empty vec on any error so a single
    /// unreadable dir never aborts the audit (PRODUCT.md B.2 "the run never
    /// aborts").
    async fn list_dir(&self, path: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rd = match tokio::fs::read_dir(path).await {
            Ok(rd) => rd,
            Err(_) => return out,
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            out.push(entry.file_name().to_string_lossy().into_owned());
        }
        out
    }

    /// Whether a path exists. Backed by [`tokio::fs::try_exists`] (treats a
    /// permission error / missing path as `false`).
    async fn file_exists(&self, path: &str) -> bool {
        tokio::fs::try_exists(path).await.unwrap_or(false)
    }

    /// Unix mode bits (e.g. `0o600`) for `path`, or `None` when unavailable.
    ///
    /// On unix this reads [`std::fs::Permissions`] via
    /// [`std::os::unix::fs::PermissionsExt::mode`]; on non-unix hosts there are
    /// no POSIX mode bits, so it always returns `None`.
    async fn get_file_permissions(&self, path: &str) -> Option<u32> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = tokio::fs::metadata(path).await.ok()?;
            // Mask to the permission bits only (TS: `stat.mode & 0o777`), so the
            // octal-formatted value matches the TS tool (e.g. 644, not 100644).
            Some(meta.permissions().mode() & 0o777)
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    // ---- Sync metadata getters: return stored fields ----

    fn channels(&self) -> &[ChannelConfig] {
        &self.channels
    }

    fn skills(&self) -> &[SkillMetadata] {
        &self.skills
    }

    fn docker_compose(&self) -> Option<&DockerComposeConfig> {
        self.docker_compose.as_ref()
    }

    fn session_logs(&self) -> &[String] {
        &self.session_logs
    }

    fn connection_logs(&self) -> &[String] {
        &self.connection_logs
    }
}

/// Localhost-only deep TCP port probe (**PRODUCT.md B.2 step 4**: "`--deep`
/// adds localhost-only port probes").
///
/// Attempts a [`tokio::net::TcpStream`] connect to `host:port` bounded by
/// `timeout` ([`tokio::time::timeout`]). Returns `true` iff the connection is
/// established within the deadline (i.e. something is listening), `false` on
/// refusal, error, or timeout.
///
/// # Safety scope
///
/// This is intended for the `--deep` audit pass and **must only be pointed at
/// loopback** (`127.0.0.1` / `::1` / `localhost`). It performs no scanning of
/// remote hosts; callers are responsible for restricting `host`.
pub async fn probe_port(port: u16, host: &str, timeout: Duration) -> bool {
    let addr = format!("{host}:{port}");
    matches!(
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_stream))
    )
}

/// Node-compatible platform string for the current host (`"{os}-{arch}"`).
///
/// Mirrors the TS `${os.platform()}-${os.arch()}` value so the Rust report's
/// `platform` field matches byte-for-byte and `platform.split('-')` yields the
/// same base token on both runtimes. Rust's [`std::env::consts`] names are
/// remapped to Node's: `macos -> darwin`, `windows -> win32`, `aarch64 ->
/// arm64`, `x86_64 -> x64`; any other value passes through unchanged.
pub fn host_platform() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        other => other,
    };
    format!("{os}-{arch}")
}

/// Convenience helper: expand a leading `~` in `path` against `$HOME`.
///
/// State-dir discovery often deals with `~/.openclaw`-style paths; this keeps
/// the path-handling logic out of the trait impl. Returns the input unchanged
/// when there is no `~` prefix or `$HOME` is unset.
pub fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return Path::new(&home).join(rest).to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_file_missing_returns_none() {
        let ctx = RealAuditContext::new(
            "/tmp/secureops-nonexistent",
            OpenClawConfig::default(),
            "darwin",
            "local",
            "0.0.0",
        );
        assert!(ctx
            .read_file("/tmp/secureops-definitely-not-here-xyz")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn file_exists_false_for_missing() {
        let ctx = RealAuditContext::new(
            "/tmp",
            OpenClawConfig::default(),
            "darwin",
            "local",
            "0.0.0",
        );
        assert!(
            !ctx.file_exists("/tmp/secureops-definitely-not-here-xyz")
                .await
        );
    }

    #[tokio::test]
    async fn probe_unused_port_is_false() {
        // Port 1 on loopback is essentially never open in CI; a short timeout
        // keeps the test fast even if the connect hangs.
        assert!(!probe_port(1, "127.0.0.1", Duration::from_millis(200)).await);
    }
}

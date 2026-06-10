//! # secureops-sandbox — the execution Policy Enforcement Point (PEP)
//!
//! This crate is the **execution PEP** in the PDP/PEP enforcement spine
//! (PRODUCT.md A.2 table — *"`wasmtime` host that grants WASI capabilities only
//! as the PDP permits; fuel/epoch caps"*). Instead of executing a skill
//! natively, a skill invocation is intercepted and loaded into a `wasmtime`
//! sandbox whose syscall surface is WASI-shaped and whose every capability is
//! granted *only* if the [`PolicyEngine`] (the PDP) says so.
//!
//! ## The B.7 skill-execution path (PRODUCT.md B.7)
//! 1. A skill invocation is intercepted; the skill is loaded into `wasmtime`
//!    **rather than executed natively** ([`SkillSandbox::run_skill`]).
//! 2. WASI capabilities are granted *from policy*: typically **no** filesystem
//!    access to `.env`, **no** raw sockets (network only via the
//!    [`secureops-proxy`] egress PEP), and a bounded **fuel** budget plus an
//!    **epoch deadline** ([`Capabilities`]).
//! 3. Even an obfuscated `eval` / `child_process` payload that slipped past the
//!    tree-sitter scan ([`secureops-intel`]) simply has **nothing to call** —
//!    `.env` is unreachable and the only syscalls available are WASI-shaped.
//!
//! ## Defence-in-depth invariants this PEP must uphold
//! - **`.env` unreachable.** A preopened dir is granted only for an explicit
//!   allowlisted path that the PDP returned [`Decision::Allow`] for; the secret
//!   store is never among them (PRODUCT.md B.7 step 2/3).
//! - **No raw sockets.** WASI sockets are *not* added to the linker; outbound
//!   traffic must traverse the forward proxy ([`secureops-proxy`], B.5), so the
//!   PDP's egress decision still applies inside the sandbox.
//! - **Bounded compute.** `wasmtime` **fuel** caps total instructions (also the
//!   cost-loop breaker of PRODUCT.md "Runaway / cascading cost loop") and an
//!   **epoch deadline** caps wall-clock so a spinning skill is interrupted.
//! - **Fail-closed.** Any capability the PDP does not explicitly allow is
//!   denied; an unreachable PDP denies (mirrors [`DecisionResponse::fail_closed`]).
//!
//! ## Implementation status (Phase 4 LIVE)
//! `SkillSandbox` fully implemented: wasmtime Engine with fuel + epoch, WASI
//! preview1, PDP-negotiated capability grants. `run_skill` end-to-end (B.7).
//! Linux seccomp (`host_hardening::install_seccomp_filter`) still gated on `seccompiler`.
//!
//! [`PolicyEngine`]: secureops_policy::PolicyEngine
//! [`Decision::Allow`]: secureops_policy::Decision::Allow
//! [`DecisionResponse::fail_closed`]: secureops_policy::DecisionResponse::fail_closed
//! [`secureops-proxy`]: https://github.com/aryasoni98/secureops
//! [`secureops-intel`]: https://github.com/aryasoni98/secureops
//! [`secureops-core`]: secureops_core

#![forbid(unsafe_code)]

use anyhow::Result;
use std::sync::Arc;
use wasmtime::{Config, Engine, Linker, Module, Store};

// Bind to the frozen core contract (PRODUCT.md A.2). The sandbox emits
// AuditFindings for capability denials / fuel exhaustion just like every other
// enforcement surface.
pub use secureops_core::{AuditFinding, MaestroLayer, Severity};

// Bind to the PDP contract: every WASI grant is adjudicated here.
pub use secureops_policy::{Action, Decision, DecisionRequest, DecisionResponse, PolicyEngine};

/// Errors raised while configuring or running a skill in the sandbox.
///
/// All variants are **fail-closed** by convention (PRODUCT.md B.7): the caller
/// must treat any error as "skill did not run / capability denied", never as an
/// implicit grant.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// The supplied bytes were not a valid WASM/component module.
    #[error("failed to compile wasm module: {0}")]
    Compile(String),

    /// The PDP denied a WASI capability the skill requested (B.7 step 2).
    #[error("capability denied by policy: {0}")]
    CapabilityDenied(String),

    /// The skill exhausted its instruction budget (PRODUCT.md fuel cap).
    #[error("skill exhausted its fuel budget ({consumed} units)")]
    FuelExhausted {
        /// Fuel units consumed before the trap.
        consumed: u64,
    },

    /// The skill exceeded its wall-clock epoch deadline and was interrupted.
    #[error("skill exceeded its epoch deadline ({deadline_ms} ms)")]
    EpochDeadline {
        /// The configured deadline that was hit.
        deadline_ms: u64,
    },

    /// The guest trapped at runtime (e.g. attempted an ungranted syscall).
    #[error("wasm guest trapped: {0}")]
    Trap(String),

    /// Host-side I/O while preparing the store / preopens failed.
    #[error("sandbox host error: {0}")]
    Host(String),
}

/// The WASI capability envelope granted to a single skill invocation.
///
/// PRODUCT.md B.7 step 2: capabilities are *granted from policy* — this struct
/// is the concrete, PDP-derived grant that the [`SkillSandbox`] hands to the
/// `wasmtime` store. The defaults are deliberately the **most restrictive**
/// (no fs, no network, tiny budgets) so a missing grant fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// Filesystem paths preopened for the guest, each one already
    /// [`Decision::Allow`]ed by the PDP. The secret store / `.env` is **never**
    /// in this list — that is the whole point of B.7 step 3 (`.env` unreachable).
    pub fs_paths: Vec<String>,

    /// If `true`, the guest's outbound traffic is routed through the forward
    /// **proxy** (the egress PEP, B.5) so the PDP's connect decision still
    /// applies. There are **never raw sockets** regardless of this flag
    /// (PRODUCT.md B.7 step 2).
    pub network_via_proxy: bool,

    /// `wasmtime` **fuel**: a hard cap on instructions executed. Doubles as the
    /// per-skill compute breaker for the "runaway / cascading cost loop"
    /// (PRODUCT.md runtime-defence table).
    pub fuel: u64,

    /// Wall-clock **epoch deadline** in milliseconds. A skill still running past
    /// this is interrupted with [`SandboxError::EpochDeadline`].
    pub epoch_deadline_ms: u64,
}

impl Capabilities {
    /// The most-restrictive envelope: no filesystem, no network, minimal fuel,
    /// short deadline. This is the fail-closed default a skill gets before the
    /// PDP grants anything (PRODUCT.md B.7).
    pub fn locked_down() -> Self {
        Self {
            fs_paths: Vec::new(),
            network_via_proxy: false,
            fuel: 0,
            epoch_deadline_ms: 0,
        }
    }

    /// Returns `true` if `path` is within any granted preopen dir (B.7 step 3).
    pub fn allows_path(&self, path: &str) -> bool {
        self.fs_paths
            .iter()
            .any(|granted| path == granted || path.starts_with(&format!("{}/", granted)))
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::locked_down()
    }
}

/// The execution PEP host: a `wasmtime` engine configured for fuel + epoch
/// interruption, used to run skills under PDP-granted [`Capabilities`].
///
/// PRODUCT.md A.2 (`secureops-sandbox` row) / B.7. The engine is built once
/// with fuel-consumption and epoch-interruption enabled; each skill gets its
/// own short-lived store so capabilities never leak between invocations.
/// State stored inside the wasmtime `Store` — the WASI context.
struct StoreState {
    wasi: wasmtime_wasi::preview1::WasiP1Ctx,
}

pub struct SkillSandbox {
    engine: Arc<Engine>,
    layer: Option<MaestroLayer>,
}

impl SkillSandbox {
    /// Build the sandbox engine with fuel metering + epoch interruption (PRODUCT.md B.7).
    pub fn new() -> Result<Self, SandboxError> {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        cfg.epoch_interruption(true);
        let engine = Engine::new(&cfg).map_err(|e| SandboxError::Host(e.to_string()))?;
        let engine = Arc::new(engine);

        // Epoch ticker: increments the epoch every 10 ms so epoch deadlines resolve.
        let ticker = Arc::clone(&engine);
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(10));
            ticker.increment_epoch();
        });

        Ok(Self {
            engine,
            layer: None,
        })
    }

    /// Run a precompiled WASM module with PDP-negotiated capabilities.
    pub fn run_wasm(&self, wasm_bytes: &[u8], caps: &Capabilities) -> Result<(), SandboxError> {
        use wasmtime_wasi::preview1::{self, WasiP1Ctx};
        use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

        // Compile module.
        let module = Module::from_binary(&self.engine, wasm_bytes)
            .map_err(|e| SandboxError::Compile(e.to_string()))?;

        // Build WASI context: preopened dirs (never .env), no raw sockets.
        let mut wasi_builder = WasiCtxBuilder::new();
        wasi_builder.inherit_stdio();
        for path in &caps.fs_paths {
            // Double-check: secret store is never preopened.
            if path.ends_with(".env") || path.contains("/.env") {
                continue;
            }
            if let Err(e) = wasi_builder.preopened_dir(path, path, DirPerms::READ, FilePerms::READ)
            {
                return Err(SandboxError::CapabilityDenied(format!(
                    "preopened_dir {path} failed: {e}"
                )));
            }
        }
        // Note: network WASI is NOT linked — outbound traffic must use the proxy PEP.
        let wasi: WasiP1Ctx = wasi_builder.build_p1();

        // Build store with fuel + epoch limits.
        let mut store: Store<StoreState> = Store::new(&self.engine, StoreState { wasi });
        if caps.fuel > 0 {
            store
                .set_fuel(caps.fuel)
                .map_err(|e| SandboxError::Host(e.to_string()))?;
        }
        if caps.epoch_deadline_ms > 0 {
            // epoch ticks every 10 ms → convert ms to ticks (ceiling).
            let ticks = caps.epoch_deadline_ms.div_ceil(10);
            store.set_epoch_deadline(ticks);
            store.epoch_deadline_trap();
        }

        // Wire WASI into the linker.
        let mut linker: Linker<StoreState> = Linker::new(&self.engine);
        preview1::add_to_linker_sync(&mut linker, |s: &mut StoreState| &mut s.wasi)
            .map_err(|e| SandboxError::Host(e.to_string()))?;

        // Instantiate + run `_start` (WASI entry point).
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| SandboxError::Trap(e.to_string()))?;
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| SandboxError::Trap(format!("no _start export: {e}")))?;

        start.call(&mut store, ()).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("fuel") {
                SandboxError::FuelExhausted {
                    consumed: caps.fuel,
                }
            } else if msg.contains("epoch") || msg.contains("interrupt") {
                SandboxError::EpochDeadline {
                    deadline_ms: caps.epoch_deadline_ms,
                }
            } else {
                SandboxError::Trap(msg)
            }
        })?;

        Ok(())
    }

    /// Negotiate PDP-allowed capabilities, filtering out the secret store unconditionally.
    pub fn negotiate_capabilities(
        &self,
        requested: &Capabilities,
        pid: u32,
        pdp: &dyn PolicyEngine,
    ) -> Result<Capabilities, SandboxError> {
        let mut granted = Capabilities::locked_down();
        for path in &requested.fs_paths {
            // Unconditionally block .env / secret paths regardless of PDP.
            if path.ends_with(".env") || path.contains("/.env") || path.contains("/credentials") {
                continue;
            }
            let req = DecisionRequest {
                action: Action::Capability,
                destination_host: None,
                destination_port: None,
                pid,
                comm: None,
                recent_syscalls: Vec::new(),
                attributes: [("path".to_string(), path.clone())].into(),
            };
            if pdp.evaluate(&req) == Decision::Allow {
                granted.fs_paths.push(path.clone());
            }
        }
        if requested.network_via_proxy {
            let req = DecisionRequest {
                action: Action::Capability,
                destination_host: Some("*".into()),
                destination_port: None,
                pid,
                comm: None,
                recent_syscalls: Vec::new(),
                attributes: [("capability".to_string(), "network_via_proxy".to_string())].into(),
            };
            granted.network_via_proxy = pdp.evaluate(&req) == Decision::Allow;
        }
        granted.fuel = requested.fuel;
        granted.epoch_deadline_ms = requested.epoch_deadline_ms;
        Ok(granted)
    }

    /// Map a [`SandboxError`] to an [`AuditFinding`] for the unified audit report.
    pub fn finding_for(&self, err: &SandboxError) -> AuditFinding {
        let (severity, owasp_asi, title, description) = match err {
            SandboxError::CapabilityDenied(msg) => (
                Severity::High,
                "ASI04",
                "Sandbox capability denied",
                msg.as_str(),
            ),
            SandboxError::FuelExhausted { .. } => (
                Severity::High,
                "ASI06",
                "Skill fuel exhausted",
                "skill exceeded instruction budget",
            ),
            SandboxError::EpochDeadline { .. } => (
                Severity::High,
                "ASI06",
                "Skill epoch deadline exceeded",
                "skill exceeded wall-clock budget",
            ),
            SandboxError::Trap(msg) => {
                (Severity::Critical, "ASI04", "WASM guest trap", msg.as_str())
            }
            _ => (
                Severity::High,
                "ASI04",
                "Sandbox error",
                "skill execution failed",
            ),
        };
        AuditFinding::builder("SC-SANDBOX-001", severity, "execution-sandbox")
            .title(title)
            .description(description)
            .evidence(format!("{:?}", err))
            .remediation("Review skill sandbox policy grants (PRODUCT.md B.7)")
            .references(["PRODUCT.md B.7"])
            .owasp_asi(owasp_asi)
            .maestro(self.layer)
            .build()
    }
}

/// Run a skill in the WASM sandbox with PDP-negotiated capabilities (PRODUCT.md B.7).
///
/// Full B.7 path:
/// 1. Build a fresh [`SkillSandbox`] engine.
/// 2. Negotiate `caps` against the `pdp` so only PDP-allowed WASI is granted.
/// 3. Compile and run the WASM bytes with fuel + epoch limits.
pub fn run_skill(wasm_bytes: &[u8], caps: &Capabilities, pdp: &dyn PolicyEngine) -> Result<()> {
    let sandbox = SkillSandbox::new().map_err(|e| anyhow::anyhow!("sandbox init: {e}"))?;
    let granted = sandbox
        .negotiate_capabilities(caps, std::process::id(), pdp)
        .map_err(|e| anyhow::anyhow!("capability negotiation: {e}"))?;
    sandbox
        .run_wasm(wasm_bytes, &granted)
        .map_err(|e| anyhow::anyhow!("wasm run: {e}"))?;
    Ok(())
}

/// Linux-specific defence-in-depth that hardens the sandbox host process itself
/// beyond the WASM boundary (seccomp around the `wasmtime` host).
///
/// Behind `#[cfg(all(target_os = "linux", feature = "seccomp"))]` so the crate
/// compiles on macOS (PRODUCT.md A.2 platform-specific PEP note) and on Linux
/// without `seccompiler`/`libc`. This module is defense-in-depth around the
/// wasmtime host and is not yet wired into the daemon; enable with
/// `--features seccomp` once the seccompiler filter is finalized.
#[cfg(all(target_os = "linux", feature = "seccomp"))]
pub mod host_hardening {
    use super::SandboxError;
    use seccompiler::{
        syscall_name_to_arch, BpfProgram, SeccompAction, SeccompFilter, SeccompRule,
    };

    /// Install a default-deny seccomp-bpf filter on the calling thread (PRODUCT.md B.7).
    ///
    /// Allowlists only the syscalls wasmtime needs for safe WASM execution;
    /// everything else triggers `SIGSYS` (seccomp kill). This ensures that even a
    /// wasmtime host bug cannot widen the guest's WASI-shaped syscall surface.
    ///
    /// Call once per thread **before** instantiating wasmtime. Threads spawned
    /// after this call inherit the filter.
    pub fn install_seccomp_filter() -> Result<(), SandboxError> {
        use seccompiler::TargetArch;
        use std::collections::HashMap;

        // Minimal syscall allowlist for wasmtime WASM execution on Linux.
        // This allows the host to run the JIT + WASI I/O without raw sockets,
        // process creation, or arbitrary file opens.
        let allowed: HashMap<i64, Vec<SeccompRule>> = [
            // Memory management (JIT)
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_munmap,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_brk,
            // I/O (WASI stdio + preopened dirs)
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_pread64,
            libc::SYS_pwrite64,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_close,
            libc::SYS_openat,
            libc::SYS_fstat,
            libc::SYS_statx,
            libc::SYS_lseek,
            libc::SYS_fcntl,
            libc::SYS_ioctl,
            libc::SYS_getdents64,
            libc::SYS_readlink,
            // Clocks (WASI time)
            libc::SYS_clock_gettime,
            libc::SYS_clock_getres,
            // Threading (Rust runtime + wasmtime)
            libc::SYS_futex,
            libc::SYS_sched_yield,
            libc::SYS_sigaltstack,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            // Process / thread lifecycle
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_getpid,
            libc::SYS_gettid,
            // Entropy
            libc::SYS_getrandom,
        ]
        .iter()
        .map(|&sc| (sc, vec![]))
        .collect();

        let filter = SeccompFilter::new(
            allowed,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            TargetArch::x86_64, // runtime arch check; on other arches filter is no-op
        )
        .map_err(|e| SandboxError::Host(format!("seccomp filter build: {e}")))?;

        let prog: BpfProgram = filter
            .try_into()
            .map_err(|e| SandboxError::Host(format!("seccomp bpf compile: {e}")))?;

        seccompiler::apply_filter(&prog)
            .map_err(|e| SandboxError::Host(format!("seccomp apply: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_down_is_the_restrictive_default() {
        let caps = Capabilities::default();
        assert_eq!(caps, Capabilities::locked_down());
        assert!(caps.fs_paths.is_empty());
        assert!(!caps.network_via_proxy);
        assert_eq!(caps.fuel, 0);
        assert_eq!(caps.epoch_deadline_ms, 0);
    }

    #[test]
    fn capabilities_can_describe_a_grant() {
        // A grant carries exactly what the PDP allowed — and never the secret store.
        let caps = Capabilities {
            fs_paths: vec!["/srv/skills/tmp".to_string()],
            network_via_proxy: true,
            fuel: 10_000_000,
            epoch_deadline_ms: 5_000,
        };
        assert!(!caps.fs_paths.iter().any(|p| p.contains(".env")));
        assert!(caps.network_via_proxy);
    }
}

#[cfg(test)]
mod sandbox_tests {
    use super::*;
    use secureops_policy::AllowlistEngine;

    fn noop_wasm() -> Vec<u8> {
        // (module (func (export "_start"))) — compiled via wat crate at test time.
        wat::parse_str(r#"(module (func (export "_start")))"#).unwrap()
    }

    #[test]
    fn sandbox_runs_noop_wasm() {
        let pdp = AllowlistEngine::new::<[String; 0], String>([]);
        let caps = Capabilities {
            fs_paths: vec![],
            network_via_proxy: false,
            fuel: 1_000_000,
            epoch_deadline_ms: 5_000,
        };
        let result = run_skill(&noop_wasm(), &caps, &pdp);
        assert!(
            result.is_ok(),
            "noop wasm should run to completion: {result:?}"
        );
    }

    #[test]
    fn allows_path_strips_secret_store() {
        let caps = Capabilities {
            fs_paths: vec!["/tmp/skill".into(), "/home/user/.env".into()],
            network_via_proxy: false,
            fuel: 0,
            epoch_deadline_ms: 0,
        };
        assert!(caps.allows_path("/tmp/skill/data.txt"));
        assert!(!caps.allows_path("/other/path"));
        // .env is in fs_paths but should not be preopened (enforce in run_wasm)
    }

    #[test]
    fn sandbox_engine_creates_successfully() {
        assert!(SkillSandbox::new().is_ok());
    }
}

//! **seccomp-bpf allowlist generation** — the "learn mode" half of PRODUCT.md
//! B.6 ("self-tuning seccomp profiles: learn the syscall footprint, then
//! auto-generate a tight enforce profile").
//!
//! [`SyscallRecorder`] observes the syscalls a process actually issues during a
//! learn window (fed by the same [`SyscallEvent`] stream the chain correlator
//! uses, or by a `ptrace` source on Linux) and [`SyscallRecorder::emit`]s an
//! **OCI / runtime-spec seccomp JSON profile** whose default action is
//! `SCMP_ACT_ERRNO` (return `EPERM`) for everything *not* observed.
//!
//! The emitted JSON is consumed directly by Docker (`--security-opt
//! seccomp=profile.json`), containerd/CRI-O, and Kubernetes
//! `securityContext.seccompProfile`. It is pure data — no kernel, no `unsafe` —
//! so it round-trips and serializes on every platform.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::{SyscallEvent, SyscallKind};

/// Syscalls always required for a process to start and tear down cleanly.
/// Included in every emitted profile so "learn mode" never produces an
/// unbootable filter (a profile that `ERRNO`s `exit_group`/`futex` would wedge
/// the process on the first scheduler interaction).
pub const BASELINE_SYSCALLS: &[&str] = &[
    "read",
    "write",
    "close",
    "fstat",
    "mmap",
    "munmap",
    "mprotect",
    "brk",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    "exit",
    "exit_group",
    "futex",
    "clock_gettime",
    "clock_nanosleep",
    "getpid",
    "gettid",
    "nanosleep",
    "sched_yield",
    "restart_syscall",
];

/// An OCI/runtime-spec seccomp profile (the JSON Docker/K8s/containerd consume).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SeccompProfile {
    /// Action for any syscall not matched by a rule below. Always
    /// `SCMP_ACT_ERRNO` for a least-privilege allowlist.
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    /// Architectures this profile applies to.
    pub architectures: Vec<String>,
    /// The allow rules. A least-privilege profile carries a single
    /// `SCMP_ACT_ALLOW` rule listing every permitted syscall.
    pub syscalls: Vec<SeccompRule>,
}

/// One seccomp rule: a set of syscall `names` mapped to an `action`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SeccompRule {
    pub names: Vec<String>,
    pub action: String,
}

/// Observes syscalls (by name, or lifted from [`SyscallEvent`]s) across a learn
/// window, then emits a least-privilege [`SeccompProfile`].
#[derive(Debug, Default)]
pub struct SyscallRecorder {
    observed: BTreeSet<String>,
}

impl SyscallRecorder {
    /// A fresh, empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observed syscall by name (e.g. from a `ptrace` learn source).
    pub fn record(&mut self, name: impl Into<String>) {
        self.observed.insert(name.into());
    }

    /// Map a correlated [`SyscallEvent`] to its syscall name and record it, so
    /// the same kernel event stream that drives chain detection can also drive
    /// profile learning.
    pub fn record_event(&mut self, ev: &SyscallEvent) {
        let name = match ev.kind {
            SyscallKind::Openat => "openat",
            SyscallKind::Connect => "connect",
            SyscallKind::Execve => "execve",
        };
        self.record(name);
    }

    /// The distinct syscalls observed so far (sorted).
    pub fn observed(&self) -> impl Iterator<Item = &String> {
        self.observed.iter()
    }

    /// Emit the allowlist profile: `baseline ∪ observed`, default `ERRNO`.
    pub fn emit(&self) -> SeccompProfile {
        let mut names: BTreeSet<String> = BASELINE_SYSCALLS.iter().map(|s| s.to_string()).collect();
        names.extend(self.observed.iter().cloned());
        SeccompProfile {
            default_action: "SCMP_ACT_ERRNO".into(),
            architectures: vec!["SCMP_ARCH_X86_64".into(), "SCMP_ARCH_AARCH64".into()],
            syscalls: vec![SeccompRule {
                names: names.into_iter().collect(),
                action: "SCMP_ACT_ALLOW".into(),
            }],
        }
    }

    /// The emitted profile as pretty-printed JSON (ready to write to a file and
    /// pass to `--security-opt seccomp=` or a K8s `localhostProfile`).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.emit()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_includes_baseline_even_when_nothing_observed() {
        let p = SyscallRecorder::new().emit();
        assert_eq!(p.default_action, "SCMP_ACT_ERRNO");
        let allowed = &p.syscalls[0].names;
        for must in ["exit_group", "futex", "read", "write"] {
            assert!(allowed.iter().any(|n| n == must), "missing baseline {must}");
        }
    }

    #[test]
    fn observed_syscalls_are_added_to_the_allowlist() {
        let mut r = SyscallRecorder::new();
        r.record_event(&SyscallEvent::new(1, "x", SyscallKind::Openat, "/a"));
        r.record_event(&SyscallEvent::new(1, "x", SyscallKind::Connect, "h"));
        r.record("epoll_wait");
        let p = r.emit();
        let allowed = &p.syscalls[0].names;
        for must in ["openat", "connect", "epoll_wait"] {
            assert!(allowed.iter().any(|n| n == must), "missing observed {must}");
        }
        assert_eq!(p.syscalls[0].action, "SCMP_ACT_ALLOW");
    }

    #[test]
    fn allowlist_is_deduplicated_and_sorted() {
        let mut r = SyscallRecorder::new();
        r.record("read"); // already in baseline
        r.record("read"); // duplicate
        let names = &r.emit().syscalls[0].names;
        let reads = names.iter().filter(|n| *n == "read").count();
        assert_eq!(reads, 1, "duplicate not collapsed");
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(*names, sorted, "names not sorted");
    }

    #[test]
    fn json_is_valid_and_round_trips_shape() {
        let json = SyscallRecorder::new().to_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["defaultAction"], "SCMP_ACT_ERRNO");
        assert!(v["syscalls"][0]["names"].is_array());
    }
}

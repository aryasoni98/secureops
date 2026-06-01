//! # secureops-ebpf — kernel PEP eBPF programs (PRODUCT.md B.6)
//!
//! Hooks `openat`, `connect`, and `execve` via tracepoints, streams
//! [`SyscallEvent`] records to the Ring-2 daemon over a BPF ring buffer.
//! The daemon keeps a per-PID state window and detects the canonical
//! prompt-injection exfil chain: `openat(.env) → connect(unknown host)`.
//!
//! ## Architecture
//! ```text
//!   kernel tracepoints
//!     sys_enter_openat  ──┐
//!     sys_enter_connect ──┼──► RingBuf(EVENTS) ──► daemon thread ──► per-PID window ──► PDP
//!     sys_enter_execve  ──┘
//! ```
//!
//! ## Build & run
//! ```sh
//! # Install the BPF linker (one-time):
//! cargo install bpf-linker
//!
//! # Compile the eBPF programs (from this directory):
//! CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=bpf-linker \
//!     cargo build --target bpfel-unknown-none -Z build-std=core --release
//!
//! # Run the daemon with the BPF object:
//! SECUREOPS_BPF_OBJ=target/bpfel-unknown-none/release/secureops-ebpf \
//!     cargo run -p secureops-daemon
//! ```

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

// ---------------------------------------------------------------------------
// Shared event type (mirrored in secureops-bpf userspace for ring-buffer read)
// ---------------------------------------------------------------------------

/// Maximum argument string length (path or connect address).
const ARG_LEN: usize = 256;

/// Identifies which kernel hook produced the event.
#[repr(u8)]
pub enum EventKind {
    Openat  = 0,
    Connect = 1,
    Execve  = 2,
}

/// A single in-kernel syscall observation streamed to the daemon.
///
/// Kept `repr(C)` + fixed size so the userspace ring-buffer reader can
/// `transmute` raw bytes directly (PRODUCT.md A.5 frozen wire shape).
#[repr(C)]
pub struct SyscallEvent {
    /// Process id of the originating process (`pid_tgid >> 32`).
    pub pid:  u32,
    /// Thread id (`pid_tgid & 0xFFFFFFFF`).
    pub tid:  u32,
    /// Which syscall family produced this event.
    pub kind: u8,
    /// First string argument: path (openat/execve) or connect(2) addr.
    pub _pad: [u8; 7],
    /// Null-terminated process `comm` (executable short name, 16 bytes).
    pub comm: [u8; 16],
    /// First string argument, zero-padded to `ARG_LEN`.
    pub arg:  [u8; ARG_LEN],
}

// ---------------------------------------------------------------------------
// BPF maps
// ---------------------------------------------------------------------------

/// Ring buffer consumed by the daemon. 512 KiB covers burst traffic without
/// dropping events under normal agent workload.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

// ---------------------------------------------------------------------------
// Tracepoint hooks
// ---------------------------------------------------------------------------

/// `sys_enter_openat` — the "read-a-secret" half of the exfil chain.
///
/// Tracepoint args layout (kernel abi):
/// ```c
/// struct { long nr; long dfd; const char* pathname; int flags; umode_t mode; }
/// ```
/// `pathname` is at byte offset 16.
#[tracepoint(name = "secureops_openat", category = "syscalls")]
pub fn secureops_openat(ctx: TracePointContext) -> u32 {
    emit_event(&ctx, EventKind::Openat, 16).unwrap_or(0)
}

/// `sys_enter_connect` — the "connect-to-unknown-host" half of the exfil chain.
///
/// Tracepoint args layout:
/// ```c
/// struct { long nr; long fd; const struct sockaddr* addr; int addrlen; }
/// ```
/// `addr` is at byte offset 16.
#[tracepoint(name = "secureops_connect", category = "syscalls")]
pub fn secureops_connect(ctx: TracePointContext) -> u32 {
    emit_event(&ctx, EventKind::Connect, 16).unwrap_or(0)
}

/// `sys_enter_execve` — process identity / lineage for the per-PID state window.
///
/// Tracepoint args layout:
/// ```c
/// struct { long nr; const char* filename; const char* const* argv; ... }
/// ```
/// `filename` is at byte offset 8.
#[tracepoint(name = "secureops_execve", category = "syscalls")]
pub fn secureops_execve(ctx: TracePointContext) -> u32 {
    emit_event(&ctx, EventKind::Execve, 8).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build and submit a [`SyscallEvent`] to the ring buffer.
///
/// `arg_offset` is the byte offset in the tracepoint args struct at which the
/// pointer-to-string argument lives (different per syscall).
#[inline(always)]
fn emit_event(ctx: &TracePointContext, kind: EventKind, arg_offset: usize) -> Option<u32> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tid = (pid_tgid & 0xFFFF_FFFF) as u32;

    let mut comm = [0u8; 16];
    unsafe {
        bpf_get_current_comm(
            comm.as_mut_ptr() as *mut core::ffi::c_void,
            16,
        );
    }

    let mut entry = EVENTS.reserve::<SyscallEvent>(0)?;
    unsafe {
        let ev = entry.as_mut_ptr();
        (*ev).pid  = pid;
        (*ev).tid  = tid;
        (*ev).kind = kind as u8;
        (*ev)._pad = [0; 7];
        (*ev).comm = comm;
        (*ev).arg  = [0; ARG_LEN];

        // Read the string pointer from the tracepoint args, then the string itself.
        let ptr: u64 = ctx.read_at(arg_offset).ok()?;
        bpf_probe_read_user(
            (*ev).arg.as_mut_ptr() as *mut core::ffi::c_void,
            (ARG_LEN - 1) as u32,
            ptr as *const core::ffi::c_void,
        );
    }
    entry.submit(0);
    Some(0)
}

// ---------------------------------------------------------------------------
// Required panic handler for no_std binaries.
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

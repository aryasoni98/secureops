//! Canonical detection-pattern sources shared across crates.
//!
//! Only the *pattern strings* live here (no `regex` dependency in core): each
//! consumer compiles them into its own `Regex` table in the form it needs
//! (the checks crate bakes in `(?i)`; the memory-integrity monitor also keeps
//! the bare source string for output-faithful alert messages). Centralizing the
//! strings means the two prompt-injection tables — previously copy-pasted into
//! `secureops-checks` and `secureops-monitors` — can no longer drift apart.
//!
//! The strings are the JS `RegExp.source` of the `/.../i` literals in
//! `auditor.ts` / `monitors/memory-integrity.ts` (the case-insensitive flag is
//! applied by each consumer, not baked into the source — matching `.source`).

/// Prompt-injection regex sources (port of `PROMPT_INJECTION_PATTERNS`). Each is
/// matched case-insensitively by the consumer.
pub const PROMPT_INJECTION_SOURCES: &[&str] = &[
    r"ignore\s+previous\s+instructions",
    r"you\s+are\s+now",
    r"new\s+system\s+prompt",
    r"forward\s+to",
    r"send\s+to",
    r"exfiltrate",
];

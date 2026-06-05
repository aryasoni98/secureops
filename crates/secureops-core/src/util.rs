//! Small, I/O-free helpers shared across the workspace.
//!
//! These were independently re-implemented in the monitors, fs, cli, napi and
//! checks crates (RFC3339 time formatting, epoch-millis parsing, `path.basename`,
//! the unix "group/other-accessible" permission test). Centralizing them here
//! keeps one source of truth so the behaviors cannot drift apart.

use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Current UTC time as an RFC3339 string — the Rust equivalent of TS
/// `new Date().toISOString()` (PRODUCT.md A.5 wire format). On the (impossible)
/// formatting error, falls back to the epoch so an audit never aborts over a clock.
pub fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Current UTC time as epoch milliseconds.
pub fn now_ms() -> i128 {
    OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000
}

/// Parse an RFC3339 timestamp to epoch milliseconds. Returns `None` for
/// unparseable input (callers exclude such entries, matching the TS tool).
pub fn parse_ms(ts: &str) -> Option<i128> {
    OffsetDateTime::parse(ts, &Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp_nanos() / 1_000_000)
}

/// Final path component — port of Node's `path.basename`. Trailing slashes are
/// trimmed first (`"a/b/" -> "b"`); a path with no separator returns itself.
pub fn basename(p: &str) -> &str {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or(p)
}

/// True if a unix permission `mode` grants any group or other access
/// (`mode & 0o077 != 0`) — the credential-permission red flag used by the
/// checks, hardening and credential monitor. `mode` is the permission bits,
/// already masked to `0o777` by the caller.
pub fn is_group_or_other_accessible(mode: u32) -> bool {
    mode & 0o077 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_handles_trailing_slash_and_bare_names() {
        assert_eq!(basename("/a/b/c.json"), "c.json");
        assert_eq!(basename("/a/b/"), "b");
        assert_eq!(basename("bare"), "bare");
        assert_eq!(basename(""), "");
    }

    #[test]
    fn group_or_other_access_matches_octal_mask() {
        assert!(!is_group_or_other_accessible(0o600));
        assert!(is_group_or_other_accessible(0o640)); // group read
        assert!(is_group_or_other_accessible(0o604)); // other read
        assert!(!is_group_or_other_accessible(0o700));
    }

    #[test]
    fn parse_ms_round_trips_and_rejects_garbage() {
        assert_eq!(parse_ms("1970-01-01T00:00:01Z"), Some(1000));
        assert_eq!(parse_ms("not-a-timestamp"), None);
    }
}

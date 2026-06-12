//! Colored console report - faithful port of
//! `secureops/src/reporters/console-reporter.ts` (`formatConsoleReport`).
//!
//! Same ANSI codes, same grade thresholds, same layout and severity grouping
//! order (CRITICAL → HIGH → MEDIUM → LOW → INFO).

use secureops_core::{AuditFinding, AuditReport, Severity};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";
const WHITE: &str = "\x1b[37m";
const BG_RED: &str = "\x1b[41m";
const BG_GREEN: &str = "\x1b[42m";

fn severity_color(s: Severity) -> String {
    match s {
        Severity::Critical => format!("{BG_RED}{WHITE}{BOLD}"),
        Severity::High => format!("{RED}{BOLD}"),
        Severity::Medium => YELLOW.to_string(),
        Severity::Low => BLUE.to_string(),
        Severity::Info => DIM.to_string(),
    }
}

fn severity_icon(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "!!!",
        Severity::High => "!!",
        Severity::Medium => "!",
        Severity::Low => "-",
        Severity::Info => "i",
    }
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

struct Grade {
    letter: char,
    color: String,
}

fn grade(score: u32) -> Grade {
    if score >= 90 {
        Grade {
            letter: 'A',
            color: format!("{BG_GREEN}{WHITE}{BOLD}"),
        }
    } else if score >= 75 {
        Grade {
            letter: 'B',
            color: format!("{GREEN}{BOLD}"),
        }
    } else if score >= 60 {
        Grade {
            letter: 'C',
            color: format!("{YELLOW}{BOLD}"),
        }
    } else if score >= 40 {
        Grade {
            letter: 'D',
            color: format!("{RED}{BOLD}"),
        }
    } else {
        Grade {
            letter: 'F',
            color: format!("{BG_RED}{WHITE}{BOLD}"),
        }
    }
}

fn format_finding(f: &AuditFinding) -> String {
    let color = severity_color(f.severity);
    let icon = severity_icon(f.severity);
    let sev = severity_label(f.severity);
    let fix_label = if f.auto_fixable {
        format!(" {GREEN}[auto-fixable]{RESET}")
    } else {
        String::new()
    };
    let mut lines = vec![
        format!(
            "  {color}[{icon}] {sev}{RESET} {BOLD}{}{RESET}{fix_label}",
            f.title
        ),
        format!(
            "      {DIM}ID: {} | Category: {} | OWASP: {}{RESET}",
            f.id, f.category, f.owasp_asi
        ),
        format!("      {}", f.description),
        format!("      {CYAN}Evidence:{RESET} {}", f.evidence),
        format!("      {GREEN}Fix:{RESET} {}", f.remediation),
    ];
    if !f.references.is_empty() {
        lines.push(format!(
            "      {DIM}References: {}{RESET}",
            f.references.join(", ")
        ));
    }
    lines.join("\n")
}

/// Render an [`AuditReport`] as a colored console string.
pub fn format_console_report(report: &AuditReport) -> String {
    let g = grade(report.score);
    let mut lines: Vec<String> = Vec::new();

    lines.push(String::new());
    lines.push(format!(
        "{BOLD}{MAGENTA}========================================{RESET}"
    ));
    lines.push(format!(
        "{BOLD}{MAGENTA}  SecureOps Security Audit Report{RESET}"
    ));
    lines.push(format!(
        "{BOLD}{MAGENTA}========================================{RESET}"
    ));
    lines.push(String::new());
    lines.push(format!(
        "  {BOLD}Score:{RESET} {} {}/100 ({}) {RESET}",
        g.color, report.score, g.letter
    ));
    lines.push(format!("  {BOLD}Time:{RESET}  {}", report.timestamp));
    lines.push(format!("  {BOLD}Platform:{RESET} {}", report.platform));
    lines.push(format!(
        "  {BOLD}OpenClaw:{RESET} {}",
        report.openclaw_version
    ));
    lines.push(format!("  {BOLD}Mode:{RESET} {}", report.deployment_mode));
    lines.push(String::new());

    let order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    for sev in order {
        let group: Vec<&AuditFinding> = report
            .findings
            .iter()
            .filter(|f| f.severity == sev)
            .collect();
        if group.is_empty() {
            continue;
        }
        let color = severity_color(sev);
        lines.push(format!(
            "{color}--- {} ({}) ---{RESET}",
            severity_label(sev),
            group.len()
        ));
        lines.push(String::new());
        for f in group {
            lines.push(format_finding(f));
            lines.push(String::new());
        }
    }

    lines.push(format!("{BOLD}{MAGENTA}--- Summary ---{RESET}"));
    lines.push(String::new());
    lines.push(format!(
        "  {BG_RED}{WHITE} CRITICAL {RESET} {}",
        report.summary.critical
    ));
    lines.push(format!(
        "  {RED}{BOLD} HIGH     {RESET} {}",
        report.summary.high
    ));
    lines.push(format!(
        "  {YELLOW} MEDIUM   {RESET} {}",
        report.summary.medium
    ));
    lines.push(format!("  {BLUE} LOW      {RESET} {}", report.summary.low));
    lines.push(format!("  {DIM} INFO     {RESET} {}", report.summary.info));
    lines.push(String::new());
    lines.push(format!(
        "  {GREEN}Auto-fixable:{RESET} {} finding(s)",
        report.summary.auto_fixable
    ));
    lines.push(format!(
        "  {DIM}Run \"secureops harden\" to apply automatic fixes{RESET}"
    ));
    lines.push(String::new());

    lines.join("\n")
}

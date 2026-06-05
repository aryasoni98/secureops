//! Access-control category (PRODUCT.md A.4, B.2).
//!
//! Ports `auditAccessControl` from `secureops/src/auditor.ts`: reviews channel
//! DM/group policies and allowlists plus session controls for over-permissive
//! access (SC-AC-\*). Emits the `"access-control"` wire category.

use async_trait::async_trait;
use secureops_core::{
    AuditContext, AuditFinding, AuditOptions, Check, IocDatabase, MaestroLayer, NistAttackType,
    Severity,
};
use std::sync::Arc;

/// Audits access control (`auditAccessControl`). Emits `"access-control"` findings.
pub struct AccessControlCheck {
    db: Arc<IocDatabase>,
}

impl AccessControlCheck {
    pub fn new(db: Arc<IocDatabase>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Check for AccessControlCheck {
    fn category(&self) -> &'static str {
        "access-control"
    }

    async fn run(&self, ctx: &dyn AuditContext, _opts: &AuditOptions) -> Vec<AuditFinding> {
        let _db = &*self.db;
        let mut findings: Vec<AuditFinding> = Vec::new();
        let channels = ctx.channels();

        // AC-001 / AC-002 / AC-003 per channel
        for ch in channels {
            let dm_policy = ch.dm_policy.as_deref();
            let group_policy = ch.group_policy.as_deref();

            // AC-001: Open DM policy
            if dm_policy == Some("open") {
                findings.push(
                    AuditFinding::builder("SC-AC-001", Severity::High, "access-control")
                        .title(format!("Channel \"{}\" has open DM policy", ch.name))
                        .description("Anyone can send direct messages to the agent without pairing, enabling prompt injection attacks.")
                        .evidence(format!("Channel \"{}\": dmPolicy = \"open\"", ch.name))
                        .remediation("Set dmPolicy to \"pairing\" for this channel")
                        .auto_fixable(true)
                        .owasp_asi("ASI01")
                        .maestro(MaestroLayer::L3)
                        .nist(NistAttackType::Evasion)
                        .build(),
                );
            }

            // AC-002: Open group policy
            if group_policy == Some("open") {
                findings.push(
                    AuditFinding::builder("SC-AC-002", Severity::High, "access-control")
                        .title(format!("Channel \"{}\" has open group policy", ch.name))
                        .description("Anyone in the group can interact with the agent without restrictions.")
                        .evidence(format!("Channel \"{}\": groupPolicy = \"open\"", ch.name))
                        .remediation("Set groupPolicy to \"allowlist\" for this channel")
                        .auto_fixable(true)
                        .owasp_asi("ASI01")
                        .maestro(MaestroLayer::L3)
                        .nist(NistAttackType::Evasion)
                        .build(),
                );
            }

            // AC-003: Wildcard allowlist
            if ch
                .allowlist
                .as_ref()
                .is_some_and(|a| a.iter().any(|e| e == "*"))
            {
                findings.push(
                    AuditFinding::builder("SC-AC-003", Severity::Medium, "access-control")
                        .title(format!("Channel \"{}\" has wildcard in allowlist", ch.name))
                        .description("Using \"*\" in the allowlist effectively makes the channel open to everyone.")
                        .evidence(format!("Channel \"{}\": allowlist contains \"*\"", ch.name))
                        .remediation("Replace \"*\" with specific user identifiers")
                        .owasp_asi("ASI09")
                        .maestro(MaestroLayer::L3)
                        .nist(NistAttackType::Evasion)
                        .build(),
                );
            }
        }

        // AC-004: Pairing disabled without allowlist
        for ch in channels {
            let dm_policy = ch.dm_policy.as_deref();
            let allowlist_empty = ch.allowlist.as_ref().map_or(true, |a| a.is_empty());
            if dm_policy != Some("pairing") && allowlist_empty {
                let dm_scope_str = ch.dm_policy.as_deref().unwrap_or("undefined");
                findings.push(
                    AuditFinding::builder("SC-AC-004", Severity::High, "access-control")
                        .title(format!("Channel \"{}\" has no pairing and no allowlist", ch.name))
                        .description("Neither pairing nor an allowlist is configured, leaving the channel unprotected.")
                        .evidence(format!(
                            "Channel \"{}\": dmPolicy = \"{}\", allowlist empty",
                            ch.name, dm_scope_str
                        ))
                        .remediation("Set dmPolicy to \"pairing\" or configure an allowlist")
                        .auto_fixable(true)
                        .owasp_asi("ASI01")
                        .maestro(MaestroLayer::L3)
                        .nist(NistAttackType::Evasion)
                        .build(),
                );
            }
        }

        // AC-005: Session DM scope
        let dm_scope = ctx
            .config()
            .session
            .as_ref()
            .and_then(|s| s.dm_scope.as_deref());
        if dm_scope != Some("per-channel-peer") && channels.len() > 1 {
            findings.push(
                AuditFinding::builder("SC-AC-005", Severity::Medium, "access-control")
                    .title("Session DM scope not isolated per user")
                    .description("session.dmScope is not \"per-channel-peer\". With multiple users, context may leak between conversations.")
                    .evidence(format!(
                        "session.dmScope = \"{}\", channels: {}",
                        dm_scope.unwrap_or("undefined"),
                        channels.len()
                    ))
                    .remediation("Set session.dmScope to \"per-channel-peer\"")
                    .auto_fixable(true)
                    .owasp_asi("ASI09")
                    .maestro(MaestroLayer::L3)
                    .nist(NistAttackType::Evasion)
                    .build(),
            );
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockAuditContext;
    use secureops_core::{ChannelConfig, OpenClawConfig, SessionConfig};
    use std::sync::Arc;

    fn check() -> AccessControlCheck {
        AccessControlCheck::new(Arc::new(IocDatabase::default()))
    }

    fn opts() -> AuditOptions {
        AuditOptions {
            deep: false,
            fix: false,
            json: false,
        }
    }

    fn channel(
        name: &str,
        dm: Option<&str>,
        group: Option<&str>,
        allowlist: Option<Vec<&str>>,
    ) -> ChannelConfig {
        ChannelConfig {
            name: name.to_string(),
            dm_policy: dm.map(|s| s.to_string()),
            group_policy: group.map(|s| s.to_string()),
            allowlist: allowlist.map(|v| v.iter().map(|s| s.to_string()).collect()),
        }
    }

    #[tokio::test]
    async fn open_policies_and_wildcard_fire() {
        // Open DM, open group, wildcard allowlist -> AC-001, AC-002, AC-003.
        let ctx = MockAuditContext::new().with_channels(vec![channel(
            "slack",
            Some("open"),
            Some("open"),
            Some(vec!["*"]),
        )]);
        let findings = check().run(&ctx, &opts()).await;
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"SC-AC-001"));
        assert!(ids.contains(&"SC-AC-002"));
        assert!(ids.contains(&"SC-AC-003"));
        // dmPolicy "open" != "pairing" with non-empty allowlist -> AC-004 should NOT fire.
        assert!(!ids.contains(&"SC-AC-004"));
        let f1 = findings.iter().find(|f| f.id == "SC-AC-001").unwrap();
        assert_eq!(f1.severity, Severity::High);
        assert_eq!(f1.title, "Channel \"slack\" has open DM policy");
        assert_eq!(f1.evidence, "Channel \"slack\": dmPolicy = \"open\"");
    }

    #[tokio::test]
    async fn no_pairing_no_allowlist_fires_ac004() {
        let ctx = MockAuditContext::new().with_channels(vec![channel("sms", None, None, None)]);
        let findings = check().run(&ctx, &opts()).await;
        let f = findings.iter().find(|f| f.id == "SC-AC-004").unwrap();
        assert_eq!(f.severity, Severity::High);
        assert_eq!(
            f.evidence,
            "Channel \"sms\": dmPolicy = \"undefined\", allowlist empty"
        );
        assert!(f.auto_fixable);
    }

    #[tokio::test]
    async fn dm_scope_fires_ac005_with_multiple_channels() {
        let ctx = MockAuditContext::new()
            .with_config(OpenClawConfig {
                session: Some(SessionConfig {
                    dm_scope: Some("global".to_string()),
                }),
                ..Default::default()
            })
            .with_channels(vec![
                channel("a", Some("pairing"), None, Some(vec!["u1"])),
                channel("b", Some("pairing"), None, Some(vec!["u2"])),
            ]);
        let findings = check().run(&ctx, &opts()).await;
        let f = findings.iter().find(|f| f.id == "SC-AC-005").unwrap();
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.evidence, "session.dmScope = \"global\", channels: 2");
    }

    #[tokio::test]
    async fn clean_config_yields_nothing() {
        // pairing DM, allowlist group, no wildcard, per-channel-peer scope, >1 channel.
        let ctx = MockAuditContext::new()
            .with_config(OpenClawConfig {
                session: Some(SessionConfig {
                    dm_scope: Some("per-channel-peer".to_string()),
                }),
                ..Default::default()
            })
            .with_channels(vec![
                channel("a", Some("pairing"), Some("allowlist"), Some(vec!["u1"])),
                channel("b", Some("pairing"), Some("allowlist"), Some(vec!["u2"])),
            ]);
        let findings = check().run(&ctx, &opts()).await;
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }
}

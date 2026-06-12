//! Gateway exposure category (PRODUCT.md A.4, B.2).
//!
//! Ports `auditGateway` from `secureops/src/auditor.ts`: inspects the
//! `gateway` config block - bind host, auth mode, TLS, mDNS advertisement,
//! control-UI exposure, reverse-proxy trust - for the most checks of any
//! category (SC-GW-\*). Deep mode actively probes the gateway and browser
//! relay ports via `secureops_fs::probe_port`. MAESTRO mostly L4.

use async_trait::async_trait;
use secureops_core::{
    AuditContext, AuditFinding, AuditOptions, Check, IocDatabase, MaestroLayer, NistAttackType,
    Severity,
};
use std::sync::Arc;
use std::time::Duration;

/// Audits gateway/network exposure (`auditGateway`). Emits `"gateway"` findings.
pub struct GatewayCheck {
    db: Arc<IocDatabase>,
}

impl GatewayCheck {
    pub fn new(db: Arc<IocDatabase>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Check for GatewayCheck {
    fn category(&self) -> &'static str {
        "gateway"
    }

    async fn run(&self, ctx: &dyn AuditContext, opts: &AuditOptions) -> Vec<AuditFinding> {
        // IOC db is intentionally unused by this category, but the field/new
        // are kept so the registry constructs every check uniformly.
        let _db = &*self.db;

        let deep = opts.deep;
        let mut findings: Vec<AuditFinding> = Vec::new();
        let gw = ctx.config().gateway.as_ref();

        // GW-001: Gateway bind mode
        // gw?.bind !== 'loopback'
        let bind = gw.and_then(|g| g.bind.as_deref());
        if bind != Some("loopback") {
            findings.push(
                AuditFinding::builder("SC-GW-001", Severity::Critical, "gateway")
                    .title("Gateway not bound to loopback")
                    .description(format!(
                        "Gateway is bound to \"{}\" instead of loopback. This exposes the gateway to network attacks.",
                        bind.unwrap_or("all interfaces")
                    ))
                    .evidence(format!("gateway.bind = \"{}\"", bind.unwrap_or("undefined")))
                    .remediation("Set gateway.bind to \"loopback\" in openclaw.json")
                    .auto_fixable(true)
                    .references(["CVE-2026-25253"])
                    .owasp_asi("ASI03")
                    .maestro(MaestroLayer::L4)
                    .nist(NistAttackType::Evasion)
                    .build(),
            );
        }

        // GW-002: Gateway auth mode (supports legacy "authToken" and modern "auth.mode")
        // authMode = gw?.auth?.mode ?? (gw?.authToken ? 'token' : undefined)
        let auth_token = gw.and_then(|g| g.auth_token.as_deref());
        let auth_mode: Option<&str> = gw
            .and_then(|g| g.auth.as_ref())
            .and_then(|a| a.mode.as_deref())
            .or({
                // gw?.authToken ? 'token' : undefined  (truthy check: empty string is falsy)
                match auth_token {
                    Some(t) if !t.is_empty() => Some("token"),
                    _ => None,
                }
            });
        if auth_mode != Some("password") && auth_mode != Some("token") {
            findings.push(
                AuditFinding::builder("SC-GW-002", Severity::Critical, "gateway")
                    .title("Gateway authentication disabled")
                    .description(format!(
                        "Gateway authentication mode is \"{}\". Anyone with network access can control this instance.",
                        auth_mode.unwrap_or("none")
                    ))
                    .evidence(format!("gateway.auth.mode = \"{}\"", auth_mode.unwrap_or("undefined")))
                    .remediation("Set gateway.auth.mode to \"password\" or \"token\" and configure a strong credential")
                    .auto_fixable(true)
                    .references(["CVE-2026-25253"])
                    .owasp_asi("ASI03")
                    .maestro(MaestroLayer::L4)
                    .nist(NistAttackType::Evasion)
                    .build(),
            );
        }

        // GW-003: Auth token length (supports legacy "authToken" and modern "auth.token")
        // token = gw?.auth?.token ?? gw?.auth?.password ?? gw?.authToken ?? ''
        let token: &str = gw
            .and_then(|g| g.auth.as_ref())
            .and_then(|a| a.token.as_deref())
            .or_else(|| {
                gw.and_then(|g| g.auth.as_ref())
                    .and_then(|a| a.password.as_deref())
            })
            .or(auth_token)
            .unwrap_or("");
        if auth_mode == Some("token") || auth_mode == Some("password") {
            let token_len = token.chars().count();
            if token_len > 0 && token_len < 32 {
                findings.push(
                    AuditFinding::builder("SC-GW-003", Severity::Medium, "gateway")
                        .title("Weak gateway authentication token")
                        .description(format!(
                            "Gateway auth token/password is only {} characters. Minimum 32 recommended.",
                            token_len
                        ))
                        .evidence(format!("Token length: {} characters", token_len))
                        .remediation("Generate a token of at least 32 characters using a CSPRNG")
                        .auto_fixable(true)
                        .owasp_asi("ASI03")
                        .maestro(MaestroLayer::L4)
                        .nist(NistAttackType::Evasion)
                        .build(),
                );
            }
        }

        // GW-004: Gateway port accessible from non-localhost (deep probe)
        // gatewayPort = gw?.port ?? 18789
        let gateway_port: u16 = gw.and_then(|g| g.port).unwrap_or(18789);
        if deep {
            let listening =
                secureops_fs::probe_port(gateway_port, "127.0.0.1", Duration::from_millis(2000))
                    .await;
            if listening {
                // Port is open - check if bind is loopback-only
                let bind_mode = bind.unwrap_or("all");
                let is_loopback =
                    bind_mode == "loopback" || bind_mode == "127.0.0.1" || bind_mode == "localhost";
                findings.push(
                    AuditFinding::builder(
                        "SC-GW-004",
                        if is_loopback { Severity::Low } else { Severity::High },
                        "gateway",
                    )
                    .title(if is_loopback {
                        "Gateway port open on loopback only"
                    } else {
                        "Gateway port open and bound to non-loopback interface"
                    })
                    .description(if is_loopback {
                        format!(
                            "Port {} is listening on loopback (localhost). This is the recommended configuration.",
                            gateway_port
                        )
                    } else {
                        format!(
                            "Port {} is listening and bound to \"{}\". It may be accessible from other machines on the network.",
                            gateway_port, bind_mode
                        )
                    })
                    .evidence(format!("Port: {}, Bind: {}, Status: open", gateway_port, bind_mode))
                    .remediation(if is_loopback {
                        "No action needed - loopback binding is secure"
                    } else {
                        "Set gateway.bind to \"loopback\" to restrict access to localhost only"
                    })
                    .auto_fixable(!is_loopback)
                    .owasp_asi("ASI05")
                    .maestro(MaestroLayer::L4)
                    .nist(NistAttackType::Evasion)
                    .build(),
                );
            } else {
                findings.push(
                    AuditFinding::builder("SC-GW-004", Severity::Info, "gateway")
                        .title("Gateway port not listening")
                        .description(format!(
                            "Port {} is not currently accepting connections. Gateway may not be running.",
                            gateway_port
                        ))
                        .evidence(format!("Port: {}, Status: closed/unreachable", gateway_port))
                        .remediation("Start the gateway if it should be running")
                        .owasp_asi("ASI05")
                        .maestro(MaestroLayer::L4)
                        .nist(NistAttackType::Evasion)
                        .build(),
                );
            }
        } else {
            findings.push(
                AuditFinding::builder("SC-GW-004", Severity::Info, "gateway")
                    .title("Gateway port accessibility check")
                    .description(format!(
                        "Port {} remote accessibility requires deep scan mode (--deep) for active probing.",
                        gateway_port
                    ))
                    .evidence(format!("Port: {}", gateway_port))
                    .remediation("Run audit with --deep flag for active network probing")
                    .owasp_asi("ASI05")
                    .maestro(MaestroLayer::L4)
                    .nist(NistAttackType::Evasion)
                    .build(),
            );
        }

        // GW-005: Browser relay port
        // browserRelayPort = (gw?.port ?? 18789) - 897
        let browser_relay_port: u16 = gw.and_then(|g| g.port).unwrap_or(18789) - 897;
        if deep {
            let listening = secureops_fs::probe_port(
                browser_relay_port,
                "127.0.0.1",
                Duration::from_millis(2000),
            )
            .await;
            if listening {
                let bind_mode = bind.unwrap_or("all");
                let is_loopback =
                    bind_mode == "loopback" || bind_mode == "127.0.0.1" || bind_mode == "localhost";
                findings.push(
                    AuditFinding::builder(
                        "SC-GW-005",
                        if is_loopback { Severity::Low } else { Severity::Medium },
                        "gateway",
                    )
                    .title(if is_loopback {
                        "Browser relay port open on loopback only"
                    } else {
                        "Browser relay port open and may be network-accessible"
                    })
                    .description(if is_loopback {
                        format!(
                            "Browser relay port {} is listening on loopback. This is safe.",
                            browser_relay_port
                        )
                    } else {
                        format!(
                            "Browser relay port {} is listening and bound to \"{}\". The browser automation surface may be reachable from the network.",
                            browser_relay_port, bind_mode
                        )
                    })
                    .evidence(format!(
                        "Port: {}, Bind: {}, Status: open",
                        browser_relay_port, bind_mode
                    ))
                    .remediation(if is_loopback {
                        "No action needed"
                    } else {
                        "Set gateway.bind to \"loopback\" to restrict the browser relay to localhost"
                    })
                    .auto_fixable(!is_loopback)
                    .owasp_asi("ASI05")
                    .maestro(MaestroLayer::L4)
                    .nist(NistAttackType::Evasion)
                    .build(),
                );
            } else {
                findings.push(
                    AuditFinding::builder("SC-GW-005", Severity::Info, "gateway")
                        .title("Browser relay port not listening")
                        .description(format!(
                            "Browser relay port {} is not currently accepting connections.",
                            browser_relay_port
                        ))
                        .evidence(format!(
                            "Port: {}, Status: closed/unreachable",
                            browser_relay_port
                        ))
                        .remediation("No action needed if browser automation is not in use")
                        .owasp_asi("ASI05")
                        .maestro(MaestroLayer::L4)
                        .nist(NistAttackType::Evasion)
                        .build(),
                );
            }
        } else {
            findings.push(
                AuditFinding::builder("SC-GW-005", Severity::Info, "gateway")
                    .title("Browser relay port check")
                    .description(format!(
                        "Browser relay port {} accessibility requires deep scan mode.",
                        browser_relay_port
                    ))
                    .evidence(format!("Port: {}", browser_relay_port))
                    .remediation("Run audit with --deep flag for active network probing")
                    .owasp_asi("ASI05")
                    .maestro(MaestroLayer::L4)
                    .nist(NistAttackType::Evasion)
                    .build(),
            );
        }

        // GW-006: TLS enabled
        // !gw?.tls?.enabled
        let tls_enabled = gw
            .and_then(|g| g.tls.as_ref())
            .and_then(|t| t.enabled)
            .unwrap_or(false);
        if !tls_enabled {
            findings.push(
                AuditFinding::builder("SC-GW-006", Severity::Medium, "gateway")
                    .title("TLS not enabled on gateway")
                    .description("Gateway traffic is unencrypted. Credentials and conversation data are transmitted in plaintext.")
                    .evidence("gateway.tls is not configured")
                    .remediation("Configure gateway.tls with a valid certificate and key")
                    .owasp_asi("ASI03")
                    .maestro(MaestroLayer::L4)
                    .nist(NistAttackType::Evasion)
                    .build(),
            );
        }

        // GW-007: mDNS/Bonjour mode
        // gw?.mdns && gw.mdns.mode !== 'minimal'
        if let Some(mdns) = gw.and_then(|g| g.mdns.as_ref()) {
            let mdns_mode = mdns.mode.as_deref();
            if mdns_mode != Some("minimal") {
                findings.push(
                    AuditFinding::builder("SC-GW-007", Severity::Medium, "gateway")
                        .title("mDNS broadcasting in full mode")
                        .description("mDNS is broadcasting sensitive instance information on the local network.")
                        // `gateway.mdns.mode = "${gw.mdns.mode}"` - an absent mode
                        // renders as "undefined" in a JS template literal.
                        .evidence(format!("gateway.mdns.mode = \"{}\"", mdns_mode.unwrap_or("undefined")))
                        .remediation("Manually set gateway.mdns.mode to \"minimal\" (not auto-fixable - key not in OpenClaw config schema)")
                        .owasp_asi("ASI05")
                        .maestro(MaestroLayer::L4)
                        .nist(NistAttackType::Evasion)
                        .build(),
                );
            }
        }

        // GW-008: Reverse proxy without trustedProxies
        // gw?.bind !== 'loopback' && (!gw?.trustedProxies || gw.trustedProxies.length === 0)
        let trusted_proxies_empty = gw
            .and_then(|g| g.trusted_proxies.as_ref())
            .map(|p| p.is_empty())
            .unwrap_or(true);
        if bind != Some("loopback") && trusted_proxies_empty {
            findings.push(
                AuditFinding::builder("SC-GW-008", Severity::Critical, "gateway")
                    .title("Reverse proxy without trustedProxies configuration")
                    .description("Gateway is network-accessible without trustedProxies set. All connections appear as localhost, bypassing authentication.")
                    .evidence(format!(
                        "gateway.bind = \"{}\", trustedProxies = []",
                        bind.unwrap_or("all")
                    ))
                    .remediation("Set gateway.trustedProxies to the IP of your reverse proxy, e.g., [\"127.0.0.1\"]")
                    .auto_fixable(true)
                    .references(["CVE-2026-25253"])
                    .owasp_asi("ASI03")
                    .maestro(MaestroLayer::L4)
                    .nist(NistAttackType::Evasion)
                    .build(),
            );
        }

        // GW-009: dangerouslyDisableDeviceAuth
        // gw?.controlUi?.dangerouslyDisableDeviceAuth === true
        let disable_device_auth = gw
            .and_then(|g| g.control_ui.as_ref())
            .and_then(|c| c.dangerously_disable_device_auth)
            .unwrap_or(false);
        if disable_device_auth {
            findings.push(
                AuditFinding::builder("SC-GW-009", Severity::Critical, "gateway")
                    .title("Device authentication disabled on Control UI")
                    .description("dangerouslyDisableDeviceAuth is enabled, bypassing all device-level authentication for the Control UI.")
                    .evidence("gateway.controlUi.dangerouslyDisableDeviceAuth = true")
                    .remediation("Set gateway.controlUi.dangerouslyDisableDeviceAuth to false")
                    .auto_fixable(true)
                    .owasp_asi("ASI03")
                    .maestro(MaestroLayer::L4)
                    .nist(NistAttackType::Evasion)
                    .build(),
            );
        }

        // GW-010: allowInsecureAuth
        // gw?.controlUi?.allowInsecureAuth === true
        let allow_insecure_auth = gw
            .and_then(|g| g.control_ui.as_ref())
            .and_then(|c| c.allow_insecure_auth)
            .unwrap_or(false);
        if allow_insecure_auth {
            findings.push(
                AuditFinding::builder("SC-GW-010", Severity::Medium, "gateway")
                    .title("Insecure authentication allowed on Control UI")
                    .description(
                        "allowInsecureAuth is enabled, allowing weaker authentication methods.",
                    )
                    .evidence("gateway.controlUi.allowInsecureAuth = true")
                    .remediation("Set gateway.controlUi.allowInsecureAuth to false")
                    .auto_fixable(true)
                    .owasp_asi("ASI03")
                    .maestro(MaestroLayer::L4)
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
    use secureops_core::{
        ControlUiConfig, GatewayAuth, GatewayConfig, MdnsConfig, OpenClawConfig, TlsConfig,
    };

    fn db() -> Arc<IocDatabase> {
        Arc::new(IocDatabase::default())
    }

    fn ids(findings: &[AuditFinding]) -> Vec<String> {
        findings.iter().map(|f| f.id.clone()).collect()
    }

    /// A fully-hardened config (loopback, token auth, TLS, minimal mDNS,
    /// trusted proxies, secure Control UI) should emit no config-based GW
    /// findings - only the non-deep GW-004/GW-005 informational placeholders.
    #[tokio::test]
    async fn hardened_config_emits_only_info_placeholders() {
        let config = OpenClawConfig {
            gateway: Some(GatewayConfig {
                bind: Some("loopback".to_string()),
                port: Some(18789),
                auth: Some(GatewayAuth {
                    mode: Some("token".to_string()),
                    token: Some("a".repeat(40)),
                    password: None,
                }),
                tls: Some(TlsConfig {
                    enabled: Some(true),
                    ..Default::default()
                }),
                mdns: Some(MdnsConfig {
                    mode: Some("minimal".to_string()),
                }),
                control_ui: Some(ControlUiConfig {
                    dangerously_disable_device_auth: Some(false),
                    allow_insecure_auth: Some(false),
                }),
                trusted_proxies: Some(vec!["127.0.0.1".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = MockAuditContext::new().with_config(config);
        let opts = AuditOptions {
            deep: false,
            fix: false,
            json: false,
        };
        let findings = GatewayCheck::new(db()).run(&ctx, &opts).await;
        let got = ids(&findings);

        // Only the non-deep informational placeholders should fire.
        assert_eq!(got, vec!["SC-GW-004", "SC-GW-005"]);
        for f in &findings {
            assert_eq!(f.severity, Severity::Info);
        }
        // Browser relay port = 18789 - 897 = 17892.
        let relay = findings.iter().find(|f| f.id == "SC-GW-005").unwrap();
        assert!(relay.evidence.contains("17892"));
    }

    /// A wide-open config should fire the critical exposure findings.
    #[tokio::test]
    async fn open_config_fires_critical_findings() {
        let config = OpenClawConfig {
            gateway: Some(GatewayConfig {
                bind: Some("0.0.0.0".to_string()),
                auth: Some(GatewayAuth {
                    mode: Some("none".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = MockAuditContext::new().with_config(config);
        let opts = AuditOptions::default();
        let findings = GatewayCheck::new(db()).run(&ctx, &opts).await;
        let got = ids(&findings);

        // bind != loopback -> GW-001; auth mode "none" -> GW-002;
        // no TLS -> GW-006; bind != loopback + no trustedProxies -> GW-008.
        assert!(got.contains(&"SC-GW-001".to_string()));
        assert!(got.contains(&"SC-GW-002".to_string()));
        assert!(got.contains(&"SC-GW-006".to_string()));
        assert!(got.contains(&"SC-GW-008".to_string()));

        let gw001 = findings.iter().find(|f| f.id == "SC-GW-001").unwrap();
        assert_eq!(gw001.severity, Severity::Critical);
        assert_eq!(gw001.evidence, "gateway.bind = \"0.0.0.0\"");
        assert_eq!(gw001.references, vec!["CVE-2026-25253".to_string()]);
    }

    /// Weak token (token mode, <32 chars) fires GW-003; device-auth disabled
    /// and insecure-auth allowed fire GW-009 / GW-010.
    #[tokio::test]
    async fn weak_token_and_control_ui_flags() {
        let config = OpenClawConfig {
            gateway: Some(GatewayConfig {
                bind: Some("loopback".to_string()),
                auth: Some(GatewayAuth {
                    mode: Some("token".to_string()),
                    token: Some("short".to_string()),
                    ..Default::default()
                }),
                tls: Some(TlsConfig {
                    enabled: Some(true),
                    ..Default::default()
                }),
                control_ui: Some(ControlUiConfig {
                    dangerously_disable_device_auth: Some(true),
                    allow_insecure_auth: Some(true),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = MockAuditContext::new().with_config(config);
        let opts = AuditOptions::default();
        let findings = GatewayCheck::new(db()).run(&ctx, &opts).await;
        let got = ids(&findings);

        assert!(got.contains(&"SC-GW-003".to_string()));
        assert!(got.contains(&"SC-GW-009".to_string()));
        assert!(got.contains(&"SC-GW-010".to_string()));

        let gw003 = findings.iter().find(|f| f.id == "SC-GW-003").unwrap();
        assert_eq!(gw003.severity, Severity::Medium);
        assert_eq!(gw003.evidence, "Token length: 5 characters");
        // No GW-001 (loopback) and no GW-008 (loopback) for a loopback bind.
        assert!(!got.contains(&"SC-GW-001".to_string()));
        assert!(!got.contains(&"SC-GW-008".to_string()));
    }

    /// mDNS present with a non-minimal mode fires GW-007 with the mode echoed.
    #[tokio::test]
    async fn mdns_full_mode_fires_gw007() {
        let config = OpenClawConfig {
            gateway: Some(GatewayConfig {
                bind: Some("loopback".to_string()),
                auth: Some(GatewayAuth {
                    mode: Some("token".to_string()),
                    token: Some("a".repeat(40)),
                    ..Default::default()
                }),
                tls: Some(TlsConfig {
                    enabled: Some(true),
                    ..Default::default()
                }),
                mdns: Some(MdnsConfig {
                    mode: Some("full".to_string()),
                }),
                trusted_proxies: Some(vec!["127.0.0.1".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = MockAuditContext::new().with_config(config);
        let opts = AuditOptions::default();
        let findings = GatewayCheck::new(db()).run(&ctx, &opts).await;

        let gw007 = findings.iter().find(|f| f.id == "SC-GW-007").unwrap();
        assert_eq!(gw007.severity, Severity::Medium);
        assert_eq!(gw007.evidence, "gateway.mdns.mode = \"full\"");
    }
}

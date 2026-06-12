// SecureOps landing — Quick start terminal, Tiers, Final CTA, Footer
const { motion: moC, useReducedMotion: useRMC } = window.FramerMotion || {};

/* ------------------------------ QUICK START ------------------------------- */
function SOQuickstart() {
  const steps = [
    ["secureops init", "Initialized SecureOps state — keystore + starter openclaw.json"],
    ["secureops audit", "Score 84/100 · 3 findings (1 high, 2 medium)"],
    ["secureops harden", "4 fixes applied · backup 2026-06-10T07-44 · rollback available"],
    ["secureops audit --json --threshold 80", "exit 0 — pipeline passes"],
  ];
  return (
    <section className="wk-section" id="quickstart" data-screen-label="Quick start">
      <div className="wk-wrap">
        <div className="wk-shead">
          <Reveal><span className="wk-shead__eyebrow">Quick start</span></Reveal>
          <Reveal delay={0.05}><h2 className="wk-shead__title">Audited and hardened in four commands.</h2></Reveal>
        </div>
        <Reveal>
          <div className="so-term">
            <div className="so-term__bar">
              <span className="d" style={{ background: "rgba(244,63,94,0.8)" }}></span>
              <span className="d" style={{ background: "rgba(245,158,11,0.8)" }}></span>
              <span className="d" style={{ background: "rgba(34,197,94,0.8)" }}></span>
              <span className="title">secureops — zsh</span>
            </div>
            <Stagger className="so-term__body" gap={0.14} y={14}>
              {steps.map(([cmd, out], i) => (
                <div key={cmd}>
                  <div><span className="p">$ </span>{cmd}{i === steps.length - 1 && <span className="so-caret" aria-hidden="true"></span>}</div>
                  <div className="out">{out}</div>
                </div>
              ))}
            </Stagger>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

/* --------------------------------- TIERS ---------------------------------- */
function SOTiers() {
  const tiers = [
    {
      name: "Host-local", badge: "Free forever", pop: true,
      desc: "The full CLI + daemon. No license, no account.",
      items: ["secureops CLI + daemon", "Audit · harden · monitors · kill switch", "Tested in CI on Linux + macOS"],
    },
    {
      name: "Platform", badge: "Self-hosted",
      desc: "Multi-tenant scanning for whole fleets.",
      items: ["Multi-tenant API + scanner worker", "Postgres · Redis · MinIO · WebSocket hub", "React dashboard + first-run wizard"],
    },
    {
      name: "Intelligence", badge: "Self-hosted",
      desc: "Findings that explain themselves.",
      items: ["Attack-path graph + blast radius", "LLM bug-hunt loop (BYO model)", "LinUCB finding ranking"],
    },
    {
      name: "Enterprise", badge: "Self-hosted",
      desc: "For orgs with auditors of their own.",
      items: ["SSO (OIDC) + license server", "Signed IR export", "eBPF + Neo4j Helm subcharts"],
    },
  ];
  return (
    <section className="wk-section" id="tiers" data-screen-label="Tiers">
      <div className="wk-wrap">
        <div className="wk-shead">
          <Reveal><span className="wk-shead__eyebrow">Tiers</span></Reveal>
          <Reveal delay={0.05}><h2 className="wk-shead__title">Start host-local. Scale self-hosted.</h2></Reveal>
          <Reveal delay={0.1}><p className="wk-shead__sub">The community tier needs no license at all — and every tier runs on your own infrastructure. No SaaS dependency.</p></Reveal>
        </div>
        <Stagger className="so-tiers" gap={0.08}>
          {tiers.map((t) => (
            <div key={t.name} className={`wk-price-card ${t.pop ? "wk-price-card--pop" : ""}`} style={{ height: "100%" }}>
              {t.pop && <span className="pop">✦ {t.badge}</span>}
              <h3 style={{ marginTop: t.pop ? 8 : 0 }}>{t.name}</h3>
              {!t.pop && (
                <span style={{ alignSelf: "flex-start", fontFamily: "var(--font-mono)", fontSize: 10.5, fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--fg-muted)", border: "1px solid var(--border)", borderRadius: 999, padding: "3px 10px", marginTop: -6 }}>{t.badge}</span>
              )}
              <div className="desc">{t.desc}</div>
              <ul>
                {t.items.map((it) => (
                  <li key={it}><Icon name="check" size={15} />{it}</li>
                ))}
              </ul>
              {t.pop && (
                <div className="cta">
                  <Button variant="ghost" size="md" href="https://github.com/aryasoni98/secureops" className="" ariaLabel="Install the CLI">Install the CLI</Button>
                </div>
              )}
            </div>
          ))}
        </Stagger>
      </div>
    </section>
  );
}

/* ------------------------------- FINAL CTA --------------------------------- */
function SOFinalCTA() {
  return (
    <section className="wk-finalcta" data-screen-label="Final CTA">
      <div className="wk-finalcta__conic" aria-hidden="true"></div>
      <div className="so-finalcta__shield" aria-hidden="true"><Icon name="shield" size={520} stroke={0.6} /></div>
      <div className="wk-finalcta__inner">
        <Reveal>
          <h2 className="wk-finalcta__title">Assume the agent is already compromised. <span className="wk-text-gradient wk-text-gradient--animate">Then secure it anyway.</span></h2>
        </Reveal>
        <Reveal delay={0.1}>
          <p className="wk-finalcta__sub">One cargo install between your agent and a very bad week.</p>
        </Reveal>
        <Reveal delay={0.18}>
          <div className="so-finalcta-actions">
            <SOCopyCmd cmd="git clone https://github.com/aryasoni98/secureops" small={true} />
            <Button variant="grad" size="md" icon={<Icon name="github" size={15} />} trailing={<Icon name="arrow" size={14} />} href="https://github.com/aryasoni98/secureops" data-cursor-hot>Star on GitHub</Button>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

/* --------------------------------- FOOTER ---------------------------------- */
function SOFooter() {
  return (
    <footer className="so-footer" data-screen-label="Footer">
      <div className="wk-wrap">
        <div className="so-footer__inner">
          <SOMark size={26} />
          <div className="so-footer__links">
            <a href="https://github.com/aryasoni98/secureops">GitHub</a>
            <a href="https://github.com/aryasoni98/secureops">Docs</a>
            <a href="https://github.com/aryasoni98/secureops/blob/master/SECURITY.md">Security</a>
            <a href="https://github.com/aryasoni98/secureops/blob/master/LICENSE">MIT License</a>
          </div>
          <div className="so-footer__tag">secureops · out-of-band security for AI agents · 26 Rust crates · MIT</div>
        </div>
      </div>
    </footer>
  );
}

Object.assign(window, { SOQuickstart, SOTiers, SOFinalCTA, SOFooter });

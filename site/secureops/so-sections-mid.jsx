// SecureOps landing — Problem comparison, Trust rings, Features bento
const { motion: moB, AnimatePresence: APB, useInView: useIVB, useReducedMotion: useRMB } = window.FramerMotion || {};

/* ------------------------------- PROBLEM --------------------------------- */
function SOProblem() {
  return (
    <section className="wk-section" id="problem" data-screen-label="Problem">
      <div className="wk-wrap">
        <div className="wk-shead">
          <Reveal><span className="wk-shead__eyebrow">The problem</span></Reveal>
          <Reveal delay={0.05}><h2 className="wk-shead__title">Guardrails inside a compromised process are theater.</h2></Reveal>
          <Reveal delay={0.1}><p className="wk-shead__sub">Agents read secrets, call tools, and reach the network. Whoever owns the agent owns its in-process defenses too.</p></Reveal>
        </div>
        <Stagger className="wk-compare" gap={0.1}>
          <div className="wk-compare__col wk-compare__col--old">
            <span className="wk-compare__eyebrow">Today</span>
            <h3 className="wk-compare__title">In-process guardrails</h3>
            <p className="wk-compare__desc">The defense lives inside the thing being attacked.</p>
            <div className="wk-compare__stage">
              <ul className="so-checklist so-checklist--dim">
                <li><span className="ic ic--bad"><Icon name="x" size={12} /></span>Attacker disables the hook that would have blocked them</li>
                <li><span className="ic ic--bad"><Icon name="x" size={12} /></span>Prompt injection rewrites the policy the agent enforces on itself</li>
                <li><span className="ic ic--bad"><Icon name="x" size={12} /></span>Exfiltration looks like a normal tool call</li>
                <li><span className="ic ic--bad"><Icon name="x" size={12} /></span>Logs live in the same process — trivially forged</li>
              </ul>
            </div>
          </div>
          <div className="wk-compare__col wk-compare__col--new">
            <span className="wk-compare__eyebrow wk-compare__eyebrow--blue">With SecureOps</span>
            <h3 className="wk-compare__title">Out-of-band enforcement</h3>
            <p className="wk-compare__desc">A privileged daemon that doesn't care what the agent thinks.</p>
            <div className="wk-compare__stage">
              <ul className="so-checklist">
                <li><span className="ic ic--good"><Icon name="check" size={12} /></span>The daemon survives agent compromise</li>
                <li><span className="ic ic--good"><Icon name="check" size={12} /></span>Fail-closed egress: HTTPS allowlist, 403, zero bytes on deny</li>
                <li><span className="ic ic--good"><Icon name="check" size={12} /></span>Kill switch halts everything from outside</li>
                <li><span className="ic ic--good"><Icon name="check" size={12} /></span>Hash-chained, ed25519-signed audit log — tamper-evident</li>
              </ul>
            </div>
          </div>
          <div className="wk-compare__col wk-compare__col--reaction">
            <span className="wk-compare__eyebrow wk-compare__eyebrow--spark">The review</span>
            <div className="wk-compare__stage">
              <div>
                <p className="wk-quote" style={{ fontSize: "clamp(22px, 2vw, 28px)" }}>"wait — the guardrails survive the breach?"</p>
                <div className="so-reaction-avs" aria-hidden="true">
                  {["#1E64E6", "#22C55E", "#F97316", "#0B2768"].map((c) => <span key={c} style={{ background: c }}></span>)}
                </div>
                <p className="wk-micro" style={{ marginTop: 12 }}>— every security review, eventually</p>
              </div>
            </div>
          </div>
        </Stagger>
      </div>
    </section>
  );
}

/* ------------------------------ TRUST RINGS ------------------------------- */
function SORings() {
  const cards = [
    { n: 0, k: "0", title: "Audit", desc: "56 checks across nine OWASP-ASI categories. A 0–100 score, and a CI gate that fails the pipeline below your threshold." },
    { n: 1, k: "1", title: "Harden", desc: "Auto-fix for gateway, credentials, config, Docker, and network — every change backed up first, with one-command rollback." },
    { n: 2, k: "2", title: "Enforce", desc: "The privileged daemon: egress proxy, runtime monitors, kill switch, and a Rego + Cedar policy engine every PEP asks before acting." },
  ];
  return (
    <section className="wk-section" id="architecture" data-screen-label="Architecture">
      <div className="so-arch">
        <div className="wk-wrap">
          <div className="wk-shead">
            <Reveal><span className="wk-shead__eyebrow">Architecture</span></Reveal>
            <Reveal delay={0.05}><h2 className="wk-shead__title">Three trust rings.</h2></Reveal>
            <Reveal delay={0.1}><p className="wk-shead__sub">Each ring assumes the one inside it has already failed.</p></Reveal>
          </div>
          <div className="so-arch-grid">
            <Reveal>
              <div className="so-rings" aria-label="Diagram: agent process surrounded by three concentric trust rings">
                <div className="so-ring so-ring--2"></div>
                <div className="so-ring so-ring--1"></div>
                <div className="so-ring so-ring--0"></div>
                <span className="so-ring-label so-ring-label--2">ring 2 · enforce</span>
                <span className="so-ring-label so-ring-label--1">ring 1 · harden</span>
                <span className="so-ring-label so-ring-label--0">ring 0 · audit</span>
                <div className="so-rings-center">
                  <span className="chip"><Icon name="bot" size={26} /></span>
                  <span className="lbl">agent process</span>
                </div>
              </div>
            </Reveal>
            <Stagger className="so-ring-cards" gap={0.1}>
              {cards.map((c) => (
                <div key={c.k} className={`so-ring-card so-ring-card--${c.k}`}>
                  <span className="num">RING {c.k}</span>
                  <div>
                    <h3>{c.title}</h3>
                    <p>{c.desc}</p>
                  </div>
                </div>
              ))}
            </Stagger>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------ FEATURES BENTO ----------------------------- */
const soFeedLines = [
  { host: "api.anthropic.com:443", ok: true },
  { host: "github.com:443", ok: true },
  { host: "pastebin.com:443", ok: false },
  { host: "crates.io:443", ok: true },
  { host: "198.51.100.7:8443", ok: false },
  { host: "api.openai.com:443", ok: true },
  { host: "docs.rs:443", ok: true },
];

function SOBentoProxy() {
  const reduce = useRMB();
  const [tick, setTick] = React.useState(0);
  React.useEffect(() => {
    if (reduce) return;
    const id = setInterval(() => setTick((t) => t + 1), 2000);
    return () => clearInterval(id);
  }, [reduce]);
  const rows = Array.from({ length: 5 }).map((_, i) => soFeedLines[(tick + i) % soFeedLines.length]);
  return (
    <div className="tile tile--big">
      <span className="ic-chip"><Icon name="shield" size={16} /></span>
      <h3>Fail-closed egress proxy.</h3>
      <p>HTTP CONNECT allowlist on 127.0.0.1:8889. Deny means a 403 — and zero bytes leave the host.</p>
      <div className="so-feed" style={{ marginTop: 16 }}>
        <APB initial={false}>
          {rows.map((r) => (
            <moB.div key={r.host} layout
              initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -14 }}
              transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
              className={`so-feed__row ${r.ok ? "" : "so-feed__row--deny"}`}>
              <span style={{ color: "var(--fg-subtle)" }}>CONNECT</span>
              <span className="host">{r.host}</span>
              <span className={`so-feed__verdict so-feed__verdict--${r.ok ? "allow" : "deny"}`}>{r.ok ? "ALLOW" : "DENY · 0 B"}</span>
            </moB.div>
          ))}
        </APB>
      </div>
    </div>
  );
}

function SOBentoAudit() {
  return (
    <div className="tile tile--tall">
      <span className="ic-chip"><Icon name="search" size={16} /></span>
      <h3>Security audit, scored.</h3>
      <p>Nine OWASP-ASI categories, 56 SC-* checks, MAESTRO cross-layer risk.</p>
      <div style={{ marginTop: "auto" }}>
        <div style={{ fontWeight: 700, fontSize: 56, letterSpacing: "-0.03em", lineHeight: 1, fontFeatureSettings: '"tnum"', background: "var(--wk-gradient)", WebkitBackgroundClip: "text", backgroundClip: "text", color: "transparent" }}>
          <SOCount to={84} /><span style={{ fontSize: 24 }}>/100</span>
        </div>
        <div style={{ fontSize: 12.5, color: "var(--fg-muted)", marginTop: 8 }}>3 findings · 1 high · 2 medium</div>
        <div style={{ marginTop: 14, padding: "10px 12px", borderRadius: 10, background: "var(--bg-muted)", fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--fg-muted)" }}>
          audit --json --threshold 80 <b style={{ color: "var(--wk-green-700)" }}>→ exit 0</b>
        </div>
      </div>
    </div>
  );
}

function SOBentoLog() {
  const blocks = [
    ["#4821", "9f2c…e1d7"],
    ["#4822", "b04a…77f3"],
    ["#4823", "0de1…a9c2"],
    ["#4824", "f63b…41e8"],
  ];
  return (
    <div className="tile tile--wide" style={{ display: "grid", gridTemplateColumns: "1fr 1.1fr", gap: 16, alignItems: "center" }}>
      <div>
        <span className="ic-chip"><Icon name="layers" size={16} /></span>
        <h3>Tamper-evident log.</h3>
        <p>SHA-256 hash chain, ed25519 signatures, signed incident export for IR.</p>
      </div>
      <div>
        <div className="so-chain" aria-hidden="true">
          {blocks.map(([id, hash], i) => (
            <React.Fragment key={id}>
              {i > 0 && <span className="so-chain__link"></span>}
              <span className="so-chain__block"><b>{id}</b>{hash}</span>
            </React.Fragment>
          ))}
        </div>
        <div style={{ fontSize: 11.5, color: "var(--fg-muted)", marginTop: 10, fontFamily: "var(--font-mono)" }}>verify: chain intact · 4,824 entries</div>
      </div>
    </div>
  );
}

function SOBentoKill() {
  const [armed, setArmed] = React.useState(false);
  return (
    <div className="tile tile--sq" style={armed ? { background: "var(--wk-spark-wash)", borderColor: "var(--wk-spark-wash-border)" } : undefined}>
      <span className="ic-chip" style={armed ? { background: "var(--wk-spark-500)", color: "#fff" } : undefined}><Icon name="zap" size={16} /></span>
      <h3 style={{ fontSize: 17 }}>Kill switch.</h3>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 12 }}>
        <button className={`so-switch ${armed ? "on" : ""}`} onClick={() => setArmed(!armed)} aria-pressed={armed} aria-label="Toggle kill switch demo" data-cursor-hot>
          <span className="knob"></span>
        </button>
        {armed && <span className="so-pulse" aria-hidden="true"></span>}
        <span style={{ fontSize: 12.5, fontWeight: 600, color: armed ? "var(--wk-spark-text)" : "var(--fg-muted)" }}>{armed ? "Agent halted" : "Try me"}</span>
      </div>
      <p style={{ marginTop: 12, fontSize: 12.5 }}>{armed ? "The daemon refuses to start while active." : "Halts the agent from outside, in one command."}</p>
    </div>
  );
}

function SOBentoPolicy() {
  return (
    <div className="tile tile--sq">
      <span className="ic-chip"><Icon name="target" size={16} /></span>
      <h3 style={{ fontSize: 17 }}>Policy engine.</h3>
      <p style={{ marginTop: 4 }}>Rego + Cedar PDP with decision cache and hot reload.</p>
      <div style={{ marginTop: 12, padding: "9px 11px", borderRadius: 9, background: "var(--bg-muted)", fontFamily: "var(--font-mono)", fontSize: 11 }}>
        pep → pdp: tool.exec<br />
        <b style={{ color: "var(--wk-green-700)" }}>decision: allow</b> <span style={{ color: "var(--fg-subtle)" }}>· 0.2 ms cached</span>
      </div>
    </div>
  );
}

function SOBentoMonitors() {
  const bars = [38, 52, 44, 61, 47, 70, 55, 63, 41, 58, 49, 66];
  return (
    <div className="tile tile--wide" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, alignItems: "center" }}>
      <div>
        <span className="ic-chip"><Icon name="bell" size={16} /></span>
        <h3>Runtime monitors.</h3>
        <p>Cost circuit-breaker, credential access, memory integrity, skill IOC scan — always on.</p>
      </div>
      <div style={{ background: "var(--bg-muted)", borderRadius: 12, padding: 14 }}>
        <div style={{ fontSize: 11, color: "var(--fg-muted)", marginBottom: 8, fontFamily: "var(--font-mono)" }}>spend vs. circuit-breaker cap</div>
        <div style={{ display: "flex", alignItems: "flex-end", gap: 5, height: 64 }}>
          {bars.map((h, i) => (
            <span key={i} style={{ flex: 1, height: `${h}%`, background: "var(--wk-gradient)", borderRadius: "3px 3px 0 0", opacity: i === bars.length - 1 ? 1 : 0.6 }}></span>
          ))}
        </div>
        <div style={{ fontSize: 11.5, color: "var(--fg-muted)", marginTop: 8 }}>$4.12 of $25.00 · breaker closed</div>
      </div>
    </div>
  );
}

function SOBento() {
  const also = [
    ["check", "CI/CD gate"],
    ["grid", "Hardening + rollback"],
    ["bot", "WASM sandbox"],
    ["chart", "Kernel PEP (eBPF)"],
  ];
  return (
    <section className="wk-section" id="features" data-screen-label="Features">
      <div className="wk-wrap">
        <div className="wk-shead">
          <Reveal><span className="wk-shead__eyebrow">Host-local features</span></Reveal>
          <Reveal delay={0.05}><h2 className="wk-shead__title">One binary. Ten layers of defense.</h2></Reveal>
          <Reveal delay={0.1}><p className="wk-shead__sub">Everything below ships in the free host-local tier — no platform required.</p></Reveal>
        </div>
        <Reveal>
          <div className="wk-bento" onMouseMove={(e) => {
            const t = e.target.closest ? e.target.closest(".tile") : null;
            if (!t) return;
            const r = t.getBoundingClientRect();
            t.style.setProperty("--mx", e.clientX - r.left + "px");
            t.style.setProperty("--my", e.clientY - r.top + "px");
          }}>
            <SOBentoProxy />
            <SOBentoAudit />
            <SOBentoLog />
            <SOBentoKill />
            <SOBentoPolicy />
            <SOBentoMonitors />
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="so-also">
            <span className="lead">Also in the box</span>
            {also.map(([ic, label]) => (
              <span className="chip" key={label}><Icon name={ic} size={14} />{label}</span>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}

Object.assign(window, { SOProblem, SORings, SOBento });

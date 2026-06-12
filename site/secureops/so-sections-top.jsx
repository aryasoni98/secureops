// SecureOps landing — Nav, Hero, Threat marquee, Metrics band
// Composes Wooak DS primitives (Icon, Button, Reveal, Stagger) from the DS bundle.
const { motion: moA, useScroll: useScrollA, useTransform: useTA, useInView: useIVA, useReducedMotion: useRMA, useMotionValue: useMVA, useSpring: useSpringA } = window.FramerMotion || {};

/* ------------------------------ BRAND MARK ------------------------------ */
function SOMark({ size = 28, word = true }) {
  return (
    <span className="so-mark">
      <span className="so-mark__chip" style={{ width: size, height: size }}><Icon name="shield" size={size * 0.58} stroke={2} /></span>
      {word && <span className="so-mark__word">secureops</span>}
    </span>
  );
}

/* --------------------------- COPY-COMMAND PILL --------------------------- */
function SOCopyCmd({ cmd, small = false }) {
  const [copied, setCopied] = React.useState(false);
  const onCopy = () => {
    if (navigator.clipboard) navigator.clipboard.writeText(cmd).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };
  return (
    <button className={`so-cmd ${small ? "so-cmd--sm" : ""}`} onClick={onCopy} data-cursor-hot aria-label={`Copy command: ${cmd}`}>
      <span className="p">$</span>
      <span>{cmd}</span>
      <span className="hint">{copied ? "copied" : "copy"}</span>
    </button>
  );
}

/* ----------------------------- ANIMATED COUNT ---------------------------- */
function SOCount({ to, duration = 1600, format = (n) => n.toLocaleString() }) {
  const ref = React.useRef(null);
  const inView = useIVA(ref, { once: true });
  const reduce = useRMA();
  const [val, setVal] = React.useState(0);
  React.useEffect(() => {
    if (!inView) return;
    const frozen = document.documentElement.classList.contains("so-frozen");
    if (reduce || frozen || to === 0) { setVal(to); return; }
    let raf, start;
    const tick = (t) => {
      if (!start) start = t;
      const k = Math.min((t - start) / duration, 1);
      setVal(Math.round(to * (1 - Math.pow(1 - k, 4))));
      if (k < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    // Snap to the final value even if animation frames are throttled.
    const safety = setTimeout(() => setVal(to), duration + 600);
    return () => { cancelAnimationFrame(raf); clearTimeout(safety); };
  }, [inView, reduce]);
  return <span ref={ref}>{format(val)}</span>;
}

/* --------------------------------- NAV ---------------------------------- */
function SONav({ theme, setTheme }) {
  const links = [
    { label: "Why", href: "#problem" },
    { label: "Architecture", href: "#architecture" },
    { label: "Features", href: "#features" },
    { label: "Quick start", href: "#quickstart" },
    { label: "Tiers", href: "#tiers" },
  ];
  return (
    <nav className="wk-nav">
      <div className="wk-wrap wk-nav__inner">
        <a href="#top" aria-label="SecureOps home"><SOMark size={27} /></a>
        <div className="wk-nav__center">
          {links.map((l) => (
            <a key={l.label} className="wk-nav__link" href={l.href} data-cursor-hot>{l.label}</a>
          ))}
        </div>
        <div className="wk-nav__right">
          <button
            aria-label="Toggle theme"
            className="wk-btn wk-btn--ghost wk-btn--sm"
            style={{ width: 38, height: 38, padding: 0, borderRadius: "50%" }}
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            data-cursor-hot
          >
            <Icon name={theme === "dark" ? "sun" : "moon"} size={16} />
          </button>
          <div className="wk-nav__divider"></div>
          <a className="wk-btn wk-btn--link wk-btn--sm" href="https://github.com/aryasoni98/secureops" data-cursor-hot>Docs</a>
          <Button variant="grad" size="sm" icon={<Icon name="github" size={15} />} href="https://github.com/aryasoni98/secureops" ariaLabel="Star on GitHub">Star on GitHub</Button>
        </div>
      </div>
    </nav>
  );
}

/* ----------------------------- HERO VISUAL ------------------------------- */
function SOHeroVisual() {
  const reduce = useRMA();
  const { scrollY } = useScrollA();
  const yOrbs = useTA(scrollY, [0, 600], [0, -80]);
  const yFrame = useTA(scrollY, [0, 600], [0, -40]);
  const yNotifA = useTA(scrollY, [0, 600], [0, -12]);
  const yNotifB = useTA(scrollY, [0, 600], [0, 30]);
  const C = 2 * Math.PI * 30;

  // Cursor-driven 3D tilt (springs back to the resting -8°/2° pose)
  const rx = useMVA(2), ry = useMVA(-8);
  const srx = useSpringA(rx, { stiffness: 120, damping: 16 });
  const sry = useSpringA(ry, { stiffness: 120, damping: 16 });
  const onTilt = (e) => {
    if (reduce) return;
    const r = e.currentTarget.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width - 0.5;
    const py = (e.clientY - r.top) / r.height - 0.5;
    ry.set(-8 + px * 11);
    rx.set(2 - py * 8);
  };
  const resetTilt = () => { ry.set(-8); rx.set(2); };

  return (
    <div className="wk-hero__visual" onPointerMove={onTilt} onPointerLeave={resetTilt}>
      <moA.div className="wk-hero__orbs" style={{ y: yOrbs }} aria-hidden="true">
        <div className="wk-hero__orb" style={{ left: "-6%", top: "8%", background: "#4A9CFF" }}></div>
        <div className="wk-hero__orb" style={{ right: "-10%", bottom: "5%", background: "#4ADE80" }}></div>
        <div className="wk-hero__orb" style={{ left: "32%", top: "58%", width: 200, height: 200, background: "#F97316", opacity: 0.3 }}></div>
      </moA.div>

      <moA.div className="wk-hero__frame" style={{ y: yFrame, rotateX: srx, rotateY: sry, transformPerspective: 1300 }}>
        <div className="wk-hero__frame-bar">
          <div className="dots"><span></span><span></span><span></span></div>
          <span className="url">secureops daemon · 127.0.0.1:8889</span>
        </div>
        <div style={{ padding: 18, display: "grid", gridTemplateColumns: "1.35fr 1fr", gap: 12, height: "calc(100% - 42px)" }}>
          {/* left column */}
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div className="wk-widget" style={{ background: "var(--bg-muted)" }}>
              <div className="wk-w-title">Audit score</div>
              <div style={{ display: "flex", alignItems: "center", gap: 16, marginTop: 8 }}>
                <svg width="74" height="74" viewBox="0 0 74 74" aria-hidden="true">
                  <defs>
                    <linearGradient id="soScoreGrad" x1="0" x2="1">
                      <stop offset="0%" stopColor="#1E64E6"></stop><stop offset="100%" stopColor="#22C55E"></stop>
                    </linearGradient>
                  </defs>
                  <circle cx="37" cy="37" r="30" stroke="var(--border)" strokeWidth="6.5" fill="none"></circle>
                  <circle cx="37" cy="37" r="30" stroke="url(#soScoreGrad)" strokeWidth="6.5" fill="none"
                    strokeDasharray={C} strokeDashoffset={C * (1 - 0.84)} strokeLinecap="round"
                    style={{ transform: "rotate(-90deg)", transformOrigin: "37px 37px" }}></circle>
                  <text x="37" y="42" textAnchor="middle" fontWeight="700" fontSize="17" fill="var(--fg)" fontFamily="Inter">84</text>
                </svg>
                <div style={{ fontSize: 12, color: "var(--fg-muted)", lineHeight: 1.5 }}>
                  <b style={{ color: "var(--fg)" }}>3 findings</b><br />1 high · 2 medium<br />56 SC-* checks run
                </div>
              </div>
            </div>
            <div className="wk-widget" style={{ background: "var(--bg-muted)", flex: 1 }}>
              <div className="wk-w-title" style={{ marginBottom: 8 }}>Runtime monitors</div>
              <div className="so-mon">
                <div className="so-mon__row"><span className="so-mon__dot"></span>Cost circuit-breaker<span className="v">$4.12 / $25</span></div>
                <div className="so-mon__row"><span className="so-mon__dot"></span>Memory integrity<span className="v">clean</span></div>
                <div className="so-mon__row"><span className="so-mon__dot" style={{ background: "var(--warning)" }}></span>Credential access<span className="v">2 events</span></div>
                <div className="so-mon__row"><span className="so-mon__dot"></span>Skill IOC scan<span className="v">0 hits</span></div>
              </div>
            </div>
          </div>
          {/* right column */}
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div className="wk-widget" style={{ background: "var(--bg-muted)" }}>
              <div className="wk-w-title">Egress · last 60 s</div>
              <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                <div className="wk-w-big" style={{ background: "var(--wk-gradient)", WebkitBackgroundClip: "text", backgroundClip: "text", color: "transparent" }}>142</div>
                <span style={{ fontSize: 11.5, color: "var(--fg-muted)" }}>allowed</span>
              </div>
              <div style={{ marginTop: 8, height: 6, borderRadius: 99, background: "var(--border)", overflow: "hidden", display: "flex" }}>
                <span style={{ width: "97%", background: "var(--wk-gradient)" }}></span>
                <span style={{ width: "3%", background: "var(--danger)" }}></span>
              </div>
              <div style={{ fontSize: 11.5, color: "var(--fg-muted)", marginTop: 8 }}>3 denied · 0 bytes out</div>
            </div>
            <div className="wk-widget" style={{ background: "var(--bg-muted)", flex: 1 }}>
              <div className="wk-w-title" style={{ marginBottom: 10 }}>Kill switch</div>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span className="so-switch" aria-hidden="true"><span className="knob"></span></span>
                <span style={{ fontSize: 12, fontWeight: 600, whiteSpace: "nowrap" }}>Standing by</span>
              </div>
              <div style={{ fontSize: 11.5, color: "var(--fg-muted)", marginTop: 10, lineHeight: 1.5 }}>One command halts the agent from outside the process.</div>
            </div>
          </div>
        </div>
      </moA.div>

      <moA.div className="wk-hero__notif" style={{ y: yNotifA, top: 10, right: -6, width: 236 }}>
        <div className="av" style={{ background: "var(--wk-spark-wash)", display: "grid", placeItems: "center" }}>
          <Icon name="x" size={15} style={{ color: "var(--wk-spark-500)" }} />
        </div>
        <div>
          <div className="t">Egress denied · pastebin.com</div>
          <div className="s">403 · 0 bytes left the host</div>
        </div>
      </moA.div>

      <moA.div className="wk-hero__notif" style={{ y: yNotifB, bottom: 24, left: -12, width: 224 }}>
        <div className="av" style={{ background: "var(--wk-gradient)", color: "#fff", display: "grid", placeItems: "center" }}>
          <Icon name="check" size={15} />
        </div>
        <div>
          <div className="t">CI gate passed</div>
          <div className="s">score 84 ≥ threshold 80 · exit 0</div>
        </div>
      </moA.div>
    </div>
  );
}

/* --------------------------------- HERO ---------------------------------- */
function SOHero() {
  const reduce = useRMA();
  const sparks = [{ x: 12, y: 24, d: 4 }, { x: 46, y: 70, d: 6 }, { x: 88, y: 18, d: 5 }];
  return (
    <header className="wk-hero" id="top" data-screen-label="Hero">
      <div className="wk-wrap">
        {!reduce && sparks.map((s, i) => (
          <moA.div key={i} className="wk-spark" style={{ left: `${s.x}%`, top: `${s.y}%` }}
            animate={{ y: [0, -22, 0], x: [0, 12, 0], opacity: [0.25, 0.8, 0.25] }}
            transition={{ duration: 6 + s.d, repeat: Infinity, ease: "easeInOut", delay: i * 0.7 }}
          />
        ))}
        <Reveal>
          <span className="wk-hero__pill"><Icon name="shield" size={13} /> v0.0.2 beta · 26 Rust crates · MIT <span className="shimmer"></span></span>
        </Reveal>
        <div className="wk-hero__grid">
          <div>
            <SOWordReveal className="wk-hero__title"
              words={[{ t: "Out-of-band", grad: true }, { t: "security" }, { t: "for" }, { t: "AI" }, { t: "agents." }]} />
            <Reveal delay={0.12}>
              <p className="wk-hero__sub">When an agent is compromised, in-process guardrails die with it. SecureOps enforces from a privileged daemon outside the agent process — it keeps working after the agent is owned.</p>
            </Reveal>
            <Reveal delay={0.18}>
              <div className="wk-hero__ctas">
                <SOCopyCmd cmd="cargo install secureops-cli" />
                <SOMagnetic>
                  <Button variant="grad" size="lg" icon={<Icon name="github" size={16} />} trailing={<Icon name="arrow" size={15} />} href="https://github.com/aryasoni98/secureops" data-cursor-hot>GitHub</Button>
                </SOMagnetic>
              </div>
            </Reveal>
            <Reveal delay={0.28}>
              <div className="wk-hero__trust">
                <div className="wk-hero__trust-label">In the box</div>
                <div className="so-badges" style={{ marginTop: 14 }}>
                  <span>fail-closed egress proxy</span>
                  <span>kill switch</span>
                  <span>tamper-evident log</span>
                  <span>Linux + macOS</span>
                </div>
              </div>
            </Reveal>
          </div>
          <Reveal delay={0.1}>
            <SOHeroVisual />
          </Reveal>
        </div>
      </div>
    </header>
  );
}

/* ----------------------------- THREAT MARQUEE ----------------------------- */
function SOMarquee() {
  const threats = [
    "Memory poisoning", "Tool misuse", "Privilege compromise", "Resource overload",
    "Cascading hallucination", "Intent manipulation", "Deceptive behaviors",
    "Repudiation", "Identity spoofing",
  ];
  const reel = [...threats, ...threats];
  return (
    <section data-screen-label="Threat marquee">
      <div className="so-marquee-label">Audited against the nine OWASP agentic threat categories</div>
      <div className="wk-marquee" style={{ paddingTop: 26, paddingBottom: 26 }}>
        <div className="wk-marquee__reel">
          {reel.map((t, i) => (
            <span className="so-threat" key={i}>
              <span className="n">T{(i % threats.length) + 1}</span>
              <span className="t">{t}</span>
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ------------------------------ METRICS BAND ------------------------------ */
function SOMetrics() {
  const stats = [
    { v: 26, suffix: "", label: "Rust crates in the workspace" },
    { v: 285, suffix: "", label: "tests in CI, Linux + macOS" },
    { v: 56, suffix: "", label: "SC-* audit checks" },
    { v: 0, suffix: "", label: "bytes out on egress deny" },
  ];
  return (
    <section className="wk-section" data-screen-label="Metrics">
      <div className="wk-metrics">
        <div className="wk-wrap">
          <Stagger className="wk-metrics__grid" gap={0.08}>
            {stats.map((s) => (
              <div key={s.label}>
                <div className="wk-metrics__num"><SOCount to={s.v} />{s.suffix}</div>
                <div className="wk-metrics__label">{s.label}</div>
              </div>
            ))}
          </Stagger>
        </div>
      </div>
    </section>
  );
}

Object.assign(window, { SOMark, SOCopyCmd, SOCount, SONav, SOHero, SOMarquee, SOMetrics });

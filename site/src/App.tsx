// SecureOps landing page — single-page infographic-style site.
// Dark glassmorphism + bento grid + Framer Motion scroll reveals.
// Content mirrors README.md / PRODUCT.md; update both together.

import { useState } from "react";
import { motion, useScroll, useSpring, type Variants } from "framer-motion";

const REPO = "https://github.com/aryasoni98/secureops";
const DOCS = "./docs/";

// ---------------------------------------------------------------- motion ----

const fadeUp: Variants = {
  hidden: { opacity: 0, y: 32 },
  show: { opacity: 1, y: 0, transition: { duration: 0.6, ease: "easeOut" } },
};

const stagger: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08 } },
};

function Reveal({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <motion.div
      className={className}
      variants={fadeUp}
      initial="hidden"
      whileInView="show"
      viewport={{ once: true, margin: "-80px" }}
    >
      {children}
    </motion.div>
  );
}

// ----------------------------------------------------------------- atoms ----

function SectionTitle({ kicker, title, sub }: { kicker: string; title: string; sub?: string }) {
  return (
    <Reveal className="text-center mb-12">
      <p className="text-emerald-400 font-mono text-sm tracking-widest uppercase mb-3">{kicker}</p>
      <h2 className="text-3xl md:text-5xl font-bold tracking-tight text-white">{title}</h2>
      {sub && <p className="text-slate-400 mt-4 max-w-2xl mx-auto text-lg">{sub}</p>}
    </Reveal>
  );
}

function GlassCard({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <motion.div
      variants={fadeUp}
      whileHover={{ y: -4, transition: { duration: 0.2 } }}
      className={`rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur p-6 ${className}`}
    >
      {children}
    </motion.div>
  );
}

function CopyCommand({ cmd }: { cmd: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(cmd).catch(() => {});
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      className="group flex items-center gap-3 rounded-xl border border-slate-700 bg-slate-900/80 px-5 py-3 font-mono text-sm text-slate-200 hover:border-emerald-500/60 transition-colors"
    >
      <span className="text-emerald-400">$</span>
      <span>{cmd}</span>
      <span className="ml-2 text-xs text-slate-500 group-hover:text-emerald-400">
        {copied ? "copied!" : "copy"}
      </span>
    </button>
  );
}

// ------------------------------------------------------------------ hero ----

function Hero() {
  return (
    <header className="relative min-h-screen flex flex-col items-center justify-center px-6 overflow-hidden">
      <div className="blob w-[34rem] h-[34rem] bg-emerald-500 -top-32 -left-32" />
      <div className="blob w-[28rem] h-[28rem] bg-cyan-500 top-1/3 -right-24" style={{ animationDelay: "-6s" }} />
      <div className="blob w-[24rem] h-[24rem] bg-violet-600 bottom-0 left-1/4" style={{ animationDelay: "-12s" }} />

      <motion.div
        variants={stagger}
        initial="hidden"
        animate="show"
        className="relative z-10 text-center max-w-4xl"
      >
        <motion.p
          variants={fadeUp}
          className="inline-block rounded-full border border-emerald-500/40 bg-emerald-500/10 px-4 py-1.5 text-sm text-emerald-300 font-mono mb-6"
        >
          v0.0.1 beta · 26 Rust crates · MIT
        </motion.p>
        <motion.h1
          variants={fadeUp}
          className="text-5xl md:text-7xl font-extrabold tracking-tight text-white leading-tight"
        >
          Out-of-band security
          <br />
          <span className="bg-gradient-to-r from-emerald-400 via-cyan-400 to-violet-400 bg-clip-text text-transparent">
            for AI agents
          </span>
        </motion.h1>
        <motion.p variants={fadeUp} className="mt-6 text-lg md:text-xl text-slate-400 max-w-2xl mx-auto">
          When an agent is compromised, in-process guardrails can be switched off by the attacker.
          SecureOps moves enforcement <b className="text-slate-200">outside the agent process</b> —
          into a privileged daemon that keeps working even after the agent is owned.
        </motion.p>
        <motion.div variants={fadeUp} className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
          <CopyCommand cmd="cargo install secureops-cli" />
          <div className="flex gap-3">
            <a
              href={REPO}
              className="rounded-xl bg-emerald-500 px-6 py-3 font-semibold text-slate-950 hover:bg-emerald-400 transition-colors"
            >
              GitHub →
            </a>
            <a
              href={DOCS}
              className="rounded-xl border border-slate-700 px-6 py-3 font-semibold text-slate-200 hover:border-slate-500 transition-colors"
            >
              Docs
            </a>
          </div>
        </motion.div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1, transition: { delay: 1.2 } }}
        className="absolute bottom-8 text-slate-600 text-sm"
      >
        ↓ scroll
      </motion.div>
    </header>
  );
}

// ----------------------------------------------------------------- stats ----

const STATS = [
  { value: "26", label: "Rust crates" },
  { value: "285", label: "tests in CI" },
  { value: "56", label: "SC-* audit checks" },
  { value: "9", label: "OWASP-ASI categories" },
  { value: "0", label: "bytes on egress deny" },
];

function Stats() {
  return (
    <motion.section
      variants={stagger}
      initial="hidden"
      whileInView="show"
      viewport={{ once: true }}
      className="relative z-10 mx-auto max-w-5xl px-6 -mt-10 grid grid-cols-2 md:grid-cols-5 gap-4"
    >
      {STATS.map((s) => (
        <motion.div
          key={s.label}
          variants={fadeUp}
          className="rounded-2xl border border-slate-800 bg-slate-900/70 backdrop-blur p-5 text-center"
        >
          <div className="text-3xl font-extrabold text-emerald-400">{s.value}</div>
          <div className="text-xs text-slate-400 mt-1">{s.label}</div>
        </motion.div>
      ))}
    </motion.section>
  );
}

// --------------------------------------------------------------- problem ----

function Problem() {
  return (
    <section className="mx-auto max-w-6xl px-6 py-28">
      <SectionTitle
        kicker="The problem"
        title="Guardrails inside a compromised process are theater"
        sub="AI agents read secrets, call tools, and reach the network. The attacker who owns the agent owns its in-process defenses too."
      />
      <motion.div
        variants={stagger}
        initial="hidden"
        whileInView="show"
        viewport={{ once: true }}
        className="grid md:grid-cols-2 gap-6"
      >
        <GlassCard className="border-rose-500/30">
          <h3 className="font-bold text-rose-300 text-lg mb-3">In-process guardrails</h3>
          <ul className="space-y-2 text-slate-400 text-sm">
            <li>✗ Attacker disables the hook that would have blocked them</li>
            <li>✗ Prompt injection rewrites the policy the agent enforces on itself</li>
            <li>✗ Exfiltration looks like a normal tool call</li>
            <li>✗ Logs live in the same process — trivially forged</li>
          </ul>
        </GlassCard>
        <GlassCard className="border-emerald-500/30">
          <h3 className="font-bold text-emerald-300 text-lg mb-3">SecureOps: out-of-band enforcement</h3>
          <ul className="space-y-2 text-slate-400 text-sm">
            <li>✓ Privileged daemon survives agent compromise</li>
            <li>✓ Fail-closed egress proxy: HTTPS allowlist, 403, 0 bytes on deny</li>
            <li>✓ Kill switch halts everything from outside</li>
            <li>✓ Hash-chained, ed25519-signed audit log — tamper-evident</li>
          </ul>
        </GlassCard>
      </motion.div>
    </section>
  );
}

// ----------------------------------------------------------- trust rings ----

const RINGS = [
  { ring: "Ring 0", title: "Audit", desc: "56 checks, 0–100 score, CI gate", color: "border-emerald-500/60 text-emerald-300" },
  { ring: "Ring 1", title: "Harden", desc: "Auto-fix with backups + rollback", color: "border-cyan-500/60 text-cyan-300" },
  { ring: "Ring 2", title: "Enforce", desc: "Daemon: proxy, monitors, kill switch, PDP/PEP", color: "border-violet-500/60 text-violet-300" },
];

function TrustRings() {
  return (
    <section className="mx-auto max-w-6xl px-6 py-28">
      <SectionTitle
        kicker="Architecture"
        title="Three trust rings"
        sub="Each ring assumes the one inside it has already failed."
      />
      <div className="grid md:grid-cols-2 gap-12 items-center">
        <Reveal className="relative mx-auto w-72 h-72 md:w-96 md:h-96">
          {/* Concentric animated rings */}
          <div className="absolute inset-0 rounded-full border-2 border-dashed border-violet-500/40 ring-spin" />
          <div className="absolute inset-10 rounded-full border-2 border-dashed border-cyan-500/40 ring-spin" style={{ animationDirection: "reverse" }} />
          <div className="absolute inset-20 rounded-full border-2 border-dashed border-emerald-500/40 ring-spin" />
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <div className="text-3xl">🤖</div>
              <div className="text-xs text-slate-500 mt-1 font-mono">agent process</div>
            </div>
          </div>
        </Reveal>
        <motion.div variants={stagger} initial="hidden" whileInView="show" viewport={{ once: true }} className="space-y-4">
          {RINGS.map((r) => (
            <GlassCard key={r.ring} className={r.color.split(" ")[0]}>
              <div className="flex items-baseline gap-3">
                <span className={`font-mono text-xs ${r.color.split(" ")[1]}`}>{r.ring}</span>
                <h3 className="font-bold text-white">{r.title}</h3>
              </div>
              <p className="text-sm text-slate-400 mt-1">{r.desc}</p>
            </GlassCard>
          ))}
        </motion.div>
      </div>
    </section>
  );
}

// -------------------------------------------------------------- features ----

const FEATURES = [
  { icon: "🔍", title: "Security audit", desc: "Nine OWASP-ASI categories, 56 SC-* checks, MAESTRO cross-layer risk, 0–100 score.", span: "md:col-span-2" },
  { icon: "🚦", title: "CI/CD gate", desc: "`audit --json` exits 2 below your threshold. Pipelines fail before drift ships." },
  { icon: "🔧", title: "Hardening + rollback", desc: "Gateway, credentials, config, Docker, network — every change backed up first." },
  { icon: "🌐", title: "Fail-closed egress proxy", desc: "HTTP CONNECT allowlist on 127.0.0.1:8889. Deny = 403 and zero bytes out.", span: "md:col-span-2" },
  { icon: "📟", title: "Runtime monitors", desc: "Cost circuit-breaker, credential access, memory integrity, skill IOC scan." },
  { icon: "🛑", title: "Kill switch", desc: "One command halts the agent from outside. Daemon refuses to start while active." },
  { icon: "⛓️", title: "Tamper-evident log", desc: "SHA-256 hash chain + ed25519 signatures. Signed incident export for IR.", span: "md:col-span-2" },
  { icon: "📜", title: "Policy engine", desc: "Rego + Cedar PDP, decision cache, hot reload. Every PEP asks before acting." },
  { icon: "🧰", title: "WASM sandbox", desc: "wasmtime host: PDP-granted WASI only, fuel + epoch caps. `.env` unreachable." },
  { icon: "🐧", title: "Kernel PEP (eBPF)", desc: "Syscall chain correlator + seccomp generation, feature-gated for Linux." },
];

function Features() {
  return (
    <section className="mx-auto max-w-6xl px-6 py-28">
      <SectionTitle
        kicker="Host-local features"
        title="One binary. Ten layers of defense."
        sub="Everything below ships in the host-local tier — no platform required."
      />
      <motion.div
        variants={stagger}
        initial="hidden"
        whileInView="show"
        viewport={{ once: true }}
        className="grid md:grid-cols-3 gap-4"
      >
        {FEATURES.map((f) => (
          <GlassCard key={f.title} className={f.span ?? ""}>
            <div className="text-2xl mb-3">{f.icon}</div>
            <h3 className="font-bold text-white mb-1">{f.title}</h3>
            <p className="text-sm text-slate-400">{f.desc}</p>
          </GlassCard>
        ))}
      </motion.div>
    </section>
  );
}

// ------------------------------------------------------------- terminal ----

const TERMINAL_LINES = [
  { cmd: "secureops init", out: "Initialized SecureOps state — keystore + starter openclaw.json" },
  { cmd: "secureops audit", out: "Score 84/100 · 3 findings (1 high, 2 medium)" },
  { cmd: "secureops harden", out: "4 fixes applied · backup 2026-06-10T07-44 · rollback available" },
  { cmd: "secureops audit --json --threshold 80", out: "exit 0 — pipeline passes" },
];

function Terminal() {
  return (
    <section className="mx-auto max-w-4xl px-6 py-28">
      <SectionTitle kicker="Quick start" title="Audited and hardened in four commands" />
      <Reveal>
        <div className="rounded-2xl border border-slate-800 bg-[#0a0f1e] shadow-2xl shadow-emerald-500/5 overflow-hidden">
          <div className="flex items-center gap-2 border-b border-slate-800 px-4 py-3">
            <span className="w-3 h-3 rounded-full bg-rose-500/80" />
            <span className="w-3 h-3 rounded-full bg-amber-500/80" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/80" />
            <span className="ml-3 text-xs text-slate-500 font-mono">secureops — zsh</span>
          </div>
          <motion.div
            variants={stagger}
            initial="hidden"
            whileInView="show"
            viewport={{ once: true }}
            className="p-6 font-mono text-sm space-y-4"
          >
            {TERMINAL_LINES.map((l, i) => (
              <motion.div key={l.cmd} variants={fadeUp}>
                <div className={i === TERMINAL_LINES.length - 1 ? "caret" : ""}>
                  <span className="text-emerald-400">$ </span>
                  <span className="text-slate-100">{l.cmd}</span>
                </div>
                <div className="text-slate-500 pl-4">{l.out}</div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </Reveal>
    </section>
  );
}

// ----------------------------------------------------------------- tiers ----

const TIERS = [
  { name: "Host-local", items: ["secureops CLI + daemon", "Audit · harden · monitors · kill switch", "Tested in CI on Linux + macOS"], badge: "free forever" },
  { name: "Platform", items: ["Multi-tenant API + scanner worker", "Postgres · Redis · MinIO · WebSocket hub", "React dashboard + first-run wizard"], badge: "self-hosted" },
  { name: "Intelligence", items: ["Attack-path graph + blast radius", "LLM bug-hunt loop (BYO model)", "LinUCB finding ranking"], badge: "self-hosted" },
  { name: "Enterprise", items: ["SSO (OIDC) + license server", "Signed IR export", "eBPF + Neo4j Helm subcharts"], badge: "self-hosted" },
];

function Tiers() {
  return (
    <section className="mx-auto max-w-6xl px-6 py-28">
      <SectionTitle
        kicker="Tiers"
        title="Start host-local. Scale self-hosted."
        sub="The community tier needs no license at all. Everything is deployable on your own infrastructure — no central SaaS dependency."
      />
      <motion.div
        variants={stagger}
        initial="hidden"
        whileInView="show"
        viewport={{ once: true }}
        className="grid md:grid-cols-4 gap-4"
      >
        {TIERS.map((t) => (
          <GlassCard key={t.name}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-white">{t.name}</h3>
              <span className="text-[10px] font-mono uppercase tracking-wide rounded-full border border-emerald-500/40 text-emerald-300 px-2 py-0.5">
                {t.badge}
              </span>
            </div>
            <ul className="space-y-2 text-sm text-slate-400">
              {t.items.map((i) => (
                <li key={i}>• {i}</li>
              ))}
            </ul>
          </GlassCard>
        ))}
      </motion.div>
    </section>
  );
}

// ------------------------------------------------------------------- cta ----

function Cta() {
  return (
    <section className="relative mx-auto max-w-4xl px-6 py-32 text-center overflow-hidden">
      <div className="blob w-96 h-96 bg-emerald-500 left-1/2 -translate-x-1/2 top-0 opacity-20" />
      <Reveal>
        <h2 className="text-4xl md:text-6xl font-extrabold text-white tracking-tight">
          Assume the agent
          <br />
          <span className="bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
            is already compromised.
          </span>
        </h2>
        <p className="mt-6 text-slate-400 text-lg">Then secure it anyway.</p>
        <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
          <CopyCommand cmd="git clone https://github.com/aryasoni98/secureops" />
          <a
            href={REPO}
            className="rounded-xl bg-emerald-500 px-8 py-3 font-semibold text-slate-950 hover:bg-emerald-400 transition-colors"
          >
            ⭐ Star on GitHub
          </a>
        </div>
      </Reveal>
    </section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-slate-800 py-10 text-center text-sm text-slate-500">
      <div className="flex items-center justify-center gap-6 mb-3">
        <a href={REPO} className="hover:text-emerald-400 transition-colors">GitHub</a>
        <a href={DOCS} className="hover:text-emerald-400 transition-colors">Docs</a>
        <a href={`${REPO}/blob/master/SECURITY.md`} className="hover:text-emerald-400 transition-colors">Security</a>
        <a href={`${REPO}/blob/master/LICENSE`} className="hover:text-emerald-400 transition-colors">MIT License</a>
      </div>
      SecureOps · out-of-band security for AI agents · Rust port of @adversa/secureops
    </footer>
  );
}

// ------------------------------------------------------------------- app ----

export function App() {
  const { scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 120, damping: 25 });
  return (
    <>
      {/* Scroll progress bar */}
      <motion.div
        style={{ scaleX: progress }}
        className="fixed top-0 left-0 right-0 h-0.5 origin-left bg-gradient-to-r from-emerald-400 to-cyan-400 z-50"
      />
      <Hero />
      <Stats />
      <Problem />
      <TrustRings />
      <Features />
      <Terminal />
      <Tiers />
      <Cta />
      <Footer />
    </>
  );
}

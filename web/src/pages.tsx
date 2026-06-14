// Authenticated dashboard pages (PRODUCT.md Phase 8 - seven screens).
// All fetches go through the typed `api` client. Each page is self-contained;
// shared chrome lives in `components.tsx`. Every data fetch keeps a separate
// error state so "empty" never masks "API failed", and mutating buttons are
// disabled while their request is in flight.

import { motion, animate, useMotionValue, useTransform } from "framer-motion";
import { useEffect, useMemo, useState } from "react";
import {
  api,
  downloadBlob,
  openWs,
  type ComplianceFormat,
  type AttackPath,
  type Finding,
  type FindingAction,
  type Remediation,
} from "./api";
import {
  EmptyRow,
  ErrorNotice,
  GlassCard,
  MotionRow,
  Page,
  PillButton,
  SeverityBadge,
} from "./components";
import { buildGraph, layoutGraph } from "./graphLayout";

const SEVERITY_FILTERS: ReadonlyArray<"" | Finding["severity"]> = [
  "",
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const ACTION_BUTTONS: ReadonlyArray<{ action: FindingAction; color: string }> = [
  { action: "confirm", color: "text-emerald-400 hover:text-emerald-300" },
  { action: "dismiss", color: "text-rose-400 hover:text-rose-300" },
  { action: "escalate", color: "text-amber-400 hover:text-amber-300" },
];

export function Findings() {
  const [items, setItems] = useState<Finding[]>([]);
  const [sev, setSev] = useState<"" | Finding["severity"]>("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => {
    const filter = sev ? { severity: sev } : {};
    const refresh = () =>
      api
        .listFindings(filter)
        .then((r) => {
          setItems(r.findings);
          setError("");
        })
        .catch(() => setError("Could not load findings."));
    refresh();
    const ws = openWs("/ws/findings", refresh);
    return () => ws.close();
  }, [sev, reloadKey]);
  async function act(id: string, a: FindingAction) {
    setPending(id);
    try {
      await api.findingAction(id, a);
      setItems((p) => p.map((f) => (f.id === id ? { ...f, status: a } : f)));
      setError("");
    } catch {
      setError(`Could not ${a} finding.`);
    } finally {
      setPending(null);
    }
  }
  return (
    <Page title="Findings">
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      <div className="flex gap-2 mb-5">
        {SEVERITY_FILTERS.map((s) => (
          <PillButton key={s || "all"} active={sev === s} onClick={() => setSev(s)}>
            {s || "all"}
          </PillButton>
        ))}
      </div>
      <div className="glass shadow-card overflow-hidden">
        <table className="w-full text-sm">
          <thead className="text-slate-400 text-xs uppercase tracking-wider bg-white/[0.03]">
            <tr>
              <th className="text-left p-3">Severity</th>
              <th className="text-left p-3">Title</th>
              <th className="text-left p-3">Cloud</th>
              <th className="text-left p-3">Blast</th>
              <th className="text-left p-3">Status</th>
              <th className="text-left p-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((f, i) => (
              <MotionRow key={f.id} index={i}>
                <td className="p-3">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="p-3 font-medium">{f.title}</td>
                <td className="p-3 text-slate-400">{f.cloud || "-"}</td>
                <td className="p-3 text-slate-400">{f.blastRadius}</td>
                <td className="p-3 text-slate-400">{f.status}</td>
                <td className="p-3">
                  <div className="flex gap-3">
                    {ACTION_BUTTONS.map(({ action, color }) => (
                      <motion.button
                        key={action}
                        whileHover={{ scale: 1.08 }}
                        whileTap={{ scale: 0.92 }}
                        onClick={() => act(f.id, action)}
                        disabled={pending === f.id}
                        className={`${color} disabled:opacity-50 transition-colors`}
                      >
                        {action}
                      </motion.button>
                    ))}
                  </div>
                </td>
              </MotionRow>
            ))}
            {items.length === 0 && !error && (
              <EmptyRow colSpan={6}>No findings yet - run a scan from /setup/scan.</EmptyRow>
            )}
          </tbody>
        </table>
      </div>
    </Page>
  );
}

const COMPLIANCE_FRAMEWORKS = ["cis", "soc2", "pci"] as const;
const COMPLIANCE_FORMATS: ReadonlyArray<{ format: ComplianceFormat; label: string; primary?: boolean }> = [
  { format: "json", label: "JSON" },
  { format: "csv", label: "CSV" },
  { format: "zip", label: "Signed IR ZIP", primary: true },
];

export function Compliance() {
  const [framework, setFramework] = useState<(typeof COMPLIANCE_FRAMEWORKS)[number]>("cis");
  const [count, setCount] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState<ComplianceFormat | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => {
    api
      .complianceCount(framework)
      .then((r) => {
        setCount(r.count);
        setError("");
      })
      .catch(() => {
        setCount(null);
        setError("Could not load compliance report counts.");
      });
  }, [framework, reloadKey]);
  async function download(format: ComplianceFormat) {
    setDownloading(format);
    try {
      const blob = await api.complianceDownload(framework, format);
      downloadBlob(blob, `${framework}-compliance.${format}`);
      setError("");
    } catch {
      setError(`Could not download the ${format.toUpperCase()} report.`);
    } finally {
      setDownloading(null);
    }
  }
  return (
    <Page title="Compliance">
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      <div className="flex gap-2 mb-6">
        {COMPLIANCE_FRAMEWORKS.map((f) => (
          <motion.button
            key={f}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setFramework(f)}
            className={`relative px-4 py-1.5 rounded-xl uppercase text-sm font-semibold border transition-colors duration-200 ${
              framework === f
                ? "bg-gradient-to-r from-emerald-500 to-teal-400 text-slate-950 border-transparent shadow-glow"
                : "bg-white/[0.04] border-white/[0.08] text-slate-300 hover:bg-white/[0.08]"
            }`}
          >
            {f}
          </motion.button>
        ))}
      </div>
      <GlassCard className="mb-6 max-w-xl">
        <p className="text-slate-400">
          Findings mapped to <span className="text-white font-semibold">{framework.toUpperCase()}</span>{" "}
          controls:{" "}
          <b className="text-2xl text-gradient align-middle ml-1">{count ?? "…"}</b>
        </p>
      </GlassCard>
      <div className="flex gap-3">
        {COMPLIANCE_FORMATS.map(({ format, label, primary }, i) => (
          <motion.button
            key={format}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 + i * 0.08 }}
            whileHover={{ scale: 1.04, y: -2 }}
            whileTap={{ scale: 0.96 }}
            onClick={() => download(format)}
            disabled={downloading !== null}
            className={`px-4 py-2.5 rounded-xl font-medium disabled:opacity-50 border transition-colors ${
              primary
                ? "bg-gradient-to-r from-emerald-500 to-teal-400 text-slate-950 border-transparent shadow-glow"
                : "bg-white/[0.04] border-white/[0.08] text-slate-200 hover:bg-white/[0.08]"
            }`}
          >
            {downloading === format ? "Downloading…" : label}
          </motion.button>
        ))}
      </div>
    </Page>
  );
}

const GRAPH_W = 800;
const GRAPH_H = 460;

export function Graph() {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [error, setError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [blast, setBlast] = useState<number | null>(null);
  useEffect(() => {
    api
      .attackPaths()
      .then((r) => {
        setPaths(r.paths);
        setError("");
      })
      .catch(() => setError("Could not load attack paths."));
  }, [reloadKey]);

  const graph = useMemo(() => buildGraph(paths), [paths]);
  const nodes = useMemo(() => layoutGraph(graph, GRAPH_W, GRAPH_H), [graph]);
  const pos = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  // Entry points (first node of a path) render emerald; targets rose.
  const entries = useMemo(() => new Set(paths.map((p) => p.nodes[0])), [paths]);
  const targets = useMemo(
    () => new Set(paths.map((p) => p.nodes[p.nodes.length - 1])),
    [paths],
  );

  function pick(id: string) {
    setSelected(id);
    setBlast(null);
    api
      .blastRadius(id)
      .then((r) => setBlast(r.blastRadius))
      .catch(() => setBlast(null));
  }

  return (
    <Page title="Attack paths">
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      <p className="text-slate-400 mb-5">
        Internet → sensitive nodes ranked by blast radius. Click a node for its blast radius.
      </p>
      {nodes.length > 0 && (
        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5 }}
          className="glass shadow-card mb-5 overflow-hidden"
        >
          <svg
            viewBox={`0 0 ${GRAPH_W} ${GRAPH_H}`}
            className="w-full"
            role="img"
            aria-label="Attack path graph"
          >
            <defs>
              <marker
                id="arrow"
                viewBox="0 0 10 10"
                refX="22"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569" />
              </marker>
            </defs>
            {graph.edges.map(([s, t], i) => {
              const a = pos.get(s);
              const b = pos.get(t);
              if (!a || !b) return null;
              return (
                <motion.line
                  key={`${s}->${t}`}
                  initial={{ pathLength: 0, opacity: 0 }}
                  animate={{ pathLength: 1, opacity: 1 }}
                  transition={{ duration: 0.6, delay: 0.2 + i * 0.06, ease: "easeOut" }}
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke="#475569"
                  strokeWidth="1.5"
                  markerEnd="url(#arrow)"
                />
              );
            })}
            {nodes.map((n, i) => {
              const fill = entries.has(n.id)
                ? "#10b981"
                : targets.has(n.id)
                  ? "#f43f5e"
                  : "#64748b";
              const isSel = selected === n.id;
              const isHover = hovered === n.id;
              return (
                <motion.g
                  key={n.id}
                  initial={{ opacity: 0, scale: 0 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ type: "spring", stiffness: 300, damping: 20, delay: i * 0.05 }}
                  style={{ transformOrigin: `${n.x}px ${n.y}px` }}
                  onClick={() => pick(n.id)}
                  onMouseEnter={() => setHovered(n.id)}
                  onMouseLeave={() => setHovered(null)}
                  className="cursor-pointer"
                  data-testid={`graph-node-${n.id}`}
                >
                  {isSel && (
                    <motion.circle
                      cx={n.x}
                      cy={n.y}
                      fill="none"
                      stroke={fill}
                      strokeWidth="2"
                      initial={{ r: 14, opacity: 0.8 }}
                      animate={{ r: 26, opacity: 0 }}
                      transition={{ duration: 1.4, repeat: Infinity, ease: "easeOut" }}
                    />
                  )}
                  <motion.circle
                    cx={n.x}
                    cy={n.y}
                    animate={{ r: isSel ? 14 : isHover ? 12 : 10 }}
                    transition={{ type: "spring", stiffness: 400, damping: 25 }}
                    fill={fill}
                    stroke={isSel ? "#f8fafc" : "#0f172a"}
                    strokeWidth="2"
                  />
                  <text
                    x={n.x}
                    y={n.y - 16}
                    textAnchor="middle"
                    fill={isSel || isHover ? "#f8fafc" : "#cbd5e1"}
                    fontSize="11"
                    fontFamily="monospace"
                  >
                    {n.id}
                  </text>
                </motion.g>
              );
            })}
          </svg>
          {selected && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="px-4 py-2.5 border-t border-white/[0.06] text-sm text-slate-300 bg-white/[0.02]"
            >
              <code>{selected}</code>{" "}
              <span className="text-amber-400 font-medium">blast radius {blast ?? "…"}</span>
            </motion.div>
          )}
        </motion.div>
      )}
      <ul className="space-y-2.5">
        {paths.map((p, i) => (
          <motion.li
            key={i}
            initial={{ opacity: 0, x: -16 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3 + i * 0.07, duration: 0.4, ease: "easeOut" }}
            whileHover={{ x: 4 }}
            className="glass glass-hover p-3.5 text-sm flex items-center justify-between"
          >
            <code className="text-slate-300">{p.nodes.join(" → ")}</code>
            <span className="text-amber-400 font-medium shrink-0 ml-3">blast {p.blastRadius}</span>
          </motion.li>
        ))}
        {paths.length === 0 && !error && (
          <li className="text-slate-500">No path data yet - call POST /graph/rebuild.</li>
        )}
      </ul>
    </Page>
  );
}

const REM_CLASS_COLORS: Record<Remediation["class"], string> = {
  destructive: "border-rose-500/50 bg-rose-500/10 text-rose-300",
  reversible: "border-amber-500/50 bg-amber-500/10 text-amber-300",
  safe: "border-emerald-500/50 bg-emerald-500/10 text-emerald-300",
};

export function RemediationQueue() {
  const [items, setItems] = useState<Remediation[]>([]);
  const [error, setError] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  function refresh() {
    api
      .remediationQueue()
      .then((r) => {
        setItems(r.remediations);
        setError("");
      })
      .catch(() => setError("Could not load the remediation queue."));
  }
  useEffect(() => {
    refresh();
    const ws = openWs("/ws/remediation", refresh);
    return () => ws.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reloadKey]);
  async function decide(id: string, decision: "approve" | "deny") {
    setPending(id);
    try {
      await (decision === "approve" ? api.approveRemediation(id) : api.denyRemediation(id));
      refresh();
    } catch {
      setError(`Could not ${decision} the remediation.`);
    } finally {
      setPending(null);
    }
  }
  return (
    <Page title="Remediation queue (HITL)">
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      <div className="glass shadow-card overflow-hidden">
        <table className="w-full text-sm">
          <thead className="text-slate-400 text-xs uppercase tracking-wider bg-white/[0.03]">
            <tr>
              <th className="text-left p-3">Playbook</th>
              <th className="text-left p-3">Finding</th>
              <th className="text-left p-3">Class</th>
              <th className="text-left p-3">State</th>
              <th className="text-left p-3">Action</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r, i) => (
              <MotionRow key={r.id} index={i}>
                <td className="p-3 font-mono">{r.playbook_id}</td>
                <td className="p-3 font-mono text-slate-400">{r.finding_id}</td>
                <td className="p-3">
                  <span
                    className={`text-xs px-2.5 py-0.5 rounded-full border font-medium ${REM_CLASS_COLORS[r.class]}`}
                  >
                    {r.class}
                  </span>
                </td>
                <td className="p-3 text-slate-400">{r.state}</td>
                <td className="p-3">
                  <div className="flex gap-3">
                    <motion.button
                      whileHover={{ scale: 1.08 }}
                      whileTap={{ scale: 0.92 }}
                      onClick={() => decide(r.id, "approve")}
                      disabled={pending === r.id}
                      className="text-emerald-400 hover:text-emerald-300 disabled:opacity-50 transition-colors"
                    >
                      approve
                    </motion.button>
                    <motion.button
                      whileHover={{ scale: 1.08 }}
                      whileTap={{ scale: 0.92 }}
                      onClick={() => decide(r.id, "deny")}
                      disabled={pending === r.id}
                      className="text-rose-400 hover:text-rose-300 disabled:opacity-50 transition-colors"
                    >
                      deny
                    </motion.button>
                  </div>
                </td>
              </MotionRow>
            ))}
            {items.length === 0 && !error && <EmptyRow colSpan={5}>Queue empty.</EmptyRow>}
          </tbody>
        </table>
      </div>
    </Page>
  );
}

/** Animated count-up number for stat cards. */
function CountUp({ value }: { value: number }) {
  const mv = useMotionValue(0);
  const rounded = useTransform(mv, (v) => {
    // Preserve up to 2 decimals for fractional stats (e.g. exploration alpha).
    return Number.isInteger(value) ? Math.round(v).toLocaleString() : v.toFixed(2);
  });
  useEffect(() => {
    const controls = animate(mv, value, { duration: 1, ease: [0.22, 1, 0.36, 1] });
    return controls.stop;
  }, [value, mv]);
  return <motion.span>{rounded}</motion.span>;
}

function Stat({ label, value, delay = 0 }: { label: string; value: number; delay?: number }) {
  return (
    <GlassCard delay={delay} className="relative overflow-hidden">
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-emerald-400/60 to-transparent" />
      <div className="text-xs text-slate-400 uppercase tracking-wider mb-1">{label}</div>
      <div className="text-3xl font-bold text-gradient">
        <CountUp value={value} />
      </div>
    </GlassCard>
  );
}

export function Usage() {
  const [stats, setStats] = useState<{ updates: number; dim: number; alpha: number } | null>(null);
  const [error, setError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => {
    api
      .rlStats()
      .then((s) => {
        setStats(s);
        setError("");
      })
      .catch(() => setError("Could not load RL telemetry."));
  }, [reloadKey]);
  return (
    <Page title="Usage & RL telemetry">
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      {stats ? (
        <div className="grid grid-cols-3 gap-5">
          <Stat label="RL updates" value={stats.updates} />
          <Stat label="Feature dim" value={stats.dim} delay={0.08} />
          <Stat label="Exploration alpha" value={stats.alpha} delay={0.16} />
        </div>
      ) : (
        !error && <p className="text-slate-500">Loading…</p>
      )}
    </Page>
  );
}

export function LicenseStatus() {
  const [lic, setLic] = useState<{ tier: string; expiry: number; features: string[] } | null>(null);
  const [error, setError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => {
    api
      .getLicense()
      .then((l) => {
        setLic(l);
        setError("");
      })
      .catch(() => setError("Could not load the license."));
  }, [reloadKey]);
  return (
    <Page title="License">
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      {lic ? (
        <GlassCard className="max-w-md relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-emerald-400/60 via-cyan-400/40 to-transparent" />
          <div className="space-y-2.5">
            <p className="text-sm flex items-center justify-between">
              <span className="text-slate-400">Tier</span>
              <b className="text-gradient text-base uppercase tracking-wide">{lic.tier}</b>
            </p>
            <p className="text-sm flex items-center justify-between">
              <span className="text-slate-400">Expires</span>
              <span>{new Date(lic.expiry * 1000).toLocaleString()}</span>
            </p>
            <p className="text-sm flex items-center justify-between">
              <span className="text-slate-400">Features</span>
              <span>{lic.features.join(", ") || "(base)"}</span>
            </p>
          </div>
        </GlassCard>
      ) : (
        !error && <p className="text-slate-500">No active license.</p>
      )}
    </Page>
  );
}

export function Profile() {
  return (
    <Page title="Profile">
      <GlassCard className="max-w-xl">
        <p className="text-slate-400 mb-4">
          RBAC roles, API key rotation, and notification preferences land here. Sign out clears the
          local session token.
        </p>
        <motion.button
          whileHover={{ scale: 1.04, boxShadow: "0 0 24px rgba(244,63,94,0.35)" }}
          whileTap={{ scale: 0.96 }}
          onClick={() => {
            localStorage.clear();
            window.location.href = "/license";
          }}
          className="bg-gradient-to-r from-rose-500 to-rose-400 text-white font-medium px-4 py-2 rounded-xl"
        >
          Clear local state
        </motion.button>
      </GlassCard>
    </Page>
  );
}

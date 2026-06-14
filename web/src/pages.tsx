// Authenticated dashboard pages (PRODUCT.md Phase 8 - seven screens).
// All fetches go through the typed `api` client. Each page is self-contained;
// shared chrome lives in `components.tsx`. Every data fetch keeps a separate
// error state so "empty" never masks "API failed", and mutating buttons are
// disabled while their request is in flight.

import { motion, animate, useMotionValue, useTransform } from "framer-motion";
import { useEffect, useMemo, useState, Fragment, useRef } from "react";
import {
  api,
  downloadBlob,
  openWs,
  type ComplianceFormat,
  type ComplianceReport,
  type AttackPath,
  type Finding,
  type FindingAction,
  type Remediation,
} from "./api";
import {
  ActionChip,
  DataTable,
  EmptyRow,
  EmptyState,
  ErrorNotice,
  GlassCard,
  MotionRow,
  Page,
  PageToolbar,
  PillButton,
  PrimaryButton,
  QuickStat,
  QuickStats,
  SecondaryButton,
  SeverityBadge,
  SplitLayout,
  TableHead,
} from "./components";
import { buildGraph, layoutGraph } from "./graphLayout";
import { buildGraphSpecFromFindings, matchPlaybook, suggestFix } from "./remediationHints";

const SEVERITY_FILTERS: ReadonlyArray<"" | Finding["severity"]> = [
  "",
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const ACTION_BUTTONS: ReadonlyArray<{ action: FindingAction; variant: "confirm" | "dismiss" | "escalate"; label: string }> = [
  { action: "confirm", variant: "confirm", label: "Confirm" },
  { action: "dismiss", variant: "dismiss", label: "Dismiss" },
  { action: "escalate", variant: "escalate", label: "Escalate" },
];

export function Findings() {
  const [items, setItems] = useState<Finding[]>([]);
  const [sev, setSev] = useState<"" | Finding["severity"]>("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState<string | null>(null);
  const [aiSteps, setAiSteps] = useState<Record<string, string[]>>({});
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
  async function queueFix(f: Finding) {
    const pb = matchPlaybook(f);
    if (!pb) {
      setError("No automated playbook matched this finding - review the suggested fix manually.");
      return;
    }
    setPending(f.id);
    try {
      await api.queueRemediation(f.id, pb.playbookId);
      setError("");
    } catch {
      setError("Could not queue remediation.");
    } finally {
      setPending(null);
    }
  }
  async function runAiFix(f: Finding) {
    setAiLoading(f.id);
    try {
      const job = await api.runBugHunt(f.title.slice(0, 80));
      const detail = await api.getBugHunt(job.jobId);
      const steps =
        detail.report?.remediation_steps?.length
          ? detail.report.remediation_steps
          : suggestFix(f);
      setAiSteps((p) => ({ ...p, [f.id]: steps }));
      setExpanded(f.id);
      setError("");
    } catch {
      setAiSteps((p) => ({ ...p, [f.id]: suggestFix(f) }));
      setExpanded(f.id);
      setError("AI analysis unavailable - showing rule-based fix. Ensure bughunt feature is licensed.");
    } finally {
      setAiLoading(null);
    }
  }
  const stats = useMemo(() => {
    const open = items.filter((f) => f.status !== "dismissed").length;
    const critical = items.filter((f) => f.severity === "critical").length;
    const high = items.filter((f) => f.severity === "high").length;
    return { total: items.length, open, critical, high };
  }, [items]);

  return (
    <Page
      title="Findings"
      subtitle="Security issues from your latest cloud scan. Expand a row for AI-powered fix suggestions and one-click remediation."
    >
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      <QuickStats>
        <QuickStat label="Total" value={stats.total} hint="All severities" />
        <QuickStat label="Open" value={stats.open} tone={stats.open > 0 ? "warn" : "good"} />
        <QuickStat label="Critical" value={stats.critical} tone={stats.critical > 0 ? "bad" : "good"} />
        <QuickStat label="High" value={stats.high} tone={stats.high > 0 ? "warn" : "default"} />
      </QuickStats>
      <PageToolbar>
        <div className="flex flex-wrap gap-2">
          <span className="text-xs text-slate-500 self-center mr-1">Filter:</span>
          {SEVERITY_FILTERS.map((s) => (
            <PillButton key={s || "all"} active={sev === s} onClick={() => setSev(s)}>
              {s || "All"}
            </PillButton>
          ))}
        </div>
        <span className="text-xs text-slate-500">{items.length} shown</span>
      </PageToolbar>
      <DataTable>
          <TableHead>
            <tr>
              <th className="text-left p-3 lg:p-4 w-10" aria-label="Expand" />
              <th className="text-left p-3 lg:p-4 w-28">Severity</th>
              <th className="text-left p-3 lg:p-4 min-w-[280px]">Finding</th>
              <th className="text-left p-3 lg:p-4 w-24">Cloud</th>
              <th className="text-left p-3 lg:p-4 w-20">Blast</th>
              <th className="text-left p-3 lg:p-4 w-24">Status</th>
              <th className="text-left p-3 lg:p-4 w-48">Actions</th>
            </tr>
          </TableHead>
          <tbody>
            {items.map((f, i) => {
              const isOpen = expanded === f.id;
              const fixSteps = aiSteps[f.id] ?? suggestFix(f);
              const pb = matchPlaybook(f);
              return (
                <Fragment key={f.id}>
                  <MotionRow index={i}>
                    <td className="p-3">
                      <button
                        type="button"
                        onClick={() => setExpanded(isOpen ? null : f.id)}
                        className="text-slate-400 hover:text-emerald-400 transition-colors"
                        aria-label={isOpen ? "Collapse solution" : "Expand solution"}
                      >
                        {isOpen ? "▾" : "▸"}
                      </button>
                    </td>
                    <td className="p-3">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="p-3 lg:p-4 font-medium text-slate-100 leading-snug">{f.title}</td>
                    <td className="p-3 lg:p-4">
                      <span className="inline-flex px-2 py-0.5 rounded-md bg-white/[0.06] text-slate-300 text-xs uppercase">
                        {f.cloud || "-"}
                      </span>
                    </td>
                    <td className="p-3 lg:p-4">
                      <span className={`font-mono text-sm ${f.blastRadius >= 50 ? "text-amber-400" : "text-slate-400"}`}>
                        {f.blastRadius}
                      </span>
                    </td>
                    <td className="p-3 lg:p-4">
                      <span className="text-xs capitalize text-slate-400">{f.status}</span>
                    </td>
                    <td className="p-3 lg:p-4">
                      <div className="flex flex-wrap gap-1.5">
                        {ACTION_BUTTONS.map(({ action, variant, label }) => (
                          <ActionChip
                            key={action}
                            variant={variant}
                            onClick={() => act(f.id, action)}
                            disabled={pending === f.id}
                          >
                            {label}
                          </ActionChip>
                        ))}
                      </div>
                    </td>
                  </MotionRow>
                  {isOpen && (
                    <tr key={`${f.id}-solution`} className="bg-emerald-500/[0.04] border-t border-white/[0.04]">
                      <td colSpan={7} className="p-4 lg:p-6">
                        <div className="grid lg:grid-cols-[1fr_auto] gap-6 max-w-none">
                          <div className="glass p-4 rounded-xl border border-emerald-500/15">
                            <p className="text-xs uppercase tracking-wider text-emerald-400 mb-3 font-semibold">
                              Recommended fix
                            </p>
                            <ul className="space-y-2 text-sm text-slate-300">
                              {fixSteps.map((step, j) => (
                                <li key={j} className="flex gap-2">
                                  <span className="text-emerald-500 shrink-0">•</span>
                                  <span>{step}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                          <div className="flex flex-col gap-2 justify-start min-w-[200px]">
                            <ActionChip
                              variant="ai"
                              onClick={() => runAiFix(f)}
                              disabled={aiLoading === f.id}
                              className="py-2.5"
                            >
                              {aiLoading === f.id ? "Analyzing…" : "✨ Generate AI fix"}
                            </ActionChip>
                            {pb && (
                              <ActionChip
                                variant="queue"
                                onClick={() => queueFix(f)}
                                disabled={pending === f.id}
                                className="py-2.5"
                              >
                                Queue → HITL
                              </ActionChip>
                            )}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {items.length === 0 && !error && (
              <EmptyRow colSpan={7}>No findings yet - run a scan from /setup/scan.</EmptyRow>
            )}
          </tbody>
      </DataTable>
    </Page>
  );
}

const COMPLIANCE_FRAMEWORKS = [
  { id: "scs", label: "AWS SCS-C02" },
  { id: "owasp", label: "OWASP Top 10" },
  { id: "soc2", label: "SOC 2" },
  { id: "iso27001", label: "ISO 27001" },
  { id: "hipaa", label: "HIPAA" },
  { id: "gdpr", label: "GDPR" },
  { id: "ccpa", label: "CCPA" },
  { id: "ccsk", label: "CCSK v4" },
  { id: "cis", label: "CIS" },
  { id: "pci", label: "PCI" },
] as const;

const COMPLIANCE_FORMATS: ReadonlyArray<{ format: ComplianceFormat; label: string; primary?: boolean }> = [
  { format: "json", label: "JSON" },
  { format: "csv", label: "CSV" },
  { format: "zip", label: "Signed IR ZIP", primary: true },
];

function ControlStatus({ status }: { status: string }) {
  const styles =
    status === "pass"
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
      : "border-rose-500/40 bg-rose-500/10 text-rose-300";
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium uppercase ${styles}`}>
      {status}
    </span>
  );
}

export function Compliance() {
  const [framework, setFramework] = useState<(typeof COMPLIANCE_FRAMEWORKS)[number]["id"]>("scs");
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState<ComplianceFormat | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => {
    api
      .complianceReport(framework)
      .then((r) => {
        setReport(r);
        setError("");
      })
      .catch(() => {
        setReport(null);
        setError("Could not load compliance report.");
      });
  }, [framework, reloadKey]);
  async function download(format: ComplianceFormat) {
    setDownloading(format);
    try {
      const blob = await api.complianceDownload(framework, format);
      downloadBlob(blob, `${framework}-compliance.${format === "zip" ? "zip" : format}`);
      setError("");
    } catch {
      setError(`Could not download the ${format.toUpperCase()} report.`);
    } finally {
      setDownloading(null);
    }
  }
  const gaps = report?.controls.filter((c) => c.status === "fail") ?? [];

  const frameworkSidebar = (
    <div className="space-y-4">
      <div className="xl:hidden flex flex-wrap gap-2">
        {COMPLIANCE_FRAMEWORKS.map((f) => (
          <PillButton key={f.id} active={framework === f.id} onClick={() => setFramework(f.id)}>
            {f.label}
          </PillButton>
        ))}
      </div>
      <div className="hidden xl:block glass p-3 space-y-1">
        <p className="text-[10px] uppercase tracking-wider text-slate-500 px-2 py-1">Frameworks</p>
        {COMPLIANCE_FRAMEWORKS.map((f) => (
          <button
            key={f.id}
            type="button"
            onClick={() => setFramework(f.id)}
            className={`w-full text-left px-3 py-2.5 rounded-lg text-sm transition-colors ${
              framework === f.id
                ? "bg-emerald-500/15 text-white border border-emerald-500/25"
                : "text-slate-400 hover:text-white hover:bg-white/[0.06]"
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>
      <div className="flex flex-wrap xl:flex-col gap-2">
        {COMPLIANCE_FORMATS.map(({ format, label, primary }) => (
          <button
            key={format}
            type="button"
            onClick={() => download(format)}
            disabled={downloading !== null}
            className={`px-3 py-2 rounded-lg text-xs font-medium disabled:opacity-50 border transition-colors ${
              primary
                ? "bg-gradient-to-r from-emerald-500 to-teal-400 text-slate-950 border-transparent"
                : "bg-white/[0.04] border-white/[0.08] text-slate-300 hover:bg-white/[0.08]"
            }`}
          >
            {downloading === format ? "…" : label}
          </button>
        ))}
      </div>
    </div>
  );

  return (
    <Page
      title="Compliance"
      subtitle="Map open findings to industry frameworks. Failed controls highlight gaps that need remediation."
    >
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      <SplitLayout sidebar={frameworkSidebar}>
        {report ? (
          <>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 mb-6 w-full">
              <GlassCard hover={false}>
                <div className="text-xs text-slate-400 uppercase tracking-wider mb-1">Score</div>
                <div className="text-3xl lg:text-4xl font-bold text-gradient">{report.score}%</div>
                <p className="text-xs text-slate-500 mt-1 truncate">{report.frameworkLabel}</p>
              </GlassCard>
              <GlassCard hover={false} delay={0.05}>
                <div className="text-xs text-slate-400 uppercase tracking-wider mb-1">Passing</div>
                <div className="text-3xl lg:text-4xl font-bold text-emerald-400">{report.passing}</div>
                <p className="text-xs text-slate-500 mt-1">of {report.totalControls} controls</p>
              </GlassCard>
              <GlassCard hover={false} delay={0.1}>
                <div className="text-xs text-slate-400 uppercase tracking-wider mb-1">Gaps</div>
                <div className="text-3xl lg:text-4xl font-bold text-rose-400">{report.failing}</div>
                <p className="text-xs text-slate-500 mt-1">failed controls</p>
              </GlassCard>
              <GlassCard hover={false} delay={0.15}>
                <div className="text-xs text-slate-400 uppercase tracking-wider mb-1">Unmapped</div>
                <div className="text-3xl lg:text-4xl font-bold text-amber-400">{report.unmappedFindings}</div>
                <p className="text-xs text-slate-500 mt-1">findings without control</p>
              </GlassCard>
            </div>
            <DataTable className="mb-6">
              <TableHead>
                <tr>
                  <th className="text-left p-3 lg:p-4 min-w-[240px]">Control</th>
                  <th className="text-left p-3 lg:p-4 w-24">Status</th>
                  <th className="text-left p-3 lg:p-4 w-24">Severity</th>
                  <th className="text-left p-3 lg:p-4">Linked findings</th>
                </tr>
              </TableHead>
              <tbody>
                {report.controls.map((c, i) => (
                  <MotionRow key={c.id} index={i}>
                    <td className="p-3 lg:p-4">
                      <div className="font-mono text-emerald-300/90 text-xs mb-0.5">{c.id}</div>
                      <div className="text-slate-300 leading-snug">{c.title}</div>
                    </td>
                    <td className="p-3 lg:p-4">
                      <ControlStatus status={c.status} />
                    </td>
                    <td className="p-3 lg:p-4 text-slate-400 capitalize">{c.maxSeverity || "-"}</td>
                    <td className="p-3 lg:p-4 text-slate-400 font-mono text-xs break-all">
                      {c.findings.length ? c.findings.join(", ") : "-"}
                    </td>
                  </MotionRow>
                ))}
              </tbody>
            </DataTable>
            {gaps.length > 0 && (
              <GlassCard className="border border-rose-500/20" hover={false}>
                <p className="text-sm text-rose-300 font-medium mb-3">
                  {gaps.length} compliance gap{gaps.length > 1 ? "s" : ""} - prioritize these controls
                </p>
                <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {gaps.map((g) => (
                    <div key={g.id} className="glass p-3 rounded-lg text-sm border border-rose-500/10">
                      <span className="font-mono text-rose-300 text-xs">{g.id}</span>
                      <p className="text-slate-400 mt-1 leading-snug">{g.title}</p>
                    </div>
                  ))}
                </div>
              </GlassCard>
            )}
          </>
        ) : (
          !error && (
            <GlassCard hover={false}>
              <p className="text-slate-400">Loading compliance mapping…</p>
            </GlassCard>
          )
        )}
      </SplitLayout>
    </Page>
  );
}

const GRAPH_H_RATIO = 0.52;
const GRAPH_H_MIN = 380;
const GRAPH_H_MAX = 640;

export function Graph() {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [error, setError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  const [rebuilding, setRebuilding] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [blast, setBlast] = useState<number | null>(null);
  const graphRef = useRef<HTMLDivElement>(null);
  const [graphSize, setGraphSize] = useState({ w: 1200, h: 520 });

  useEffect(() => {
    const el = graphRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      const w = Math.max(Math.floor(entry.contentRect.width), 480);
      const h = Math.min(GRAPH_H_MAX, Math.max(GRAPH_H_MIN, Math.floor(w * GRAPH_H_RATIO)));
      setGraphSize({ w, h });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  async function loadPaths() {
    const r = await api.attackPaths();
    setPaths(r.paths);
    return r.paths;
  }

  async function rebuildFromFindings() {
    setRebuilding(true);
    try {
      const { findings } = await api.listFindings({});
      const open = findings.filter((f) => f.status !== "dismissed");
      if (open.length === 0) {
        setError("No open findings to build a graph from - run a scan first.");
        return;
      }
      const spec = buildGraphSpecFromFindings(open);
      await api.rebuildGraph(spec);
      await loadPaths();
      setError("");
    } catch {
      setError("Could not rebuild attack-path graph.");
    } finally {
      setRebuilding(false);
    }
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const existing = await api.attackPaths();
        if (cancelled) return;
        if (existing.paths.length > 0) {
          setPaths(existing.paths);
          setError("");
          return;
        }
        const { findings } = await api.listFindings({});
        if (cancelled) return;
        const open = findings.filter((f) => f.status !== "dismissed");
        if (open.length === 0) {
          setPaths([]);
          setError("");
          return;
        }
        const spec = buildGraphSpecFromFindings(open);
        await api.rebuildGraph(spec);
        if (cancelled) return;
        const r = await api.attackPaths();
        setPaths(r.paths);
        setError("");
      } catch {
        if (!cancelled) setError("Could not load attack paths.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [reloadKey]);

  const graph = useMemo(() => buildGraph(paths), [paths]);
  const nodes = useMemo(() => layoutGraph(graph, graphSize.w, graphSize.h), [graph, graphSize]);
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
    <Page
      title="Attack paths"
      subtitle="Visualize how internet-exposed assets connect to sensitive resources. Green = entry, red = target."
      actions={
        <SecondaryButton onClick={() => rebuildFromFindings()} disabled={rebuilding}>
          {rebuilding ? "Rebuilding…" : "Rebuild from findings"}
        </SecondaryButton>
      }
    >
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      <div className="grid xl:grid-cols-[minmax(0,1.4fr)_minmax(280px,0.6fr)] gap-6 w-full">
        <div ref={graphRef} className="min-w-0 w-full">
          {nodes.length > 0 ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.99 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.4 }}
              className="glass shadow-card overflow-hidden w-full"
            >
              <div className="flex flex-wrap items-center gap-4 px-4 py-2 border-b border-white/[0.06] text-xs text-slate-500">
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-500" /> Entry</span>
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-rose-500" /> Target</span>
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-slate-500" /> Asset</span>
              </div>
              <svg
                viewBox={`0 0 ${graphSize.w} ${graphSize.h}`}
                className="w-full h-auto min-h-[380px]"
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
                  className="px-4 py-3 border-t border-white/[0.06] text-sm text-slate-300 bg-white/[0.02] flex flex-wrap gap-2 items-center"
                >
                  <code className="text-emerald-300">{selected}</code>
                  <span className="text-amber-400 font-medium">Blast radius: {blast ?? "…"}</span>
                </motion.div>
              )}
            </motion.div>
          ) : (
            !error && (
              <EmptyState
                title="No attack paths yet"
                description="Run a scan first, then build the graph from your findings."
                action={
                  <PrimaryButton onClick={() => rebuildFromFindings()} disabled={rebuilding}>
                    {rebuilding ? "Building…" : "Build graph from findings"}
                  </PrimaryButton>
                }
              />
            )
          )}
        </div>
        <aside className="min-w-0 flex flex-col gap-3">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            Ranked paths ({paths.length})
          </h2>
          <ul className="space-y-2 flex-1 overflow-y-auto max-h-[640px] pr-1">
            {paths.map((p, i) => (
              <motion.li
                key={i}
                initial={{ opacity: 0, x: 8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1 + i * 0.05 }}
                className="glass p-3 text-sm border border-white/[0.06] hover:border-emerald-500/20 transition-colors"
              >
                <code className="text-slate-300 text-xs leading-relaxed block break-all">{p.nodes.join(" → ")}</code>
                <span className="text-amber-400 font-medium text-xs mt-2 inline-block">Blast {p.blastRadius}</span>
              </motion.li>
            ))}
            {paths.length === 0 && !error && (
              <li className="text-slate-500 text-sm">Paths appear here after graph rebuild.</li>
            )}
          </ul>
        </aside>
      </div>
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
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const findingTitle = useMemo(() => {
    const m = new Map<string, string>();
    for (const f of findings) m.set(f.id, f.title);
    return m;
  }, [findings]);
  function refresh() {
    Promise.all([api.remediationQueue(), api.listFindings({})])
      .then(([q, f]) => {
        setItems(q.remediations);
        setFindings(f.findings);
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
  async function queueAllMatched() {
    setBulkLoading(true);
    try {
      const open = findings.filter((f) => f.status !== "dismissed");
      let queued = 0;
      for (const f of open) {
        const pb = matchPlaybook(f);
        if (!pb || pb.class === "destructive") continue;
        try {
          await api.queueRemediation(f.id, pb.playbookId);
          queued += 1;
        } catch {
          /* skip duplicates / errors */
        }
      }
      refresh();
      if (queued === 0) {
        setError("No safe/reversible playbooks matched open findings.");
      } else {
        setError("");
      }
    } catch {
      setError("Could not bulk-queue remediations.");
    } finally {
      setBulkLoading(false);
    }
  }
  return (
    <Page
      title="Remediation queue"
      subtitle="Human-in-the-loop approval for automated fixes. Review each playbook before it runs in your cloud."
      actions={
        items.length === 0 ? (
          <PrimaryButton onClick={() => queueAllMatched()} disabled={bulkLoading}>
            {bulkLoading ? "Queuing…" : "Queue safe fixes"}
          </PrimaryButton>
        ) : (
          <span className="text-sm text-slate-500">{items.filter((i) => i.state === "pending").length} pending</span>
        )
      }
    >
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      {items.length === 0 && !error && (
        <EmptyState
          title="Queue is empty"
          description="Expand a finding and click Queue → HITL, or use the button above to auto-queue safe playbooks."
          action={
            <PrimaryButton onClick={() => queueAllMatched()} disabled={bulkLoading}>
              {bulkLoading ? "Queuing…" : "Queue safe fixes from findings"}
            </PrimaryButton>
          }
        />
      )}
      {items.length > 0 && (
      <DataTable>
          <TableHead>
            <tr>
              <th className="text-left p-3 lg:p-4 w-48">Playbook</th>
              <th className="text-left p-3 lg:p-4 min-w-[280px]">Finding</th>
              <th className="text-left p-3 lg:p-4 w-28">Class</th>
              <th className="text-left p-3 lg:p-4 w-24">State</th>
              <th className="text-left p-3 lg:p-4 w-40">Decision</th>
            </tr>
          </TableHead>
          <tbody>
            {items.map((r, i) => (
              <MotionRow key={r.id} index={i}>
                <td className="p-3 font-mono">{r.playbook_id}</td>
                <td className="p-3 lg:p-4">
                  <div className="text-slate-300 text-sm leading-snug max-w-xl">
                    {findingTitle.get(r.finding_id) || r.finding_id}
                  </div>
                  <div className="font-mono text-[10px] text-slate-600 mt-0.5">{r.finding_id.slice(0, 12)}…</div>
                </td>
                <td className="p-3">
                  <span
                    className={`text-xs px-2.5 py-0.5 rounded-full border font-medium ${REM_CLASS_COLORS[r.class]}`}
                  >
                    {r.class}
                  </span>
                </td>
                <td className="p-3 text-slate-400">{r.state}</td>
                <td className="p-3 lg:p-4">
                  <div className="flex gap-2">
                    <ActionChip variant="approve" onClick={() => decide(r.id, "approve")} disabled={pending === r.id}>
                      Approve
                    </ActionChip>
                    <ActionChip variant="deny" onClick={() => decide(r.id, "deny")} disabled={pending === r.id}>
                      Deny
                    </ActionChip>
                  </div>
                </td>
              </MotionRow>
            ))}
            {items.length === 0 && !error && <EmptyRow colSpan={5}>No items in queue.</EmptyRow>}
          </tbody>
      </DataTable>
      )}
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
  const [findingsCount, setFindingsCount] = useState(0);
  const [openFindings, setOpenFindings] = useState(0);
  const [pathsCount, setPathsCount] = useState(0);
  const [pendingRem, setPendingRem] = useState(0);
  const [complianceScore, setComplianceScore] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => {
    Promise.all([
      api.rlStats(),
      api.listFindings({}),
      api.attackPaths(),
      api.remediationQueue(),
      api.complianceReport("scs"),
    ])
      .then(([s, f, g, r, c]) => {
        setStats(s);
        setFindingsCount(f.count);
        setOpenFindings(f.findings.filter((x) => x.status !== "dismissed").length);
        setPathsCount(g.paths.length);
        setPendingRem(r.remediations.filter((x) => x.state === "pending").length);
        setComplianceScore(c.score);
        setError("");
      })
      .catch(() => setError("Could not load usage telemetry."));
  }, [reloadKey]);
  return (
    <Page title="Usage & telemetry" subtitle="Platform activity, reinforcement-learning stats, and scan health at a glance.">
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      {stats ? (
        <div className="space-y-8 w-full">
          <section>
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">Security posture</h2>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 sm:gap-4">
              <Stat label="Total findings" value={findingsCount} />
              <Stat label="Open findings" value={openFindings} delay={0.05} />
              <Stat label="Attack paths" value={pathsCount} delay={0.1} />
              <Stat label="Pending HITL" value={pendingRem} delay={0.15} />
              <Stat label="SCS score" value={complianceScore ?? 0} delay={0.2} />
            </div>
          </section>
          <section>
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">RL prioritization</h2>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 sm:gap-4 max-w-3xl">
              <Stat label="RL updates" value={stats.updates} delay={0.25} />
              <Stat label="Feature dimensions" value={stats.dim} delay={0.3} />
              <Stat label="Exploration α" value={stats.alpha} delay={0.35} />
            </div>
          </section>
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
    <Page title="License" subtitle="Your active plan, feature flags, and subscription expiry.">
      {error && <ErrorNotice message={error} onRetry={() => setReloadKey((k) => k + 1)} />}
      {lic ? (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 w-full">
          <GlassCard hover={false} className="relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-emerald-400/60 via-cyan-400/40 to-transparent" />
            <div className="space-y-3">
              <p className="text-sm flex items-center justify-between gap-4">
                <span className="text-slate-400">Tier</span>
                <b className="text-gradient text-base uppercase tracking-wide">{lic.tier}</b>
              </p>
              <p className="text-sm flex items-center justify-between gap-4">
                <span className="text-slate-400">Expires</span>
                <span className="text-right">{new Date(lic.expiry * 1000).toLocaleString()}</span>
              </p>
            </div>
          </GlassCard>
          <GlassCard hover={false} className="sm:col-span-2 lg:col-span-2">
            <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Enabled features</p>
            <div className="flex flex-wrap gap-2">
              {(lic.features.length ? lic.features : ["base"]).map((f) => (
                <span key={f} className="px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/25 text-emerald-300 text-xs font-medium">
                  {f}
                </span>
              ))}
            </div>
          </GlassCard>
        </div>
      ) : (
        !error && <p className="text-slate-500">No active license.</p>
      )}
    </Page>
  );
}

export function Profile() {
  return (
    <Page title="Profile" subtitle="Session and account preferences.">
      <div className="grid lg:grid-cols-2 gap-6 w-full">
        <GlassCard hover={false}>
          <h2 className="text-sm font-semibold text-white mb-2">Account</h2>
          <p className="text-slate-400 text-sm leading-relaxed mb-4">
            RBAC roles, API key rotation, and notification preferences will appear here in a future release.
          </p>
        </GlassCard>
        <GlassCard hover={false}>
          <h2 className="text-sm font-semibold text-white mb-2">Local session</h2>
          <p className="text-slate-400 text-sm leading-relaxed mb-4">
            Clears your license token and setup wizard progress from this browser.
          </p>
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => {
              localStorage.clear();
              window.location.href = "/license";
            }}
            className="bg-gradient-to-r from-rose-500 to-rose-400 text-white font-medium px-4 py-2 rounded-xl text-sm"
          >
            Clear local state & sign out
          </motion.button>
        </GlassCard>
      </div>
    </Page>
  );
}

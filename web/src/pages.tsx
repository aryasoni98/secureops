// Authenticated dashboard pages (PRODUCT.md Phase 8 - seven screens).
// All fetches go through the typed `api` client. Each page is self-contained;
// shared chrome lives in `components.tsx`. Every data fetch keeps a separate
// error state so "empty" never masks "API failed", and mutating buttons are
// disabled while their request is in flight.

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
import { EmptyRow, ErrorNotice, Page, PillButton, SeverityBadge } from "./components";
import { buildGraph, layoutGraph } from "./graphLayout";

const SEVERITY_FILTERS: ReadonlyArray<"" | Finding["severity"]> = [
  "",
  "critical",
  "high",
  "medium",
  "low",
  "info",
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
      <div className="flex gap-2 mb-3">
        {SEVERITY_FILTERS.map((s) => (
          <PillButton
            key={s || "all"}
            active={sev === s}
            onClick={() => setSev(s)}
          >
            {s || "all"}
          </PillButton>
        ))}
      </div>
      <table className="w-full text-sm">
        <thead className="text-slate-400 text-xs uppercase">
          <tr>
            <th className="text-left p-2">Severity</th>
            <th className="text-left p-2">Title</th>
            <th className="text-left p-2">Cloud</th>
            <th className="text-left p-2">Blast</th>
            <th className="text-left p-2">Status</th>
            <th className="text-left p-2">Actions</th>
          </tr>
        </thead>
        <tbody>
          {items.map((f) => (
            <tr key={f.id} className="border-t border-slate-800">
              <td className="p-2">
                <SeverityBadge severity={f.severity} />
              </td>
              <td className="p-2">{f.title}</td>
              <td className="p-2">{f.cloud || "-"}</td>
              <td className="p-2">{f.blastRadius}</td>
              <td className="p-2">{f.status}</td>
              <td className="p-2 flex gap-2">
                <button
                  onClick={() => act(f.id, "confirm")}
                  disabled={pending === f.id}
                  className="text-emerald-400 disabled:opacity-50"
                >
                  confirm
                </button>
                <button
                  onClick={() => act(f.id, "dismiss")}
                  disabled={pending === f.id}
                  className="text-rose-400 disabled:opacity-50"
                >
                  dismiss
                </button>
                <button
                  onClick={() => act(f.id, "escalate")}
                  disabled={pending === f.id}
                  className="text-amber-400 disabled:opacity-50"
                >
                  escalate
                </button>
              </td>
            </tr>
          ))}
          {items.length === 0 && !error && (
            <EmptyRow colSpan={6}>No findings yet - run a scan from /setup/scan.</EmptyRow>
          )}
        </tbody>
      </table>
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
      <div className="flex gap-3 mb-4">
        {COMPLIANCE_FRAMEWORKS.map((f) => (
          <button
            key={f}
            onClick={() => setFramework(f)}
            className={`px-3 py-1 rounded uppercase ${
              framework === f ? "bg-emerald-500 text-slate-950" : "bg-slate-800"
            }`}
          >
            {f}
          </button>
        ))}
      </div>
      <p className="text-slate-400 mb-4">
        Findings mapped to {framework.toUpperCase()} controls: <b>{count ?? "…"}</b>.
      </p>
      <div className="flex gap-2">
        {COMPLIANCE_FORMATS.map(({ format, label, primary }) => (
          <button
            key={format}
            onClick={() => download(format)}
            disabled={downloading !== null}
            className={`px-3 py-2 rounded disabled:opacity-50 ${
              primary ? "bg-emerald-500 text-slate-950" : "bg-slate-800"
            }`}
          >
            {downloading === format ? "Downloading…" : label}
          </button>
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
      <p className="text-slate-400 mb-4">
        Internet → sensitive nodes ranked by blast radius. Click a node for its blast radius.
      </p>
      {nodes.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded mb-4 overflow-hidden">
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
            {graph.edges.map(([s, t]) => {
              const a = pos.get(s);
              const b = pos.get(t);
              if (!a || !b) return null;
              return (
                <line
                  key={`${s}->${t}`}
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
            {nodes.map((n) => {
              const fill = entries.has(n.id)
                ? "#10b981"
                : targets.has(n.id)
                  ? "#f43f5e"
                  : "#64748b";
              return (
                <g
                  key={n.id}
                  onClick={() => pick(n.id)}
                  className="cursor-pointer"
                  data-testid={`graph-node-${n.id}`}
                >
                  <circle
                    cx={n.x}
                    cy={n.y}
                    r={selected === n.id ? 14 : 10}
                    fill={fill}
                    stroke={selected === n.id ? "#f8fafc" : "#0f172a"}
                    strokeWidth="2"
                  />
                  <text
                    x={n.x}
                    y={n.y - 16}
                    textAnchor="middle"
                    fill="#cbd5e1"
                    fontSize="11"
                    fontFamily="monospace"
                  >
                    {n.id}
                  </text>
                </g>
              );
            })}
          </svg>
          {selected && (
            <div className="px-3 py-2 border-t border-slate-800 text-sm text-slate-300">
              <code>{selected}</code>{" "}
              <span className="text-amber-400">
                blast radius {blast ?? "…"}
              </span>
            </div>
          )}
        </div>
      )}
      <ul className="space-y-2">
        {paths.map((p, i) => (
          <li key={i} className="bg-slate-900 border border-slate-800 rounded p-3 text-sm">
            <code>{p.nodes.join(" → ")}</code>{" "}
            <span className="text-amber-400">blast {p.blastRadius}</span>
          </li>
        ))}
        {paths.length === 0 && !error && (
          <li className="text-slate-500">No path data yet - call POST /graph/rebuild.</li>
        )}
      </ul>
    </Page>
  );
}

const REM_CLASS_COLORS: Record<Remediation["class"], string> = {
  destructive: "border-rose-500 text-rose-300",
  reversible: "border-amber-500 text-amber-300",
  safe: "border-emerald-500 text-emerald-300",
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
      <table className="w-full text-sm">
        <thead className="text-slate-400 text-xs uppercase">
          <tr>
            <th className="text-left p-2">Playbook</th>
            <th className="text-left p-2">Finding</th>
            <th className="text-left p-2">Class</th>
            <th className="text-left p-2">State</th>
            <th className="text-left p-2">Action</th>
          </tr>
        </thead>
        <tbody>
          {items.map((r) => (
            <tr key={r.id} className="border-t border-slate-800">
              <td className="p-2 font-mono">{r.playbook_id}</td>
              <td className="p-2 font-mono">{r.finding_id}</td>
              <td className="p-2">
                <span className={`text-xs px-2 py-0.5 rounded border ${REM_CLASS_COLORS[r.class]}`}>
                  {r.class}
                </span>
              </td>
              <td className="p-2">{r.state}</td>
              <td className="p-2 flex gap-2">
                <button
                  onClick={() => decide(r.id, "approve")}
                  disabled={pending === r.id}
                  className="text-emerald-400 disabled:opacity-50"
                >
                  approve
                </button>
                <button
                  onClick={() => decide(r.id, "deny")}
                  disabled={pending === r.id}
                  className="text-rose-400 disabled:opacity-50"
                >
                  deny
                </button>
              </td>
            </tr>
          ))}
          {items.length === 0 && !error && <EmptyRow colSpan={5}>Queue empty.</EmptyRow>}
        </tbody>
      </table>
    </Page>
  );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded p-4">
      <div className="text-xs text-slate-400">{label}</div>
      <div className="text-2xl font-bold">{value}</div>
    </div>
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
        <div className="grid grid-cols-3 gap-4">
          <Stat label="RL updates" value={stats.updates} />
          <Stat label="Feature dim" value={stats.dim} />
          <Stat label="Exploration alpha" value={stats.alpha} />
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
        <div className="bg-slate-900 border border-slate-800 rounded p-4">
          <p className="text-sm">
            Tier: <b className="text-emerald-400">{lic.tier}</b>
          </p>
          <p className="text-sm">Expires: {new Date(lic.expiry * 1000).toLocaleString()}</p>
          <p className="text-sm">Features: {lic.features.join(", ") || "(base)"}</p>
        </div>
      ) : (
        !error && <p className="text-slate-500">No active license.</p>
      )}
    </Page>
  );
}

export function Profile() {
  return (
    <Page title="Profile">
      <p className="text-slate-400 mb-3">
        RBAC roles, API key rotation, and notification preferences land here. Sign out clears the
        local session token.
      </p>
      <button
        onClick={() => {
          localStorage.clear();
          window.location.href = "/license";
        }}
        className="bg-rose-500 text-white px-3 py-2 rounded"
      >
        Clear local state
      </button>
    </Page>
  );
}

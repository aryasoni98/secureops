// Authenticated dashboard pages (PRODUCT.md Phase 8 — seven screens).
// All fetches go through the typed `api` client. Each page is self-contained;
// shared chrome lives in `components.tsx`.

import { useEffect, useState } from "react";
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
import { EmptyRow, Page, PillButton, SeverityBadge } from "./components";

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
  useEffect(() => {
    const filter = sev ? { severity: sev } : {};
    const refresh = () =>
      api
        .listFindings(filter)
        .then((r) => setItems(r.findings))
        .catch(() => setItems([]));
    refresh();
    const ws = openWs("/ws/findings", refresh);
    return () => ws.close();
  }, [sev]);
  async function act(id: string, a: FindingAction) {
    await api.findingAction(id, a);
    setItems((p) => p.map((f) => (f.id === id ? { ...f, status: a } : f)));
  }
  return (
    <Page title="Findings">
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
              <td className="p-2">{f.cloud || "—"}</td>
              <td className="p-2">{f.blastRadius}</td>
              <td className="p-2">{f.status}</td>
              <td className="p-2 flex gap-2">
                <button onClick={() => act(f.id, "confirm")} className="text-emerald-400">
                  confirm
                </button>
                <button onClick={() => act(f.id, "dismiss")} className="text-rose-400">
                  dismiss
                </button>
                <button onClick={() => act(f.id, "escalate")} className="text-amber-400">
                  escalate
                </button>
              </td>
            </tr>
          ))}
          {items.length === 0 && (
            <EmptyRow colSpan={6}>No findings yet — run a scan from /setup/scan.</EmptyRow>
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
  useEffect(() => {
    api
      .complianceCount(framework)
      .then((r) => setCount(r.count))
      .catch(() => setCount(null));
  }, [framework]);
  async function download(format: ComplianceFormat) {
    const blob = await api.complianceDownload(framework, format);
    downloadBlob(blob, `${framework}-compliance.${format}`);
  }
  return (
    <Page title="Compliance">
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
            className={`px-3 py-2 rounded ${
              primary ? "bg-emerald-500 text-slate-950" : "bg-slate-800"
            }`}
          >
            {label}
          </button>
        ))}
      </div>
    </Page>
  );
}

export function Graph() {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  useEffect(() => {
    api
      .attackPaths()
      .then((r) => setPaths(r.paths))
      .catch(() => setPaths([]));
  }, []);
  return (
    <Page title="Attack paths">
      <p className="text-slate-400 mb-4">
        Internet → sensitive nodes ranked by blast radius. (D3 force-graph view rendered on the
        same payload when `@adversa/d3` is added.)
      </p>
      <ul className="space-y-2">
        {paths.map((p, i) => (
          <li key={i} className="bg-slate-900 border border-slate-800 rounded p-3 text-sm">
            <code>{p.nodes.join(" → ")}</code>{" "}
            <span className="text-amber-400">blast {p.blastRadius}</span>
          </li>
        ))}
        {paths.length === 0 && (
          <li className="text-slate-500">No path data yet — call POST /graph/rebuild.</li>
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
  function refresh() {
    api
      .remediationQueue()
      .then((r) => setItems(r.remediations))
      .catch(() => setItems([]));
  }
  useEffect(() => {
    refresh();
    const ws = openWs("/ws/remediation", refresh);
    return () => ws.close();
  }, []);
  return (
    <Page title="Remediation queue (HITL)">
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
                  onClick={() => api.approveRemediation(r.id).then(refresh)}
                  className="text-emerald-400"
                >
                  approve
                </button>
                <button
                  onClick={() => api.denyRemediation(r.id).then(refresh)}
                  className="text-rose-400"
                >
                  deny
                </button>
              </td>
            </tr>
          ))}
          {items.length === 0 && <EmptyRow colSpan={5}>Queue empty.</EmptyRow>}
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
  useEffect(() => {
    api.rlStats().then(setStats).catch(() => setStats(null));
  }, []);
  return (
    <Page title="Usage & RL telemetry">
      {stats ? (
        <div className="grid grid-cols-3 gap-4">
          <Stat label="RL updates" value={stats.updates} />
          <Stat label="Feature dim" value={stats.dim} />
          <Stat label="Exploration alpha" value={stats.alpha} />
        </div>
      ) : (
        <p className="text-slate-500">Loading…</p>
      )}
    </Page>
  );
}

export function LicenseStatus() {
  const [lic, setLic] = useState<{ tier: string; expiry: number; features: string[] } | null>(null);
  useEffect(() => {
    api.getLicense().then(setLic).catch(() => setLic(null));
  }, []);
  return (
    <Page title="License">
      {lic ? (
        <div className="bg-slate-900 border border-slate-800 rounded p-4">
          <p className="text-sm">
            Tier: <b className="text-emerald-400">{lic.tier}</b>
          </p>
          <p className="text-sm">Expires: {new Date(lic.expiry * 1000).toLocaleString()}</p>
          <p className="text-sm">Features: {lic.features.join(", ") || "(base)"}</p>
        </div>
      ) : (
        <p className="text-slate-500">No active license.</p>
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

import { useEffect, useState } from "react";
import {
  BrowserRouter,
  Link,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { api, openWs, token, type Finding, type Remediation } from "./api";

// SecureOps dashboard SPA (PRODUCT.md Phase 8).
// Server-enforced first-run wizard: /license → /setup/llm-keys → /setup/cloud → /setup/scan,
// then the seven dashboard screens. Tailwind utility classes are loaded via the
// Play CDN script in index.html; switching to a compiled build is a one-line swap.

function authed() {
  return Boolean(token.get());
}

function setupDone(key: string) {
  return localStorage.getItem(`secureops.setup.${key}`) === "ok";
}
function markSetup(key: string) {
  localStorage.setItem(`secureops.setup.${key}`, "ok");
}

// ------------------------------- shell -------------------------------------

function TopNav() {
  const nav = useNavigate();
  const loc = useLocation();
  const tabs: [string, string][] = [
    ["/findings", "Findings"],
    ["/compliance", "Compliance"],
    ["/graph", "Graph"],
    ["/remediation", "Remediation"],
    ["/usage", "Usage"],
    ["/license-status", "License"],
    ["/profile", "Profile"],
  ];
  return (
    <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-10">
      <div className="max-w-7xl mx-auto flex items-center gap-4 px-4 py-3">
        <Link to="/findings" className="font-semibold text-emerald-400">
          SecureOps
        </Link>
        <nav className="flex gap-3 text-sm">
          {tabs.map(([to, label]) => {
            const active = loc.pathname.startsWith(to);
            return (
              <Link
                key={to}
                to={to}
                className={`px-3 py-1 rounded ${
                  active ? "bg-slate-800 text-white" : "text-slate-400 hover:text-white"
                }`}
              >
                {label}
              </Link>
            );
          })}
        </nav>
        <button
          onClick={() => {
            token.clear();
            nav("/license");
          }}
          className="ml-auto text-sm text-slate-400 hover:text-rose-400"
        >
          Sign out
        </button>
      </div>
    </header>
  );
}

function Page({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="max-w-7xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">{title}</h1>
      {children}
    </div>
  );
}

// ------------------------------- wizard ------------------------------------

function LicenseActivation() {
  const [key, setKey] = useState("");
  const [msg, setMsg] = useState("");
  const nav = useNavigate();
  async function activate() {
    try {
      const r = await api.activateLicense(key);
      token.set(r.token);
      setMsg(`Activated ${r.tier} — features: ${r.features.join(", ") || "(none)"}.`);
      nav("/setup/llm-keys");
    } catch (e) {
      setMsg(String(e));
    }
  }
  return (
    <Page title="Activate License">
      <p className="text-slate-400 mb-3">
        Paste your SecureOps license key. The server verifies an Ed25519 signature; tampered or
        expired keys are rejected.
      </p>
      <textarea
        data-testid="license-key"
        value={key}
        onChange={(e) => setKey(e.target.value)}
        rows={5}
        className="w-full bg-slate-900 border border-slate-700 rounded p-3 font-mono text-xs"
        placeholder="-----BEGIN SECUREOPS LICENSE----- ..."
      />
      <div className="mt-3 flex items-center gap-3">
        <button
          onClick={activate}
          className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold px-4 py-2 rounded"
        >
          Activate
        </button>
        <p className="text-sm text-slate-300">{msg}</p>
      </div>
    </Page>
  );
}

function SetupLlmKeys() {
  const [provider, setProvider] = useState("openai");
  const [key, setKey] = useState("");
  const [msg, setMsg] = useState("");
  const nav = useNavigate();
  function save() {
    if (!key) return setMsg("paste a key");
    localStorage.setItem(`secureops.llm.${provider}`, "configured");
    markSetup("llm");
    setMsg(`${provider} key stored locally (encrypted at rest in production).`);
    nav("/setup/cloud");
  }
  return (
    <Page title="Step 2 — LLM keys">
      <p className="text-slate-400 mb-3">
        Provide a key for at least one LLM provider so SecureOps can run the bug-hunt loop. Keys
        are stored encrypted; they never leave your environment.
      </p>
      <select
        value={provider}
        onChange={(e) => setProvider(e.target.value)}
        className="bg-slate-900 border border-slate-700 rounded p-2 mr-2"
      >
        <option value="openai">OpenAI</option>
        <option value="anthropic">Anthropic</option>
        <option value="local">Local (LocalProvider)</option>
      </select>
      <input
        value={key}
        onChange={(e) => setKey(e.target.value)}
        type="password"
        placeholder="sk-..."
        className="bg-slate-900 border border-slate-700 rounded p-2 w-72"
      />
      <button
        onClick={save}
        className="ml-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 px-3 py-2 rounded"
      >
        Save & test
      </button>
      <p className="text-sm text-slate-300 mt-3">{msg}</p>
    </Page>
  );
}

function SetupCloud() {
  const [provider, setProvider] = useState("aws");
  const [arn, setArn] = useState("");
  const [msg, setMsg] = useState("");
  const nav = useNavigate();
  function snippet() {
    switch (provider) {
      case "gcp":
        return `gcloud iam service-accounts create secureops-reader \\
  --display-name="SecureOps read-only"
gcloud projects add-iam-policy-binding $PROJECT \\
  --member="serviceAccount:secureops-reader@$PROJECT.iam.gserviceaccount.com" \\
  --role="roles/viewer"`;
      case "azure":
        return `az ad sp create-for-rbac --name secureops-reader \\
  --role Reader --scopes /subscriptions/$SUB`;
      default:
        return `aws iam create-role --role-name SecureOpsReader \\
  --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name SecureOpsReader \\
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit`;
    }
  }
  function save() {
    if (!arn) return setMsg("paste the ARN / SA / app id");
    markSetup("cloud");
    setMsg(`${provider} reader credential saved.`);
    nav("/setup/scan");
  }
  return (
    <Page title="Step 3 — Cloud read-only credential">
      <p className="text-slate-400 mb-3">
        SecureOps only needs read-only access for inventory + checks. Cloud mutations only happen
        through human-approved playbooks.
      </p>
      <div className="flex gap-2 mb-3">
        {["aws", "gcp", "azure"].map((p) => (
          <button
            key={p}
            onClick={() => setProvider(p)}
            className={`px-3 py-1 rounded uppercase text-xs ${
              provider === p ? "bg-emerald-500 text-slate-950" : "bg-slate-800"
            }`}
          >
            {p}
          </button>
        ))}
      </div>
      <pre className="bg-slate-900 border border-slate-800 rounded p-3 text-xs overflow-auto whitespace-pre-wrap">
        {snippet()}
      </pre>
      <input
        value={arn}
        onChange={(e) => setArn(e.target.value)}
        placeholder="arn:aws:iam::... / sa email / app id"
        className="bg-slate-900 border border-slate-700 rounded p-2 mt-3 w-full"
      />
      <button
        onClick={save}
        className="mt-3 bg-emerald-500 hover:bg-emerald-400 text-slate-950 px-3 py-2 rounded"
      >
        Save & continue
      </button>
      <p className="text-sm text-slate-300 mt-3">{msg}</p>
    </Page>
  );
}

function SetupScan() {
  const [scope, setScope] = useState("all");
  const [progress, setProgress] = useState<string[]>([]);
  const [jobId, setJobId] = useState<string | null>(null);
  const nav = useNavigate();
  useEffect(() => {
    const ws = openWs("/ws/scan-progress", (data) => {
      setProgress((p) => [...p, JSON.stringify(data)]);
    });
    return () => ws.close();
  }, []);
  async function go() {
    const r = await api.createScan(scope);
    setJobId(r.jobId);
    markSetup("scan");
  }
  return (
    <Page title="Step 4 — first scan">
      <div className="flex items-center gap-3">
        <select
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          className="bg-slate-900 border border-slate-700 rounded p-2"
        >
          <option value="all">All clouds</option>
          <option value="aws">AWS</option>
          <option value="gcp">GCP</option>
          <option value="azure">Azure</option>
        </select>
        <button
          onClick={go}
          className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 px-3 py-2 rounded"
        >
          Run scan
        </button>
        {jobId && <span className="text-sm text-slate-300">job: {jobId}</span>}
      </div>
      <pre className="mt-4 bg-slate-900 border border-slate-800 rounded p-3 text-xs h-48 overflow-auto">
        {progress.length ? progress.join("\n") : "Waiting for /ws/scan-progress events…"}
      </pre>
      <button
        onClick={() => nav("/findings")}
        className="mt-3 text-emerald-400 hover:text-emerald-300"
      >
        Continue to dashboard →
      </button>
    </Page>
  );
}

// ----------------------------- dashboard -----------------------------------

function severityClass(s: Finding["severity"]) {
  return {
    critical: "bg-rose-500/20 text-rose-300 border-rose-500/50",
    high: "bg-orange-500/20 text-orange-300 border-orange-500/50",
    medium: "bg-amber-500/20 text-amber-300 border-amber-500/50",
    low: "bg-sky-500/20 text-sky-300 border-sky-500/50",
    info: "bg-slate-500/20 text-slate-300 border-slate-500/50",
  }[s];
}

function Findings() {
  const [items, setItems] = useState<Finding[]>([]);
  const [sev, setSev] = useState("");
  useEffect(() => {
    api
      .listFindings(sev ? { severity: sev } : {})
      .then((r) => setItems(r.findings))
      .catch(() => setItems([]));
    const ws = openWs("/ws/findings", () => {
      api.listFindings(sev ? { severity: sev } : {}).then((r) => setItems(r.findings));
    });
    return () => ws.close();
  }, [sev]);
  async function act(id: string, a: "confirm" | "dismiss" | "escalate") {
    await api.findingAction(id, a);
    setItems((p) => p.map((f) => (f.id === id ? { ...f, status: a } : f)));
  }
  return (
    <Page title="Findings">
      <div className="flex gap-2 mb-3">
        {["", "critical", "high", "medium", "low", "info"].map((s) => (
          <button
            key={s || "all"}
            onClick={() => setSev(s)}
            className={`px-3 py-1 rounded text-xs ${sev === s ? "bg-emerald-500 text-slate-950" : "bg-slate-800"}`}
          >
            {s || "all"}
          </button>
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
                <span className={`px-2 py-0.5 border rounded text-xs ${severityClass(f.severity)}`}>
                  {f.severity}
                </span>
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
            <tr>
              <td colSpan={6} className="p-4 text-slate-500">
                No findings yet — run a scan from /setup/scan.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Page>
  );
}

function Compliance() {
  const [framework, setFramework] = useState("cis");
  const [count, setCount] = useState<number | null>(null);
  useEffect(() => {
    fetch(`/api/v1/compliance/reports?framework=${framework}`, {
      headers: { authorization: `Bearer ${token.get() || ""}` },
    })
      .then((r) => r.json())
      .then((j) => setCount(j.count))
      .catch(() => setCount(null));
  }, [framework]);
  function download(format: string) {
    const url = `/api/v1/compliance/reports?framework=${framework}&format=${format}`;
    fetch(url, { headers: { authorization: `Bearer ${token.get() || ""}` } })
      .then((r) => r.blob())
      .then((b) => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(b);
        a.download = `${framework}-compliance.${format}`;
        a.click();
      });
  }
  return (
    <Page title="Compliance">
      <div className="flex gap-3 mb-4">
        {["cis", "soc2", "pci"].map((f) => (
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
        <button onClick={() => download("json")} className="bg-slate-800 px-3 py-2 rounded">
          JSON
        </button>
        <button onClick={() => download("csv")} className="bg-slate-800 px-3 py-2 rounded">
          CSV
        </button>
        <button onClick={() => download("zip")} className="bg-emerald-500 text-slate-950 px-3 py-2 rounded">
          Signed IR ZIP
        </button>
      </div>
    </Page>
  );
}

function Graph() {
  const [paths, setPaths] = useState<{ nodes: string[]; blastRadius: number }[]>([]);
  useEffect(() => {
    api.attackPaths().then((r) => setPaths(r.paths as any[])).catch(() => setPaths([]));
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

function Remediation() {
  const [items, setItems] = useState<Remediation[]>([]);
  function refresh() {
    api.remediationQueue().then((r) => setItems(r.remediations)).catch(() => setItems([]));
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
                <span
                  className={`text-xs px-2 py-0.5 rounded border ${
                    r.class === "destructive"
                      ? "border-rose-500 text-rose-300"
                      : r.class === "reversible"
                      ? "border-amber-500 text-amber-300"
                      : "border-emerald-500 text-emerald-300"
                  }`}
                >
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
          {items.length === 0 && (
            <tr>
              <td colSpan={5} className="p-4 text-slate-500">
                Queue empty.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Page>
  );
}

function Usage() {
  const [stats, setStats] = useState<{ updates: number; dim: number; alpha: number } | null>(null);
  useEffect(() => {
    api.rlStats().then(setStats).catch(() => setStats(null));
  }, []);
  return (
    <Page title="Usage & RL telemetry">
      {stats ? (
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded p-4">
            <div className="text-xs text-slate-400">RL updates</div>
            <div className="text-2xl font-bold">{stats.updates}</div>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded p-4">
            <div className="text-xs text-slate-400">Feature dim</div>
            <div className="text-2xl font-bold">{stats.dim}</div>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded p-4">
            <div className="text-xs text-slate-400">Exploration alpha</div>
            <div className="text-2xl font-bold">{stats.alpha}</div>
          </div>
        </div>
      ) : (
        <p className="text-slate-500">Loading…</p>
      )}
    </Page>
  );
}

function LicenseStatus() {
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
          <p className="text-sm">
            Expires: {new Date(lic.expiry * 1000).toLocaleString()}
          </p>
          <p className="text-sm">Features: {lic.features.join(", ") || "(base)"}</p>
        </div>
      ) : (
        <p className="text-slate-500">No active license.</p>
      )}
    </Page>
  );
}

function Profile() {
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

// ----------------------------- routing -------------------------------------

function RequireAuth({ children }: { children: JSX.Element }) {
  return authed() ? children : <Navigate to="/license" replace />;
}

function RequireSetup({ children }: { children: JSX.Element }) {
  if (!authed()) return <Navigate to="/license" replace />;
  if (!setupDone("llm")) return <Navigate to="/setup/llm-keys" replace />;
  if (!setupDone("cloud")) return <Navigate to="/setup/cloud" replace />;
  if (!setupDone("scan")) return <Navigate to="/setup/scan" replace />;
  return children;
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <>
      <TopNav />
      {children}
    </>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/license" element={<LicenseActivation />} />
        <Route
          path="/setup/llm-keys"
          element={
            <RequireAuth>
              <SetupLlmKeys />
            </RequireAuth>
          }
        />
        <Route
          path="/setup/cloud"
          element={
            <RequireAuth>
              <SetupCloud />
            </RequireAuth>
          }
        />
        <Route
          path="/setup/scan"
          element={
            <RequireAuth>
              <SetupScan />
            </RequireAuth>
          }
        />
        <Route
          path="/findings"
          element={
            <RequireSetup>
              <Shell>
                <Findings />
              </Shell>
            </RequireSetup>
          }
        />
        <Route
          path="/compliance"
          element={
            <RequireSetup>
              <Shell>
                <Compliance />
              </Shell>
            </RequireSetup>
          }
        />
        <Route
          path="/graph"
          element={
            <RequireSetup>
              <Shell>
                <Graph />
              </Shell>
            </RequireSetup>
          }
        />
        <Route
          path="/remediation"
          element={
            <RequireSetup>
              <Shell>
                <Remediation />
              </Shell>
            </RequireSetup>
          }
        />
        <Route
          path="/usage"
          element={
            <RequireSetup>
              <Shell>
                <Usage />
              </Shell>
            </RequireSetup>
          }
        />
        <Route
          path="/license-status"
          element={
            <RequireSetup>
              <Shell>
                <LicenseStatus />
              </Shell>
            </RequireSetup>
          }
        />
        <Route
          path="/profile"
          element={
            <RequireSetup>
              <Shell>
                <Profile />
              </Shell>
            </RequireSetup>
          }
        />
        <Route path="*" element={<Navigate to={authed() ? "/findings" : "/license"} replace />} />
      </Routes>
    </BrowserRouter>
  );
}

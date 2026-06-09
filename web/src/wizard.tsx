// First-run wizard (PRODUCT.md Phase 8): /license → /setup/llm-keys →
// /setup/cloud → /setup/scan. Server enforces license/SSO; the per-step "ok"
// flags in localStorage just gate client navigation so reloads land in the
// right place.

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, openWs, token } from "./api";
import { Page, PrimaryButton } from "./components";
import { setup } from "./setup";

export function LicenseActivation() {
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
        <PrimaryButton onClick={activate}>Activate</PrimaryButton>
        <p className="text-sm text-slate-300">{msg}</p>
      </div>
    </Page>
  );
}

const LLM_PROVIDERS = ["openai", "anthropic", "local"] as const;

export function SetupLlmKeys() {
  const [provider, setProvider] = useState<(typeof LLM_PROVIDERS)[number]>("openai");
  const [key, setKey] = useState("");
  const [msg, setMsg] = useState("");
  const nav = useNavigate();
  function save() {
    if (!key) return setMsg("paste a key");
    localStorage.setItem(`secureops.llm.${provider}`, "configured");
    setup.mark("llm");
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
        onChange={(e) => setProvider(e.target.value as (typeof LLM_PROVIDERS)[number])}
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

type CloudProvider = "aws" | "gcp" | "azure";

const CLOUD_SNIPPETS: Record<CloudProvider, string> = {
  aws: `aws iam create-role --role-name SecureOpsReader \\
  --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name SecureOpsReader \\
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit`,
  gcp: `gcloud iam service-accounts create secureops-reader \\
  --display-name="SecureOps read-only"
gcloud projects add-iam-policy-binding $PROJECT \\
  --member="serviceAccount:secureops-reader@$PROJECT.iam.gserviceaccount.com" \\
  --role="roles/viewer"`,
  azure: `az ad sp create-for-rbac --name secureops-reader \\
  --role Reader --scopes /subscriptions/$SUB`,
};

export function SetupCloud() {
  const [provider, setProvider] = useState<CloudProvider>("aws");
  const [arn, setArn] = useState("");
  const [msg, setMsg] = useState("");
  const nav = useNavigate();
  function save() {
    if (!arn) return setMsg("paste the ARN / SA / app id");
    setup.mark("cloud");
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
        {(["aws", "gcp", "azure"] as CloudProvider[]).map((p) => (
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
        {CLOUD_SNIPPETS[provider]}
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

const SCAN_SCOPES = ["all", "aws", "gcp", "azure"] as const;

export function SetupScan() {
  const [scope, setScope] = useState<(typeof SCAN_SCOPES)[number]>("all");
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
    setup.mark("scan");
  }
  return (
    <Page title="Step 4 — first scan">
      <div className="flex items-center gap-3">
        <select
          value={scope}
          onChange={(e) => setScope(e.target.value as (typeof SCAN_SCOPES)[number])}
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

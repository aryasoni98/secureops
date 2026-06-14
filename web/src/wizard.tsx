// First-run wizard (PRODUCT.md Phase 8): /license → /setup/llm-keys →
// /setup/cloud → /setup/scan. Server enforces license/SSO; the per-step "ok"
// flags in localStorage just gate client navigation so reloads land in the
// right place.

import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, openWs, token } from "./api";
import { AmbientBackground, Page, PrimaryButton } from "./components";
import { setup } from "./setup";

// --------------------------- step indicator ---------------------------------

const STEPS = ["License", "LLM keys", "Cloud", "First scan"] as const;

function StepProgress({ current }: { current: number }) {
  return (
    <div className="max-w-7xl mx-auto px-6 pt-8">
      <div className="flex items-center gap-0 max-w-2xl">
        {STEPS.map((label, i) => {
          const done = i < current;
          const active = i === current;
          return (
            <div key={label} className={`flex items-center ${i > 0 ? "flex-1" : ""}`}>
              {i > 0 && (
                <div className="flex-1 h-[2px] mx-2 bg-white/[0.08] relative overflow-hidden rounded-full">
                  <motion.div
                    initial={{ scaleX: 0 }}
                    animate={{ scaleX: done || active ? 1 : 0 }}
                    transition={{ duration: 0.5, ease: "easeOut" }}
                    className="absolute inset-0 origin-left bg-gradient-to-r from-emerald-400 to-teal-400"
                  />
                </div>
              )}
              <motion.div
                initial={{ scale: 0.6, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ delay: i * 0.08, type: "spring", stiffness: 300, damping: 20 }}
                className="flex items-center gap-2 shrink-0"
              >
                <span
                  className={`flex items-center justify-center w-7 h-7 rounded-full text-xs font-bold border transition-colors duration-300 ${
                    done
                      ? "bg-emerald-500 border-emerald-500 text-slate-950"
                      : active
                        ? "bg-emerald-500/15 border-emerald-400 text-emerald-300 shadow-glow"
                        : "bg-white/[0.04] border-white/[0.12] text-slate-500"
                  }`}
                >
                  {done ? "✓" : i + 1}
                </span>
                <span
                  className={`text-xs font-medium hidden sm:inline ${
                    active ? "text-white" : done ? "text-emerald-300" : "text-slate-500"
                  }`}
                >
                  {label}
                </span>
              </motion.div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** Shared chrome for wizard screens (no TopNav yet - user isn't set up). */
function WizardFrame({ step, children }: { step: number; children: React.ReactNode }) {
  return (
    <>
      <AmbientBackground />
      <StepProgress current={step} />
      {children}
    </>
  );
}

const inputClass =
  "bg-white/[0.04] border border-white/[0.1] rounded-xl p-3 focus:outline-none focus:border-emerald-400/60 focus:ring-2 focus:ring-emerald-400/20 transition-all duration-200 placeholder:text-slate-600";

// ------------------------------- steps ---------------------------------------

export function LicenseActivation() {
  const [key, setKey] = useState("");
  const [msg, setMsg] = useState("");
  const nav = useNavigate();
  async function activate() {
    try {
      const r = await api.activateLicense(key);
      token.set(r.token);
      setMsg(`Activated ${r.tier} - features: ${r.features.join(", ") || "(none)"}.`);
      nav("/setup/llm-keys");
    } catch (e) {
      setMsg(String(e));
    }
  }
  return (
    <WizardFrame step={0}>
      <Page title="Activate License">
        <p className="text-slate-400 mb-4 max-w-2xl">
          Paste your SecureOps license key. The server verifies an Ed25519 signature; tampered or
          expired keys are rejected.
        </p>
        <motion.textarea
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          data-testid="license-key"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          rows={5}
          className={`w-full font-mono text-xs ${inputClass}`}
          placeholder="-----BEGIN SECUREOPS LICENSE----- ..."
        />
        <div className="mt-4 flex items-center gap-3">
          <PrimaryButton onClick={activate}>Activate</PrimaryButton>
          <p className="text-sm text-slate-300">{msg}</p>
        </div>
      </Page>
    </WizardFrame>
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
    // Only a "configured" marker is kept client-side - never the key itself.
    // The key must be supplied to the API/scanner via env (OPENAI_API_KEY /
    // ANTHROPIC_API_KEY); see docs.
    localStorage.setItem(`secureops.llm.${provider}`, "configured");
    setup.mark("llm");
    setMsg(`${provider} marked configured - set the key as an env var on the API/scanner.`);
    nav("/setup/cloud");
  }
  return (
    <WizardFrame step={1}>
      <Page title="Step 2 - LLM keys">
        <p className="text-slate-400 mb-4 max-w-2xl">
          Provide a key for at least one LLM provider so SecureOps can run the bug-hunt loop. The
          key itself is never stored in the browser - configure it as an environment variable on
          the API/scanner (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY`); this step only records which
          provider you chose.
        </p>
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="flex items-center gap-3 flex-wrap"
        >
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value as (typeof LLM_PROVIDERS)[number])}
            className={inputClass}
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
            className={`w-72 ${inputClass}`}
          />
          <PrimaryButton onClick={save}>Save &amp; test</PrimaryButton>
        </motion.div>
        <p className="text-sm text-slate-300 mt-4">{msg}</p>
      </Page>
    </WizardFrame>
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
    <WizardFrame step={2}>
      <Page title="Step 3 - Cloud read-only credential">
        <p className="text-slate-400 mb-4 max-w-2xl">
          SecureOps only needs read-only access for inventory + checks. Cloud mutations only happen
          through human-approved playbooks.
        </p>
        <div className="flex gap-2 mb-4">
          {(["aws", "gcp", "azure"] as CloudProvider[]).map((p) => (
            <motion.button
              key={p}
              whileHover={{ scale: 1.06 }}
              whileTap={{ scale: 0.94 }}
              onClick={() => setProvider(p)}
              className={`px-3.5 py-1.5 rounded-full uppercase text-xs font-semibold border transition-colors duration-200 ${
                provider === p
                  ? "bg-gradient-to-r from-emerald-500 to-teal-400 text-slate-950 border-transparent shadow-glow"
                  : "bg-white/[0.04] border-white/[0.08] text-slate-300 hover:bg-white/[0.08]"
              }`}
            >
              {p}
            </motion.button>
          ))}
        </div>
        <motion.pre
          key={provider}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="glass p-4 text-xs overflow-auto whitespace-pre-wrap font-mono text-slate-300"
        >
          {CLOUD_SNIPPETS[provider]}
        </motion.pre>
        <input
          value={arn}
          onChange={(e) => setArn(e.target.value)}
          placeholder="arn:aws:iam::... / sa email / app id"
          className={`mt-4 w-full ${inputClass}`}
        />
        <div className="mt-4">
          <PrimaryButton onClick={save}>Save &amp; continue</PrimaryButton>
        </div>
        <p className="text-sm text-slate-300 mt-4">{msg}</p>
      </Page>
    </WizardFrame>
  );
}

const SCAN_SCOPES = ["all", "aws", "gcp", "azure"] as const;

export function SetupScan() {
  const [scope, setScope] = useState<(typeof SCAN_SCOPES)[number]>("all");
  const [progress, setProgress] = useState<string[]>([]);
  const [jobId, setJobId] = useState<string | null>(null);
  const [msg, setMsg] = useState("");
  const [starting, setStarting] = useState(false);
  const nav = useNavigate();
  // The progress socket is only opened once a scan has actually started.
  useEffect(() => {
    if (!jobId) return;
    const ws = openWs("/ws/scan-progress", (data) => {
      setProgress((p) => [...p, JSON.stringify(data)]);
    });
    return () => ws.close();
  }, [jobId]);
  async function go() {
    setStarting(true);
    try {
      const r = await api.createScan(scope);
      setJobId(r.jobId);
      setup.mark("scan");
      setMsg("");
    } catch {
      setMsg("Could not start the scan - is the API reachable?");
    } finally {
      setStarting(false);
    }
  }
  return (
    <WizardFrame step={3}>
      <Page title="Step 4 - first scan">
        <div className="flex items-center gap-3">
          <select
            value={scope}
            onChange={(e) => setScope(e.target.value as (typeof SCAN_SCOPES)[number])}
            className={inputClass}
          >
            <option value="all">All clouds</option>
            <option value="aws">AWS</option>
            <option value="gcp">GCP</option>
            <option value="azure">Azure</option>
          </select>
          <PrimaryButton onClick={go} disabled={starting}>
            {starting ? "Starting…" : "Run scan"}
          </PrimaryButton>
          {jobId && (
            <motion.span
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-sm text-slate-300"
            >
              job: {jobId}
            </motion.span>
          )}
          {msg && <span className="text-sm text-rose-300">{msg}</span>}
        </div>
        <motion.pre
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="mt-5 glass p-4 text-xs h-48 overflow-auto font-mono text-slate-300"
        >
          {progress.length
            ? progress.join("\n")
            : jobId
              ? "Waiting for /ws/scan-progress events…"
              : "Start a scan to stream progress here."}
        </motion.pre>
        <motion.button
          whileHover={{ x: 4 }}
          onClick={() => nav("/findings")}
          className="mt-4 text-emerald-400 hover:text-emerald-300 font-medium transition-colors"
        >
          Continue to dashboard →
        </motion.button>
      </Page>
    </WizardFrame>
  );
}

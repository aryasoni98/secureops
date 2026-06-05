import { useEffect, useState } from "react";
import {
  BrowserRouter,
  Link,
  Navigate,
  Route,
  Routes,
  useNavigate,
} from "react-router-dom";
import { api, token } from "./api";

// NOTE: scaffold UI (PRODUCT.md Phase 8). Wires to the real API; visual polish
// (Tailwind/shadcn), D3 graph view, and Playwright E2E are follow-on work.

function useAuthed() {
  return Boolean(token.get());
}

function Nav() {
  return (
    <nav style={{ display: "flex", gap: 12, padding: 12, borderBottom: "1px solid #ddd" }}>
      <Link to="/findings">Findings</Link>
      <Link to="/graph">Attack Paths</Link>
      <Link to="/remediation">Remediation</Link>
      <Link to="/license">License</Link>
    </nav>
  );
}

function LicenseActivation() {
  const [key, setKey] = useState("");
  const [msg, setMsg] = useState("");
  const nav = useNavigate();
  async function activate() {
    try {
      const r = await api.activateLicense(key);
      token.set(r.token);
      setMsg(`Activated: ${r.tier} (${r.features.join(", ")})`);
      nav("/findings");
    } catch (e) {
      setMsg(String(e));
    }
  }
  return (
    <div style={{ padding: 24, maxWidth: 640 }}>
      <h1>Activate License</h1>
      <p>Paste your SecureOps license key to begin.</p>
      <textarea value={key} onChange={(e) => setKey(e.target.value)} rows={4} style={{ width: "100%" }} />
      <button onClick={activate}>Activate</button>
      <p>{msg}</p>
    </div>
  );
}

function Findings() {
  const [count, setCount] = useState<number | null>(null);
  useEffect(() => {
    api.listFindings().then((r) => setCount(r.count)).catch(() => setCount(-1));
  }, []);
  return (
    <div style={{ padding: 24 }}>
      <h1>Findings</h1>
      <p>RL-ranked findings. Count: {count ?? "…"}</p>
    </div>
  );
}

function Graph() {
  const [paths, setPaths] = useState<number | null>(null);
  useEffect(() => {
    api.attackPaths().then((r) => setPaths(r.paths.length)).catch(() => setPaths(-1));
  }, []);
  return (
    <div style={{ padding: 24 }}>
      <h1>Attack Paths</h1>
      <p>Internet→sensitive paths (D3 force graph TODO). Paths: {paths ?? "…"}</p>
    </div>
  );
}

function Remediation() {
  const [items, setItems] = useState<unknown[]>([]);
  useEffect(() => {
    api.remediationQueue().then((r) => setItems(r.remediations)).catch(() => setItems([]));
  }, []);
  return (
    <div style={{ padding: 24 }}>
      <h1>Remediation Queue</h1>
      <p>HITL approvals. Queued: {items.length}</p>
    </div>
  );
}

function Protected({ children }: { children: JSX.Element }) {
  return useAuthed() ? children : <Navigate to="/license" replace />;
}

export function App() {
  return (
    <BrowserRouter>
      {useAuthed() && <Nav />}
      <Routes>
        <Route path="/license" element={<LicenseActivation />} />
        <Route path="/findings" element={<Protected><Findings /></Protected>} />
        <Route path="/graph" element={<Protected><Graph /></Protected>} />
        <Route path="/remediation" element={<Protected><Remediation /></Protected>} />
        <Route path="*" element={<Navigate to={useAuthed() ? "/findings" : "/license"} replace />} />
      </Routes>
    </BrowserRouter>
  );
}

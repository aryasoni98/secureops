// Thin typed client for the SecureOps platform API (PRODUCT.md Phase 8).
// The session token from /license/activate or SSO is kept in localStorage.

const TOKEN_KEY = "secureops.token";

export const token = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const t = token.get();
  if (t) headers["authorization"] = `Bearer ${t}`;
  const res = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
  return (await res.json()) as T;
}

export interface ActivateResp {
  tier: string;
  expiry: number;
  features: string[];
  token: string;
}

export const api = {
  activateLicense: (key: string) =>
    req<ActivateResp>("POST", "/license/activate", { key }),
  listFindings: () => req<{ findings: unknown[]; count: number }>("GET", "/findings"),
  attackPaths: () => req<{ paths: unknown[] }>("GET", "/graph/paths"),
  rebuildGraph: (spec: unknown) => req("POST", "/graph/rebuild", spec),
  runBugHunt: (scope: string) => req<{ jobId: string }>("POST", "/bughunt", { scope }),
  remediationQueue: () => req<{ remediations: unknown[] }>("GET", "/remediations/queue"),
  approveRemediation: (id: string) => req("POST", `/remediations/${id}/approve`, {}),
  rlStats: () => req<{ updates: number }>("GET", "/rl/stats"),
};

// Thin typed client for the SecureOps platform API (PRODUCT.md Phase 8).
// The session token from /license/activate or SSO is kept in localStorage.

const TOKEN_KEY = "secureops.token";

export const token = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

function authHeader(): Record<string, string> {
  const t = token.get();
  return t ? { authorization: `Bearer ${t}` } : {};
}

/** API failure with the HTTP status attached. The user-facing message is kept
 * short and generic; the full response body goes to the console only. */
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function rawFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...authHeader(),
    ...((init.headers as Record<string, string>) || {}),
  };
  const res = await fetch(`/api/v1${path}`, { ...init, headers });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    console.error(`API ${init.method ?? "GET"} ${path} → ${res.status}`, body);
    throw new ApiError(res.status, `Request failed (${res.status})`);
  }
  return res;
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await rawFetch(path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

async function reqBlob(path: string): Promise<Blob> {
  const res = await rawFetch(path, { method: "GET" });
  return res.blob();
}

export interface ActivateResp {
  tier: string;
  expiry: number;
  features: string[];
  token: string;
}

export interface Finding {
  id: string;
  tenantId: string;
  scanId?: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: string;
  cloud?: string;
  blastRadius: number;
}

export type FindingAction = "confirm" | "dismiss" | "escalate";

export interface Remediation {
  id: string;
  finding_id: string;
  playbook_id: string;
  class: "safe" | "reversible" | "destructive";
  state: "pending" | "completed" | "rolled_back" | "aborted" | "failed";
}

export interface AttackPath {
  nodes: string[];
  blastRadius: number;
}

export type ComplianceFormat = "json" | "csv" | "zip";

function findingsQuery(filter: { severity?: string; status?: string }): string {
  const qs = new URLSearchParams();
  if (filter.severity) qs.set("severity", filter.severity);
  if (filter.status) qs.set("status", filter.status);
  const s = qs.toString();
  return s ? `?${s}` : "";
}

export const api = {
  activateLicense: (key: string) =>
    req<ActivateResp>("POST", "/license/activate", { key }),
  getLicense: () => req<{ tier: string; expiry: number; features: string[] }>("GET", "/license"),
  listFindings: (filter: { severity?: string; status?: string } = {}) =>
    req<{ findings: Finding[]; count: number }>("GET", `/findings${findingsQuery(filter)}`),
  findingAction: (id: string, action: FindingAction) =>
    req<{ id: string; status: string }>("POST", `/findings/${id}/action`, { action }),
  attackPaths: () => req<{ paths: AttackPath[] }>("GET", "/graph/paths"),
  blastRadius: (node: string) =>
    req<{ node: string; blastRadius: number }>("GET", `/graph/blast-radius/${node}`),
  rebuildGraph: (spec: unknown) => req("POST", "/graph/rebuild", spec),
  runBugHunt: (scope: string) => req<{ jobId: string; status: string }>("POST", "/bughunt", { scope }),
  getBugHunt: (id: string) => req<{ status: string; report?: unknown }>("GET", `/bughunt/${id}`),
  remediationQueue: () => req<{ remediations: Remediation[] }>("GET", "/remediations/queue"),
  queueRemediation: (finding_id: string, playbook_id: string) =>
    req<Remediation>("POST", "/remediations", { finding_id, playbook_id }),
  approveRemediation: (id: string) =>
    req<{ id: string; state: string; executed: boolean }>("POST", `/remediations/${id}/approve`, {}),
  denyRemediation: (id: string) =>
    req<{ id: string; state: string }>("POST", `/remediations/${id}/deny`, {}),
  resetCircuit: (cls: string) =>
    req<{ class: string; halted: boolean }>("POST", `/remediations/circuit/${cls}/reset`, {}),
  rlStats: () => req<{ updates: number; dim: number; alpha: number }>("GET", "/rl/stats"),
  rlFeedback: (body: {
    severity: number;
    blast_radius_norm: number;
    exposed: boolean;
    rule_category: number;
    cloud: number;
    recency: number;
    action: FindingAction;
    finding_id?: string;
  }) => req<{ updates: number }>("POST", "/rl/feedback", body),
  createScan: (scope: string) =>
    req<{ jobId: string; status: string }>("POST", "/scans", { scope }),
  complianceCount: (framework: string) =>
    req<{ count: number }>("GET", `/compliance/reports?framework=${framework}`),
  complianceDownload: (framework: string, format: ComplianceFormat) =>
    reqBlob(`/compliance/reports?framework=${framework}&format=${format}`),
};

/** Trigger a browser download from a blob. */
export function downloadBlob(blob: Blob, filename: string): void {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

/** Handle returned by [`openWs`]; `close()` also cancels any pending reconnect. */
export interface WsHandle {
  close: () => void;
}

/** WebSocket helper that JSON-parses messages (falling back to raw text) and
 * reconnects with exponential backoff (1s → 30s cap) when the connection
 * drops. `close()` stops the socket and the reconnect loop. */
export function openWs(path: string, onMsg: (data: unknown) => void): WsHandle {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  let ws: WebSocket | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let closed = false;
  let attempt = 0;

  function connect() {
    ws = new WebSocket(`${proto}://${window.location.host}${path}`);
    ws.onopen = () => {
      attempt = 0;
    };
    ws.onmessage = (ev) => {
      try {
        onMsg(JSON.parse(ev.data));
      } catch {
        onMsg(ev.data);
      }
    };
    ws.onerror = () => {
      console.warn(`ws ${path}: error`);
    };
    ws.onclose = () => {
      if (closed) return;
      const delay = Math.min(1000 * 2 ** attempt, 30_000);
      attempt += 1;
      timer = setTimeout(connect, delay);
    };
  }
  connect();

  return {
    close: () => {
      closed = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    },
  };
}

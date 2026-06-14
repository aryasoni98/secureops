import type { Finding } from "./api";

/** Playbook ids shipped with secureops-selfheal sample_playbooks(). */
export interface PlaybookMatch {
  playbookId: string;
  class: "safe" | "reversible" | "destructive";
  summary: string;
}

const PLAYBOOK_RULES: ReadonlyArray<{
  id: string;
  class: PlaybookMatch["class"];
  summary: string;
  test: (title: string) => boolean;
}> = [
  {
    id: "s3-public-acl",
    class: "reversible",
    summary: "Remove public ACL / block public access on the S3 bucket.",
    test: (t) => /s3|bucket|public|acl|allusers|allusers/i.test(t),
  },
  {
    id: "sg-open-ssh-world",
    class: "reversible",
    summary: "Revoke world-open SSH (0.0.0.0/0:22) from the security group.",
    test: (t) =>
      /security group|sg-|0\.0\.0\.0|ssh|:22|ingress|open.*port/i.test(t),
  },
  {
    id: "gcs-public-bucket",
    class: "reversible",
    summary: "Remove allUsers/allAuthenticatedUsers from GCS bucket IAM.",
    test: (t) => /gcs|google.*storage|allusers/i.test(t),
  },
  {
    id: "k8s-privileged-pod",
    class: "destructive",
    summary: "Delete or restrict privileged Kubernetes workload.",
    test: (t) => /privileged|kubernetes|k8s|pod|container/i.test(t),
  },
  {
    id: "enable-cloudtrail",
    class: "safe",
    summary: "Enable multi-region CloudTrail with log validation.",
    test: (t) => /cloudtrail|audit log|logging disabled|no trail/i.test(t),
  },
  {
    id: "azure-nsg-open-rdp",
    class: "reversible",
    summary: "Close NSG rule allowing RDP from the internet.",
    test: (t) => /azure|nsg|rdp|:3389|network security/i.test(t),
  },
];

export function matchPlaybook(finding: Finding): PlaybookMatch | null {
  const title = finding.title.toLowerCase();
  for (const rule of PLAYBOOK_RULES) {
    if (rule.test(title)) {
      return { playbookId: rule.id, class: rule.class, summary: rule.summary };
    }
  }
  return null;
}

/** Rule-based remediation text shown inline on Findings (works offline). */
export function suggestFix(finding: Finding): string[] {
  const t = finding.title.toLowerCase();
  const steps: string[] = [];

  if (/public|allusers|0\.0\.0\.0|world|open.*internet/i.test(t)) {
    steps.push("Remove public exposure: block anonymous access and restrict source IPs.");
  }
  if (/s3|bucket|storage|blob|gcs/i.test(t)) {
    steps.push("Enable block public access, default encryption, and least-privilege bucket policies.");
  }
  if (/security group|nsg|firewall|ingress|:22|:3389/i.test(t)) {
    steps.push("Tighten network rules: allow only required CIDRs and ports; deny 0.0.0.0/0.");
  }
  if (/cloudtrail|logging|audit|monitor/i.test(t)) {
    steps.push("Turn on centralized audit logging (CloudTrail / equivalent) with tamper detection.");
  }
  if (/iam|mfa|root|access key|credential|privilege/i.test(t)) {
    steps.push("Enforce MFA, rotate keys, and apply least-privilege IAM policies.");
  }
  if (/encrypt|tls|unencrypted|cleartext/i.test(t)) {
    steps.push("Enable encryption in transit and at rest with customer-managed keys where required.");
  }
  if (steps.length === 0) {
    steps.push(
      "Review the finding in cloud console, confirm blast radius, then apply the smallest reversible fix.",
    );
  }

  const pb = matchPlaybook(finding);
  if (pb) {
    steps.push(`Suggested playbook: ${pb.playbookId} (${pb.class}) - ${pb.summary}`);
  }

  if (finding.severity === "critical" || finding.severity === "high") {
    steps.push("Priority: treat as urgent; queue HITL remediation after snapshot/backup.");
  }

  return steps;
}

function slug(s: string, max = 24): string {
  const base = s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, max);
  return base || "asset";
}

function inferKind(f: Finding): string {
  const t = f.title.toLowerCase();
  if (/s3|bucket|storage|blob|gcs/.test(t)) return "storage";
  if (/security group|nsg|firewall|vpc/.test(t)) return "network";
  if (/iam|role|user|identity|mfa/.test(t)) return "identity";
  if (/rds|database|db|postgres|mysql/.test(t)) return "database";
  if (/ec2|instance|vm|compute/.test(t)) return "compute";
  return f.cloud || "asset";
}

function isExposed(title: string): boolean {
  return /public|0\.0\.0\.0|world|exposed|open.*internet|allusers|anonymous/i.test(title);
}

function isSensitive(f: Finding): boolean {
  return (
    f.blastRadius >= 40 ||
    f.severity === "critical" ||
    f.severity === "high" ||
    /credential|secret|database|rds|pii|phi|payment/i.test(f.title)
  );
}

/** Build a GraphSpec from open findings so attack paths render without manual API calls. */
export function buildGraphSpecFromFindings(findings: Finding[]): {
  nodes: Array<{ id: string; kind: string; exposed: boolean; sensitive: boolean }>;
  edges: Array<{ from: string; to: string; kind: string; difficulty: number }>;
} {
  const open = findings.filter((f) => f.status !== "dismissed");
  const nodes: Array<{ id: string; kind: string; exposed: boolean; sensitive: boolean }> = [
    { id: "internet", kind: "gateway", exposed: true, sensitive: false },
  ];
  const edges: Array<{ from: string; to: string; kind: string; difficulty: number }> = [];
  const clouds = new Set<string>();

  for (const f of open) {
    const cloud = (f.cloud || "cloud").toLowerCase();
    clouds.add(cloud);
  }

  for (const cloud of clouds) {
    const cloudId = `cloud-${cloud}`;
    nodes.push({ id: cloudId, kind: "account", exposed: false, sensitive: false });
    edges.push({ from: "internet", to: cloudId, kind: "connects_to", difficulty: 2.5 });
  }

  open.forEach((f, i) => {
    const id = `${inferKind(f).slice(0, 8)}-${slug(f.title)}-${i}`;
    const exposed = isExposed(f.title);
    const sensitive = isSensitive(f);
    nodes.push({ id, kind: inferKind(f), exposed, sensitive });
    const cloudId = `cloud-${(f.cloud || "cloud").toLowerCase()}`;
    edges.push({ from: cloudId, to: id, kind: "owns", difficulty: 1.0 });
    if (exposed) {
      edges.push({ from: "internet", to: id, kind: "exposes", difficulty: 1.0 });
    } else {
      edges.push({ from: "internet", to: id, kind: "connects_to", difficulty: 3.0 });
    }
    if (/iam|role|assume|privilege/.test(f.title.toLowerCase())) {
      edges.push({ from: id, to: cloudId, kind: "has_permission", difficulty: 1.5 });
    }
  });

  return { nodes, edges };
}

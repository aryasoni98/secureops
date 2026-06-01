# SecureOps — Rust workspace

Rust port of [`@adversa/secureops`](https://www.npmjs.com/package/@adversa/secureops) (v2.2.0): security audit, hardening, and **out-of-band enforcement** for OpenClaw agent deployments.

| | |
|---|---|
| **Tests** | ~165 workspace tests |
| **Architecture** | Three trust rings + PDP/PEP ([PRODUCT.md](PRODUCT.md)) |
| **Run locally / Docker / K8s** | **[docs/RUNNING.md](docs/RUNNING.md)** |
| **One-command setup** | `just setup` (see [Justfile](Justfile)) |

---

## What problem this solves

AI agents can read secrets, call tools, and reach the network. If the agent is compromised, **in-process guards can be disabled by the attacker**.

SecureOps moves the enforcement boundary **outside the agent process**:

- **Observe** — 56 OWASP ASI–mapped checks, scoring, hardening, live monitors  
- **Enforce** — egress proxy, policy engine, sandbox, kernel hooks (Ring 2 daemon)

The agent (Ring 0) is assumed hostile; the daemon (Ring 2) keeps working after compromise.

---

## Architecture at a glance

| Fill | Role |
|------|------|
| `#D64545` | Ring 0 — untrusted agent |
| `#F4A832` | Ring 1 — in-process / CLI |
| `#248358` | Ring 2 — daemon / root of trust |
| `#7C3AED` | PEP — enforcement points |
| `#2563EB` | PDP — policy engine |
| `#475569` | Audit log / persistence |
| `#0EA5E9` | Operator / CI |

### Three trust rings (2D view)

Trust increases **outward**. Enforcement strength increases **downward** (Ring 2).

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#334155', 'clusterBkg': '#F8FAFC', 'titleColor': '#1A1A1A', 'clusterTextColor': '#1A1A1A', 'textColor': '#1A1A1A', 'edgeLabelBackground': '#FFFFFF'}}}%%
flowchart TB
  subgraph R0["Ring 0 — Untrusted"]
    direction LR
    AGENT[OpenClaw agent / LLM]
    SKILLS[Skills & plugins]
    SECRETS[.env · credentials]
  end

  subgraph R1["Ring 1 — Degraded trust (in-process)"]
    direction LR
    NAPI[N-API addon secureops-napi]
    CLI[CLI secureops]
    CHECKS[Audit engine · monitors]
  end

  subgraph R2["Ring 2 — Root of trust (separate process)"]
    direction TB
    DAEMON[secureops-daemon]
    PDP[PDP secureops-policy]
    PEP1[Egress PEP secureops-proxy]
    PEP2[Kernel PEP secureops-bpf]
    PEP3[Execution PEP secureops-sandbox]
    LOG[Audit log secureops-auditlog]
    DAEMON --> PDP
    DAEMON --> PEP1 & PEP2 & PEP3
    DAEMON --> LOG
  end

  R0 -->|"same process; dies with agent"| R1
  R1 -.->|"unix socket JSON-RPC"| R2
  R0 -->|"HTTPS_PROXY / syscalls"| PEP1 & PEP2

  classDef ring0 fill:#D64545,stroke:#9B2E2E,color:#FFFFFF,stroke-width:2px
  classDef ring1 fill:#F4A832,stroke:#C4841A,color:#1A1A1A,stroke-width:2px
  classDef ring2 fill:#248358,stroke:#186B44,color:#FFFFFF,stroke-width:2px
  classDef pdp fill:#2563EB,stroke:#1D4ED8,color:#FFFFFF,stroke-width:2px
  classDef pep fill:#7C3AED,stroke:#5B21B6,color:#FFFFFF,stroke-width:2px
  classDef audit fill:#475569,stroke:#334155,color:#FFFFFF,stroke-width:2px

  class AGENT,SKILLS,SECRETS ring0
  class NAPI,CLI,CHECKS ring1
  class DAEMON ring2
  class PDP pdp
  class PEP1,PEP2,PEP3 pep
  class LOG audit

  style R0 fill:#D64545,stroke:#9B2E2E,color:#FFFFFF
  style R1 fill:#F4A832,stroke:#C4841A,color:#1A1A1A
  style R2 fill:#248358,stroke:#186B44,color:#FFFFFF
```

| Ring | Runs where | Trust | If agent is owned |
|------|------------|-------|-------------------|
| **0** | Agent process | None | Attacker controls everything here |
| **1** | Agent process (N-API) or operator CLI | Low | Audit/monitor can be bypassed |
| **2** | `secureops-daemon` (privileged, separate) | High | Egress proxy, PDP, log still apply |

---

### PDP / PEP split (enforcement spine)

One brain (**Policy Decision Point**), many dumb enforcers (**Policy Enforcement Points**).

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#334155', 'titleColor': '#1A1A1A', 'clusterTextColor': '#1A1A1A', 'textColor': '#1A1A1A', 'edgeLabelBackground': '#FFFFFF'}}}%%
flowchart LR
  subgraph Agent["Ring 0 — Agent"]
    REQ[Outbound connect · skill run · syscall]
  end

  subgraph PEPs["PEPs — ask before allowing"]
    PROXY[Egress proxy<br/>:8889 fail-closed]
    BPF[eBPF / ES hooks]
    WASM[WASM sandbox]
  end

  subgraph PDPg["PDP — secureops-policy"]
    REGO[Rego regorus]
    CEDAR[Cedar]
    CACHE[Decision cache]
  end

  subgraph Persist["Tamper-evident"]
    AUDIT[Hash chain + ed25519]
    SQLITE[Alerts SQLite]
  end

  REQ --> PROXY & BPF & WASM
  PROXY & BPF & WASM -->|"allow / deny / escalate"| REGO
  REGO --> CEDAR & CACHE
  PROXY & BPF & WASM --> AUDIT
  DAEMON_MON[Monitors] --> SQLITE

  classDef ring0 fill:#D64545,stroke:#9B2E2E,color:#FFFFFF,stroke-width:2px
  classDef pep fill:#7C3AED,stroke:#5B21B6,color:#FFFFFF,stroke-width:2px
  classDef pdp fill:#2563EB,stroke:#1D4ED8,color:#FFFFFF,stroke-width:2px
  classDef persist fill:#475569,stroke:#334155,color:#FFFFFF,stroke-width:2px
  classDef monitor fill:#0EA5E9,stroke:#0284C7,color:#FFFFFF,stroke-width:2px

  class REQ ring0
  class PROXY,BPF,WASM pep
  class REGO,CEDAR,CACHE pdp
  class AUDIT,SQLITE persist
  class DAEMON_MON monitor

  style Agent fill:#D64545,stroke:#9B2E2E,color:#FFFFFF
  style PEPs fill:#7C3AED,stroke:#5B21B6,color:#FFFFFF
  style PDPg fill:#2563EB,stroke:#1D4ED8,color:#FFFFFF
  style Persist fill:#475569,stroke:#334155,color:#FFFFFF
```

| Component | Crate | Role |
|-----------|-------|------|
| **PDP** | `secureops-policy` | Single authority: allow, deny, escalate |
| **Egress PEP** | `secureops-proxy` | HTTP CONNECT + DNS sinkhole; unknown host → 403, 0 bytes out |
| **Kernel PEP** | `secureops-bpf` | `openat` / `connect` / `execve` correlation (Linux eBPF) |
| **Execution PEP** | `secureops-sandbox` | wasmtime + WASI; fuel/epoch limits |
| **IPC** | `secureops-ipc` | Unix socket, `SO_PEERCRED` — do not trust agent tokens |
| **Daemon** | `secureops-daemon` | Wires PDP + PEPs + monitors + shutdown |

---

### Component map (crates × rings)

Two dimensions: **ring** (trust) × **layer** (core → checks → enforcement).

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#334155', 'titleColor': '#1A1A1A', 'clusterTextColor': '#1A1A1A', 'textColor': '#1A1A1A', 'edgeLabelBackground': '#FFFFFF'}}}%%
flowchart LR
  subgraph R0["Ring 0 — Agent host"]
    OC[OpenClaw · skills · .env]
  end

  subgraph R1["Ring 1 — In-process / operator"]
    direction TB
    CORE[core]
    CHK[checks · fs · intel · crypto]
    OPS[harden · monitors]
    BIN[cli · napi]
    CORE --> CHK --> OPS --> BIN
  end

  subgraph R2["Ring 2 — Daemon"]
    direction TB
    POL[policy PDP]
    PEP[proxy · bpf · sandbox]
    SUP[auditlog · ipc · daemon]
    POL --> PEP --> SUP
  end

  OC -.->|tools & network| BIN
  BIN -.->|optional IPC| SUP
  OC -->|HTTPS_PROXY| PEP

  classDef ring0 fill:#D64545,stroke:#9B2E2E,color:#FFFFFF,stroke-width:2px
  classDef ring1 fill:#F4A832,stroke:#C4841A,color:#1A1A1A,stroke-width:2px
  classDef ring2 fill:#248358,stroke:#186B44,color:#FFFFFF,stroke-width:2px
  classDef pdp fill:#2563EB,stroke:#1D4ED8,color:#FFFFFF,stroke-width:2px
  classDef pep fill:#7C3AED,stroke:#5B21B6,color:#FFFFFF,stroke-width:2px

  class OC ring0
  class CORE,CHK,OPS,BIN ring1
  class POL pdp
  class PEP pep
  class SUP ring2

  style R0 fill:#D64545,stroke:#9B2E2E,color:#FFFFFF
  style R1 fill:#F4A832,stroke:#C4841A,color:#1A1A1A
  style R2 fill:#248358,stroke:#186B44,color:#FFFFFF
```

| Layer | Crates |
|-------|--------|
| **Core** | `secureops-core` (types, scoring — no I/O) |
| **Audit** | `secureops-checks`, `secureops-fs`, `secureops-intel`, `secureops-crypto` |
| **Operate** | `secureops-harden`, `secureops-monitors`, `secureops-cli`, `secureops-napi` |
| **Enforce** | `secureops-policy`, `secureops-proxy`, `secureops-bpf`, `secureops-sandbox` |
| **Supervise** | `secureops-auditlog`, `secureops-ipc`, `secureops-daemon` |

**Dependency rule:** everything depends inward on `secureops-core`.

---

### Deployment topology (where binaries run)

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#334155', 'titleColor': '#1A1A1A', 'clusterTextColor': '#1A1A1A', 'textColor': '#1A1A1A', 'edgeLabelBackground': '#FFFFFF'}}}%%
flowchart TB
  subgraph Operator["Operator / CI"]
    JUST[just setup · just audit]
    CICD[audit --json exit 2 if score < 80]
  end

  subgraph Host["Host · EC2 · K8s node"]
    STATE["OPENCLAW_STATE_DIR<br/>.secureops/ keystore · baselines"]
    subgraph Proc["Processes"]
      CLI_BIN[secureops CLI]
      DAE[secureops-daemon]
    end
    AGENT2[OpenClaw agent]
  end

  subgraph Optional["Optional integration"]
    NODE[Node.js + secureops.node]
    DOCKER[Docker / Compose]
    K8S[K8s Deployment + CronJob]
  end

  JUST --> CLI_BIN
  CICD --> CLI_BIN
  CLI_BIN --> STATE
  DAE --> STATE
  AGENT2 -->|"HTTPS_PROXY"| DAE
  NODE --> NAPI_R[secureops-napi]
  NAPI_R --> STATE
  DOCKER --> DAE
  K8S --> DAE

  classDef ops fill:#0EA5E9,stroke:#0284C7,color:#FFFFFF,stroke-width:2px
  classDef host fill:#14B8A6,stroke:#0D9488,color:#FFFFFF,stroke-width:2px
  classDef ring0 fill:#D64545,stroke:#9B2E2E,color:#FFFFFF,stroke-width:2px
  classDef ring1 fill:#F4A832,stroke:#C4841A,color:#1A1A1A,stroke-width:2px
  classDef ring2 fill:#248358,stroke:#186B44,color:#FFFFFF,stroke-width:2px
  classDef state fill:#A7C4BC,stroke:#6B9080,color:#1A1A1A,stroke-width:2px
  classDef deploy fill:#6366F1,stroke:#4F46E5,color:#FFFFFF,stroke-width:2px

  class JUST,CICD ops
  class STATE state
  class CLI_BIN ring1
  class DAE,NAPI_R ring2
  class AGENT2 ring0
  class NODE,DOCKER,K8S deploy

  style Operator fill:#0EA5E9,stroke:#0284C7,color:#FFFFFF
  style Host fill:#14B8A6,stroke:#0D9488,color:#FFFFFF
  style Proc fill:#E8F4F0,stroke:#6B9080,color:#1A1A1A
  style Optional fill:#6366F1,stroke:#4F46E5,color:#FFFFFF
```

Details: [docs/RUNNING.md](docs/RUNNING.md) (local, EC2, Kubernetes).

---

## Workflows

### 1. Bootstrap (`secureops init`)

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'darkMode': false, 'background': '#FFFFFF', 'actorBkg': '#FFFFFF', 'actorTextColor': '#1A1A1A', 'actorBorder': '#334155', 'actorLineColor': '#64748B', 'signalColor': '#334155', 'signalTextColor': '#1A1A1A', 'labelBoxBkgColor': '#FFFFFF', 'labelTextColor': '#1A1A1A', 'labelBoxBorderColor': '#334155', 'loopTextColor': '#1A1A1A', 'noteBkgColor': '#F1F5F9', 'noteTextColor': '#1A1A1A', 'noteBorderColor': '#94A3B8', 'activationBkgColor': '#E2E8F0', 'activationBorderColor': '#64748B'}}}%%
sequenceDiagram
  box #0EA5E9 Operator
    participant Op as Operator
  end
  box #F4A832 Ring 1
    participant CLI as secureops CLI
  end
  box #475569 State
    participant FS as State dir .secureops/
  end

  Op->>CLI: init
  CLI->>FS: Create .secureops/
  CLI->>FS: Argon2id keystore (0o400)
  CLI-->>Op: machine id · next: audit
```

```sh
just setup    # build + test + init (default /tmp/secureops-demo)
# or: just state-init
```

---

### 2. Audit (read-only, CI gate)

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#334155', 'titleColor': '#1A1A1A', 'textColor': '#1A1A1A', 'edgeLabelBackground': '#FFFFFF'}}}%%
flowchart TD
  A[Start audit] --> B[Load AuditContext<br/>openclaw.json · filesystem]
  B --> C[Run 56 SC-* checks<br/>JoinSet parallel]
  C --> D{Check panicked?}
  D -->|yes| E[Isolate as INFO finding]
  D -->|no| F[Merge findings]
  E --> F
  F --> G[Cross-layer SC-CROSS-001]
  G --> H[Score = 100 − deductions]
  H --> I{--json?}
  I -->|yes| J[stdout JSON<br/>exit 2 if score < 80]
  I -->|no| K[Colored console report]

  classDef step fill:#3B82F6,stroke:#2563EB,color:#FFFFFF,stroke-width:2px
  classDef decision fill:#F59E0B,stroke:#D97706,color:#1A1A1A,stroke-width:2px
  classDef warn fill:#94A3B8,stroke:#64748B,color:#FFFFFF,stroke-width:2px
  classDef pass fill:#059669,stroke:#047857,color:#FFFFFF,stroke-width:2px
  classDef report fill:#6366F1,stroke:#4F46E5,color:#FFFFFF,stroke-width:2px

  class A,B,C,F,G,H step
  class D,I decision
  class E warn
  class J pass
  class K report
```

```sh
just audit              # human report
just audit-json         # CI gate
just audit-deep         # + localhost port probes
```

---

### 3. Harden + rollback

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#334155', 'titleColor': '#1A1A1A', 'textColor': '#1A1A1A', 'edgeLabelBackground': '#FFFFFF'}}}%%
flowchart LR
  H[harden] --> B[Timestamped backup]
  B --> M1[Gateway]
  B --> M2[Credentials]
  B --> M3[Config]
  B --> M4[Docker]
  B --> M5[Network rules]
  M1 & M2 & M3 & M4 & M5 --> MAN[Manifest]
  RB[harden --rollback] --> REST[Restore backup]

  classDef action fill:#F4A832,stroke:#C4841A,color:#1A1A1A,stroke-width:2px
  classDef module fill:#FB923C,stroke:#EA580C,color:#FFFFFF,stroke-width:2px
  classDef done fill:#248358,stroke:#186B44,color:#FFFFFF,stroke-width:2px
  classDef rollback fill:#D64545,stroke:#9B2E2E,color:#FFFFFF,stroke-width:2px

  class H,B action
  class M1,M2,M3,M4,M5 module
  class MAN done
  class RB,REST rollback
```

```sh
just harden
just harden --full      # all auto-fixes (manual flags if needed)
```

---

### 4. Daemon runtime (Ring 2)

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'darkMode': false, 'background': '#FFFFFF', 'actorBkg': '#FFFFFF', 'actorTextColor': '#1A1A1A', 'actorBorder': '#334155', 'actorLineColor': '#64748B', 'signalColor': '#334155', 'signalTextColor': '#1A1A1A', 'labelBoxBkgColor': '#FFFFFF', 'labelTextColor': '#1A1A1A', 'labelBoxBorderColor': '#334155', 'loopTextColor': '#1A1A1A', 'noteBkgColor': '#F1F5F9', 'noteTextColor': '#1A1A1A', 'noteBorderColor': '#94A3B8'}}}%%
sequenceDiagram
  box #248358 Ring 2 daemon
    participant D as secureops-daemon
    participant Bus as AlertBus
    participant Mon as 4 monitors
    participant PX as Egress proxy
  end
  box #D64545 Safety
    participant KS as Kill switch file
  end
  box #0EA5E9 Operator
    participant Op as Operator
  end

  D->>KS: Active?
  alt kill switch on
    KS-->>D: stop — no enforcement
  else off
    D->>Bus: spawn consumer
    D->>Mon: cost · credential · memory · skill
    opt egressAllowlistEnabled
      D->>PX: bind 127.0.0.1:8889
    end
    Op->>D: SIGINT / SIGTERM
    D->>Mon: cancel token · clean shutdown
  end
```

```sh
just daemon
# Egress: set openclaw.json egressAllowlistEnabled + HTTPS_PROXY=http://127.0.0.1:8889
```

| Monitor | Purpose |
|---------|---------|
| Cost | Spend / circuit breaker |
| Credential | Secret access patterns |
| Memory integrity | Cognitive file tampering |
| Skill scanner | IOC + typosquat on install |

---

### 5. Egress decision (headline enforcement path)

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'darkMode': false, 'background': '#FFFFFF', 'actorBkg': '#FFFFFF', 'actorTextColor': '#1A1A1A', 'actorBorder': '#334155', 'actorLineColor': '#64748B', 'signalColor': '#334155', 'signalTextColor': '#1A1A1A', 'labelBoxBkgColor': '#FFFFFF', 'labelTextColor': '#1A1A1A', 'labelBoxBorderColor': '#334155', 'loopTextColor': '#1A1A1A', 'altTextColor': '#1A1A1A'}}}%%
sequenceDiagram
  box #D64545 Ring 0
    participant A as Agent
  end
  box #7C3AED PEP
    participant P as Egress proxy
  end
  box #2563EB PDP
    participant PDP as PDP policy
  end
  box #475569 External
    participant U as Internet
  end

  A->>P: CONNECT api.evil.com
  P->>PDP: Allowed for this PID/context?
  alt deny or PDP error
    PDP-->>P: Deny
    P-->>A: 403 — 0 bytes to upstream
  else allow
    PDP-->>P: Allow
    P->>U: Tunnel if in allowlist
  end
  P->>P: Append signed audit entry
```

Example config (`$OPENCLAW_STATE_DIR/openclaw.json`):

```json
{
  "secureops": {
    "network": {
      "egressAllowlistEnabled": true,
      "egressAllowlist": ["api.anthropic.com"]
    }
  }
}
```

---

### 6. Emergency kill switch

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#334155', 'labelTextColor': '#1A1A1A', 'stateLabelColor': '#FFFFFF', 'edgeLabelBackground': '#FFFFFF'}}}%%
stateDiagram-v2
  [*] --> Normal: daemon running
  Normal --> Killed: secureops kill
  Killed --> Normal: kill --deactivate
  Killed --> Blocked: daemon refuses start
  note right of Killed
    Blocks tool calls
    Monitors/enforcement off
  end note

  classDef ok fill:#059669,stroke:#047857,color:#FFFFFF,stroke-width:2px
  classDef danger fill:#DC2626,stroke:#B91C1C,color:#FFFFFF,stroke-width:2px
  classDef blocked fill:#D64545,stroke:#9B2E2E,color:#FFFFFF,stroke-width:2px

  class Normal ok
  class Killed danger
  class Blocked blocked
```

```sh
just kill
just kill-off
```

---

## Quick start

| Goal | Command |
|------|---------|
| Full local bootstrap | `just setup` |
| Security audit | `just audit` |
| Live monitors | `just monitor` |
| Ring-2 daemon | `just daemon` |
| Docker on EC2 | `just docker-up` |
| Kubernetes | `just k8s-apply` (after image build) |
| All recipes | `just --list` |

**Prerequisites:** Rust ≥ 1.80, Node ≥ 18 (for N-API build), [just](https://github.com/casey/just).

Manual build (no just):

```sh
cargo build --workspace
cargo test --workspace
export OPENCLAW_STATE_DIR=/tmp/secureops-demo
cargo run -p secureops-cli -- init
cargo run -p secureops-cli -- audit
```

**CLI commands:** `init` · `audit` · `harden` · `status` · `monitor` · `behavioral` · `kill` · `export-incident`

---

## Crate reference

| Crate | Ring | Status | Responsibility |
|-------|------|--------|----------------|
| `secureops-core` | 0 | LIVE | Types, traits, scoring, MAESTRO — **no I/O** |
| `secureops-checks` | 1 | LIVE | 56 findings, 9 OWASP ASI categories |
| `secureops-fs` | 1 | LIVE | `tokio::fs` context, kill switch, behavioral |
| `secureops-intel` | 1 | LIVE | IOC, typosquat, tree-sitter, signed feed |
| `secureops-crypto` | 1 | LIVE | Argon2id keystore, AES-GCM, keychain/TPM |
| `secureops-harden` | 1 | LIVE | Harden/rollback (5 modules) |
| `secureops-monitors` | 1 | LIVE | 4 monitors, AlertBus, SQLite |
| `secureops-cli` | 1 | LIVE | `secureops` binary |
| `secureops-napi` | 1 | LIVE | Node native addon |
| `secureops-policy` | 2 | LIVE | PDP: Rego, Cedar, cache |
| `secureops-proxy` | 2 | LIVE | Egress PEP + DNS sinkhole |
| `secureops-bpf` | 2 | GATED | Kernel PEP (Linux eBPF build) |
| `secureops-sandbox` | 2 | LIVE | wasmtime execution PEP |
| `secureops-auditlog` | 2 | LIVE | Hash chain + ed25519 |
| `secureops-ipc` | 2 | LIVE | Unix JSON-RPC + peer cred |
| `secureops-daemon` | 2 | LIVE | Ring-2 supervisor |

Separate tree: `ebpf/` — kernel programs (not in workspace; Linux only).

---

## Development

### Tests

```sh
cargo test --workspace
just ci                    # fmt + clippy + test
```

Focused crates:

```sh
cargo test -p secureops-checks
cargo test -p secureops-proxy
cargo test -p secureops-policy -- rego_pdp_tests
cargo test -p secureops-policy -- cedar_tests
```

### Wire format

All JSON uses `camelCase` serde names — **byte-compatible** with the TypeScript tool. Ring 1 (N-API) and Ring 2 (daemon) share `<stateDir>/.secureops/`.

### N-API (Node)

```sh
just napi
cp target/release/libsecureops_napi.* ../secureops/secureops.node
```

### Platform-gated features

| Feature | Platform |
|---------|----------|
| eBPF kernel PEP | Linux + `ebpf/` build |
| macOS Endpoint Security | macOS entitlement |
| TPM signing | Linux + `tss-esapi` |

macOS builds and tests **without** eBPF/TPM.

### TS parity check

```sh
# From a checkout of the sibling npm shim repo:
cd ../secureops && npm run build && cd -
# Compare audit JSON — see docs/RUNNING.md and historical README section in git
```

---

## Repository layout

```
secureops/                   # repo root = Rust workspace
├── Justfile                 # just setup · audit · docker-* · k8s-*
├── Cargo.toml               # workspace manifest (16 members)
├── docs/RUNNING.md          # Local · EC2/Docker · Kubernetes
├── deploy/docker/           # Dockerfile + compose
├── deploy/k8s/              # Kustomize manifests
├── crates/                  # 16 workspace members
└── ebpf/                    # Kernel programs (Linux, separate build)
```

---

## Further reading

- [PRODUCT.md](PRODUCT.md) — full architecture, workflows B.1–B.9, migration phasing  
- [docs/RUNNING.md](docs/RUNNING.md) — step-by-step runbooks  
- [`@adversa/secureops`](https://www.npmjs.com/package/@adversa/secureops) — TypeScript package (v2.2.0 reference)

---

## License

[MIT](LICENSE) © Adversa AI

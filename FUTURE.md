# SecureOps — Technical Specification
### A Fully Self-Hosted, Client-Deployed, AI-Native Multi-Cloud Security Platform

---

## TL;DR

- **SecureOps is a "bring-your-own-infrastructure" (BYOI) security SaaS:** the client deploys the entire platform inside their own AWS/GCP/Azure/on-prem environment via Docker Compose or Helm, launched with one `just install` command; clients supply their own LLM API keys; the vendor supplies only Ed25519-signed license keys that are validated **locally** against a public key embedded in the binary — **no vendor infrastructure is ever required to run the product.**
- **The architecture is a Rust (axum) multi-service system** — API server, scan/check engine (Cedar + Rego), Security Knowledge Graph, RL prioritizer, LLM agentic bug-hunter, three-class self-healing engine, and a token-compression layer — backed by Postgres, a graph store, Redis, an object store, and OpenTelemetry, all shipping as cosign-signed, distroless, non-root containers in every phase from P0 onward.
- **Build it in this order:** P0 license + container/Helm/Justfile foundation → P1 dashboard MVP with license activation → P2 multi-cloud scanning → P3–P4 knowledge graph + attack paths → P5 LLM bug-hunting + token compression → P6 self-healing → P7 RL feedback loop → P8 enterprise (SSO/eBPF/destructive healing) → P9 hardening/GA, with a parallel W0–W7 worldwide rollout. Feature access is gated by the license `tier` claim (Community/Pro/Enterprise) enforced in Cedar at the API edge.

---

## Key Findings

1. **The BYOI model is proven.** GitLab EE, Mattermost, Netdata, Portainer, Metabase, and HashiCorp Vault Enterprise all ship self-hosted binaries that validate an embedded, cryptographically-signed license offline and degrade gracefully (not hard-lock) on expiry. SecureOps should follow the same pattern: **offline-first signature verification with an optional online heartbeat**, never a phone-home dependency.

2. **The hardest design constraint is "vendor never hosts anything."** This forces three decisions: (a) license validation must be **offline-capable via embedded Ed25519 public key**; (b) all LLM cost/usage accounting happens **client-side** (no vendor billing pipeline — the client pays their own OpenAI/Anthropic bills); (c) telemetry to the vendor must be **opt-in and license-keyed only**, not operationally required.

3. **Token cost is the dominant variable operating expense** because security artifacts (IAM policies, K8s manifests, Terraform plans, CloudTrail) are enormous. A `TokenBudget` packing layer with semantic dedup, schema-reference compression, diff/delta evidence extraction, map-reduce chunking, and provider-side prompt caching is not optional — it is the difference between a usable product and one that burns the client's API budget.

4. **A graph is the correct core data model**, not a flat findings table. Attack-path analysis (internet → sensitive target) and blast-radius scoring require traversal queries. Neo4j gives the richest path queries; PostgreSQL + recursive CTEs (+ pgvector for semantic search) keeps the deployment to a single relational engine — a meaningful simplification for a self-hosted product the client must operate.

5. **Self-healing must be risk-classified, not binary.** Three classes — Safe (auto after dry-run), Reversible (snapshot → execute → health-check → auto-rollback), Destructive (mandatory human-in-the-loop with timeout) — plus an immutable audit log, are the safe way to ship automated remediation into someone else's production cloud.

6. **The four cited external sources could not be fetched** in this environment (tool access failure for both the lead and the subagent). Their designs below are **reconstructed from domain patterns** and flagged accordingly; verify against the live repos before implementation.

---

## Details

### 2. Complete Architecture Diagram (text-based, detailed)

```
                              CLIENT-OWNED ENVIRONMENT (AWS / GCP / Azure / on-prem / laptop)
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                    │
│  [Operator CLI] ──just──> (docker compose | helm)            [Analyst Browser]                     │
│        │                                                            │                              │
│        │                                                       HTTPS / WSS                          │
│        ▼                                                            ▼                              │
│  ┌───────────────────────────── Ingress / Reverse Proxy (nginx or traefik) ──────────────────────┐ │
│  │                         TLS terminated via cert-manager (K8s) / mounted certs (compose)        │ │
│  └───────────────────────────────────────────┬──────────────────────────────────────────────────┘ │
│                                               │ HTTP/1.1 + HTTP/2 + WS                              │
│                                   ┌───────────▼────────────┐                                       │
│                                   │  API SERVER (axum,Rust)│  serves React SPA (static, embedded)  │
│                                   │  REST + gRPC + WebSocket│  Cedar AuthZ at edge + tier gating    │
│                                   └───┬─────┬─────┬─────┬───┘                                       │
│         ┌─────────────────────────────┘     │     │     └────────────────────────┐                 │
│         │ in-proc/gRPC                       │ gRPC│ gRPC                          │ gRPC            │
│         ▼                                    ▼     ▼                              ▼                 │
│  ┌──────────────┐   ┌──────────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │ LICENSE SVC  │   │ SCAN/CHECK ENGINE│  │ GRAPH SERVICE│  │  RL ENGINE   │  │ SELF-HEAL ENGINE │ │
│  │ Ed25519 verify│  │ collectors +     │  │ KG build +   │  │ contextual   │  │ playbooks +      │ │
│  │ embedded pubkey│ │ Cedar + Rego eval│  │ attack paths │  │ bandit rank  │  │ Safe/Rev/Destr   │ │
│  │ +24h heartbeat │ │ + scoring        │  │ + blast radius│ │ +online update│ │ +HITL queue      │ │
│  └──────┬────────┘   └────┬────────┬────┘  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘ │
│         │                 │        │              │                 │                   │           │
│         │            ┌────▼───┐    │        ┌─────▼─────┐           │           ┌───────▼────────┐  │
│         │            │BUGHUNT │    │        │ TOKEN     │           │           │ AUDIT WRITER   │  │
│         │            │agentic │◄───┼────────┤ COMPRESS  │◄──────────┼───────────┤ (append-only)  │  │
│         │            │LLM loop│    │        │ TokenBudget│          │           └───────┬────────┘  │
│         │            └───┬────┘    │        └─────┬─────┘           │                   │           │
│         │                │         │              │                 │                   │           │
│  ───────┼────────────────┼─────────┼──────────────┼─────────────────┼───────────────────┼────────  │
│         │           [REDIS: job queue + cache + pub/sub for WS fan-out]                  │           │
│  ───────┼────────────────┼─────────┼──────────────┼─────────────────┼───────────────────┼────────  │
│         ▼                ▼          ▼              ▼                 ▼                   ▼           │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────┐ │
│  │ POSTGRES (findings, assets, identities,   │ GRAPH DB (Neo4j │ OBJECT STORE (MinIO/S3:        │ │ │
│  │ licenses[encrypted], rl_feedback,         │ OR pg recursive │ evidence blobs, backups,      │ │ │
│  │ audit_log, remediations, usage_metrics)   │ CTEs)           │ scan snapshots, model weights)│ │ │
│  └──────────────────────────────────────────────────────────────────────────────────────────────┘ │
│                                               │                                                    │
│                                       [OTEL COLLECTOR] ──> client's own Grafana/Tempo/Prom (opt)   │
└───────────────┬───────────────────────────────┬────────────────────────────────┬──────────────────┘
                │ HTTPS (read-only roles)        │ HTTPS (client API keys)         │ HTTPS (opt, license only)
                ▼                                ▼                                 ▼
   CLOUD CONTROL PLANES                  LLM PROVIDERS                    VENDOR LICENSE API
   AWS STS/IAM/Config/CloudTrail         OpenAI / Anthropic /            (lightweight; heartbeat +
   GCP IAM/Asset/Pub-Sub                 Azure OpenAI / custom           renewal check ONLY;
   Azure ARM/Graph/EventGrid             OpenAI-compatible endpoint      never required to run)
```

**Trust boundaries:** Everything inside the outer box is client-owned. The only outbound flows are (1) read-only cloud-API calls using roles the client grants, (2) LLM calls using the client's own keys, and (3) an *optional* license heartbeat carrying only `{license_id, instance_fingerprint, version}`.

---

### 3. Service Descriptions & Responsibilities

| Service | Responsibility | Key tech |
|---|---|---|
| **API Server** | HTTP/gRPC/WS termination; serves embedded React SPA; Cedar authorization at the edge; license-tier feature gating; request validation; OpenAPI surface | `axum`, `tower`, `tonic`, `utoipa`, `cedar-policy` |
| **License Service** | Ed25519 signature verification against embedded public key; claim extraction (`tenant_id`, `expiry`, `tier`, `seats`, `features[]`); encrypted storage of activated license; 24h heartbeat (online mode); grace-period state machine | `ed25519-dalek`, `jsonwebtoken`/custom, `aes-gcm` |
| **Scan/Check Engine** | Per-cloud collectors; event normalization to internal `AssetEvent`; Cedar + Rego rule evaluation; scoring; emits `Finding` | `aws-sdk-rust`, `google-cloud-rs`, `azure_sdk`, `regorus` (Rego in Rust), `cedar-policy` |
| **Graph Service** | Ingest assets/identities/permissions/network; build typed edges; attack-path computation (BFS/Dijkstra); blast-radius scoring; "explain path" orchestration | `neo4rs` OR `sqlx` recursive CTEs, `petgraph` for in-memory analysis |
| **RL Engine** | Contextual bandit ranking of findings; online updates from analyst feedback; model registry; batch eval gating promotion | custom (LinUCB/Thompson), `ndarray`, `linfa` (optional) |
| **Self-Healing Engine** | Playbook lookup; Safe/Reversible/Destructive classification; dry-run; snapshot/rollback; HITL approval queue; immutable audit writes | cloud SDKs, `serde_yaml` playbooks |
| **Bug-Hunt Module** | Agentic LLM loop (hypothesize → tool-call verify → iterate, bounded depth); structured vulnerability report | `async-openai`, custom Anthropic client, tool-call dispatcher |
| **Token-Compression Layer** | `TokenBudget` packer; semantic dedup; schema-ref compression; diff extraction; map-reduce; prompt caching | `tiktoken-rs`, `serde_json`, embeddings client |
| **Storage layer** | Postgres (relational + audit), Graph DB, Redis (queue/cache/pubsub), object store (evidence/backups/weights) | Postgres 16, Neo4j 5 or pg, Redis 7, MinIO |
| **OTEL Collector** | Traces/metrics/logs export to the **client's** observability stack (optional) | OpenTelemetry Collector |

---

### 4. Workflow Data-Flow Diagrams (W1–W7)

**W1 — First-Run / Onboarding**
```
operator: just install
  └─> detect runtime (docker | k8s/helm)
        └─> deploy stack; wait healthchecks green
              └─> open http://localhost:8443 in browser
                    └─> [License screen] enter key
                          └─> License Svc: Ed25519 verify (offline) → claims → encrypt+store → set feature flags
                                └─> [LLM key wizard] enter OpenAI/Anthropic keys → encrypt with client master key
                                      └─> [Cloud wizard] guided role/credential setup per cloud (IaC snippet emitted)
                                            └─> trigger INITIAL FULL SCAN (async)
                                                  └─> dashboard renders findings as they stream over WS
```

**W2 — Continuous Scan (event-driven + scheduled)**
```
CloudTrail / EventGrid / Pub-Sub  ──event──> Collector
  └─> normalize → AssetEvent → Redis queue
        └─> Check Engine: select relevant Cedar/Rego rules → evaluate
              └─> Scoring engine → Finding(severity, confidence)
                    └─> persist (Postgres) + upsert graph node/edges
                          └─> RL ranker assigns priority
                                └─> WebSocket push to dashboard (live)
                                      └─> ASYNC (non-blocking): LLM triage narrative via TokenBudget
                                            └─> notify Slack / email / webhook
```

**W3 — Self-Healing (Remediation)**
```
Finding crosses auto-heal threshold
  └─> Remediation Engine: lookup playbook by rule_id
        └─> classify: SAFE | REVERSIBLE | DESTRUCTIVE
              ├─ SAFE:        dry-run → confirm no-side-effect → execute → audit
              ├─ REVERSIBLE:  snapshot state → execute → health-check
              │                 └─ pass → audit ;  fail → auto-rollback from snapshot → audit
              └─ DESTRUCTIVE: push to HITL queue → WS + Slack notify
                                └─ await approval (timeout T)
                                      ├─ approved → execute → audit
                                      └─ timeout  → abort → audit (no action taken)
   (every branch terminates in an APPEND-ONLY immutable audit record)
```

**W4 — LLM Bug Hunting (Claude-BugHunter-inspired)**
```
analyst selects target scope (account / namespace / asset set)
  └─> assemble context: KG subgraph + raw configs (compressed via TokenBudget)
        └─> LLM: generate hypotheses [attack vectors, misconfigs, logic flaws]
              └─> for each hypothesis (bounded loop, max depth D, max tools N):
                    └─> tool-call: read-only cloud query to VERIFY against live state
                          └─> feed result back to LLM → confirm/refute/refine
              └─> emit structured vulnerability report (JSON schema)
                    └─> scoring engine assigns severity/CVSS-like score
                          └─> insert into main finding stream
```

**W5 — Security Graph**
```
ingest all assets → create nodes
  └─> build edges: identity→permission→asset, asset→network, asset→vuln, asset→control
        └─> attack-path compute: BFS/Dijkstra from {internet-exposed} → {sensitive targets}
              └─> blast-radius: count reachable sensitive nodes per compromised node
                    └─> visualize interactive node graph in dashboard
                          └─> "explain this path" → LLM narrative
                                └─> remediation priority weighted by blast radius
```

**W6 — RL Feedback Loop**
```
analyst views ranked finding → action {confirm | dismiss | escalate}
  └─> log to rl_feedback(finding_features, action, reward)
        └─> online bandit update (single gradient/posterior step)
              └─> next ranking incorporates feedback immediately
        └─> periodic BATCH eval on held-out feedback
              └─> if NDCG/precision improvement > threshold:
                    promote new weights → archive old in model registry (object store)
```

**W7 — License & Key Management**
```
key entered → backend Ed25519 verify (embedded pubkey)
  └─> extract claims {tenant_id, expiry, tier, seats, features[]}
        └─> store encrypted (client master key) → set feature flags in cache
              ├─ ONLINE mode: heartbeat every 24h to vendor API → renewal/revocation check
              │                  └─ on failure: enter GRACE PERIOD (configurable, e.g. 14d) then degrade to Community
              └─ OFFLINE mode: rely on local expiry only (air-gapped friendly)
        └─> near-expiry (e.g. T-30d): in-app banner + email notification
```

---

### 5. Docker Compose Full Service Map

```yaml
# docker-compose.yml  (single-node / small-team)
services:
  api:            # axum API + embedded SPA; depends_on: postgres, redis, graph-db
  scanner:        # check engine + collectors; can scale --scale scanner=N
  rl-engine:      # ranking service
  graph-db:       # neo4j:5  (or omitted if pg-CTE mode)
  postgres:       # postgres:16  (findings, audit, licenses, usage)
  redis:          # redis:7  (queue/cache/pubsub)
  minio:          # object store (evidence, backups, model weights)
  otel-collector: # observability export (optional profile)
```

**Container hardening (every image):**
- Multi-stage `Dockerfile`: builder stage with full Rust toolchain + `cargo-chef` for dependency caching → final stage `gcr.io/distroless/cc` (or `alpine` if musl).
- `USER 65532:65532` (non-root), `read_only: true` rootfs with explicit `tmpfs` mounts.
- `cap_drop: [ALL]`; add back **only** `NET_RAW`/`BPF` on the optional eBPF agent.
- `mem_limit`, `cpus`, `pids_limit` set; `no-new-privileges:true`.
- Per-service `networks` for isolation (frontend net for api/ingress; backend net for data stores — data stores never exposed to ingress net).
- `healthcheck` on every service; `restart: unless-stopped`.
- Secrets via Docker secrets or `.env` with documented `.env.example`; never bake secrets into images.
- Images signed with **cosign**; compose docs show `cosign verify` step.

```Dockerfile
# Stage 1: planner
FROM rust:1.84 AS chef
RUN cargo install cargo-chef
WORKDIR /app
# Stage 2: cacher
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json
# Stage 3: builder
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin secureops-api
# Stage 4: runtime
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/secureops-api /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/secureops-api"]
```

---

### 6. Helm Chart Structure

```
secureops/
├── Chart.yaml                 # parent chart, version pinned to app version
├── values.yaml                # full config surface (see below)
├── values-eks.yaml            # AWS overlay
├── values-gke.yaml            # GCP overlay
├── values-aks.yaml            # Azure overlay
├── templates/
│   ├── _helpers.tpl
│   ├── serviceaccount.yaml     # minimal SA per workload
│   ├── rbac.yaml               # least-privilege Roles/RoleBindings
│   ├── networkpolicy.yaml      # default-deny + explicit allows
│   ├── ingress.yaml            # cert-manager annotations
│   ├── hpa-scanner.yaml        # HPA for scanner workers
│   ├── pdb.yaml
│   ├── hooks/
│   │   ├── db-migrate-job.yaml      # helm.sh/hook: pre-install,pre-upgrade
│   │   └── license-validate-job.yaml# helm.sh/hook: post-install (fails install if invalid)
└── charts/                     # subcharts
    ├── api/  scanner/  graph/  rl/  selfheal/
    ├── postgresql/  (bitnami dependency, pinned)
    ├── redis/       (bitnami dependency, pinned)
    └── minio/
```

**values.yaml surface (abridged):** `global.image.{registry,tag,pullPolicy}`, per-service `resources/replicas/nodeSelector/tolerations/affinity`, `ingress.{enabled,className,host,tls,certManager.issuer}`, `persistence.{storageClass,size}` per stateful service, `secrets.provider: native|external-secrets|vault`, `podSecurityStandard: restricted`, `networkPolicy.enabled: true`, `license.mode: online|offline`, `cloud.provider: eks|gke|aks`.

**Security defaults:** Pod Security Standard **restricted**; `securityContext` runAsNonRoot, readOnlyRootFilesystem, drop ALL caps, seccomp `RuntimeDefault`; default-deny NetworkPolicy + explicit allows (api↔redis, scanner↔postgres, etc.).

**Multi-cloud overlays:**
- **EKS:** `storageClass: gp3` (EBS CSI), ALB ingress (`alb.ingress.kubernetes.io/*`), **IRSA** (`eks.amazonaws.com/role-arn` SA annotation) so scanner assumes a read-only role with no static keys.
- **GKE:** `pd-ssd` PD CSI, GCLB ingress, **Workload Identity** (`iam.gke.io/gcp-service-account` SA annotation).
- **AKS:** `managed-csi` Managed Disks, **AGIC** (Application Gateway Ingress Controller), **Workload Identity** (`azure.workload.identity/use: true`).

---

### 7. Justfile — Full Recipe List

```just
# Justfile — SecureOps operator interface
set shell := ["bash", "-uc"]
set dotenv-load := true

runtime := `if command -v kubectl >/dev/null && kubectl config current-context >/dev/null 2>&1; then echo helm; else echo docker; fi`
namespace := env_var_or_default("SECUREOPS_NS", "secureops")
compose := "docker compose -f docker-compose.yml"

# Auto-detect runtime and do a full install
install:
    @echo "Detected runtime: {{runtime}}"
    @if [ "{{runtime}}" = "helm" ]; then just _install-helm; else just _install-docker; fi

_install-docker: build up _open-browser
_install-helm:
    helm dependency update ./secureops
    helm upgrade --install secureops ./secureops -n {{namespace}} --create-namespace --wait
    just _open-browser

# Local dev with hot reload (cargo-watch + vite)
dev:
    cargo watch -x 'run --bin secureops-api' & \
    (cd web && npm run dev)

build:                       # build all container images
    {{compose}} build

up:                          # bring up all services
    {{compose}} up -d

down:                        # stop all services
    {{compose}} down

scan target="all":           # trigger manual full scan
    curl -fsS -X POST localhost:8443/api/v1/scans -d '{"scope":"{{target}}"}'

upgrade:                     # pull new images, migrate, restart
    @if [ "{{runtime}}" = "helm" ]; then \
       helm upgrade secureops ./secureops -n {{namespace}} --wait ; \
     else \
       {{compose}} pull && {{compose}} run --rm api migrate && {{compose}} up -d ; fi

backup:                      # snapshot postgres + graph + object store
    ./scripts/backup.sh

restore backup_id:           # restore from a backup id
    ./scripts/restore.sh {{backup_id}}

logs service:                # tail logs for one service
    @if [ "{{runtime}}" = "helm" ]; then \
       kubectl logs -f -n {{namespace}} deploy/{{service}} ; \
     else {{compose}} logs -f {{service}} ; fi

status:                      # health check all services
    @if [ "{{runtime}}" = "helm" ]; then kubectl get pods -n {{namespace}} ; \
     else {{compose}} ps ; fi

license:                     # open license activation screen
    just _open-browser "/license"

add-cloud provider:          # wizard to add a cloud account (aws|gcp|azure)
    ./scripts/add-cloud.sh {{provider}}

_open-browser path="/":
    @python3 -c "import webbrowser; webbrowser.open('http://localhost:8443{{path}}')" || true
```

**Key `just` facts used:** recipes can declare **dependencies** (`install: build up`), accept **parameters with defaults** (`scan target="all"`), use **variables** and **backtick command evaluation** (`runtime := \`…\``), load `.env` via `set dotenv-load`, define **private recipes** (leading `_`), and use shell conditionals for runtime auto-detection.

---

### 8. License Key System (cryptographic design)

**Generation (vendor side, offline keygen tool):**
- Vendor holds an **Ed25519 private key** (kept offline / in an HSM). Each license is a compact token: `base64url(payload).base64url(signature)` where `payload` is canonical JSON:
```json
{ "lic_id":"uuid", "tenant_id":"acme", "tier":"enterprise",
  "seats":50, "features":["rl","selfheal_destructive","ebpf","sso"],
  "issued":"2026-06-04T00:00:00Z", "expiry":"2027-06-04T00:00:00Z",
  "mode":"offline", "grace_days":14 }
```
- Signature = `Ed25519_sign(privkey, canonical_payload_bytes)`. (JWT with `EdDSA` alg is an acceptable equivalent encoding.)

**Validation (client side, embedded):**
1. The **Ed25519 public key is compiled into the binary** (`const VENDOR_PUBKEY: [u8;32]`). 
2. `verify(VENDOR_PUBKEY, payload_bytes, sig)` — pure local check, no network.
3. Check `expiry > now`. Enforce `seats` and `features` against tier.
4. Persist activated license **encrypted at rest** (AES-256-GCM with a client-generated master key derived via Argon2id from an operator passphrase or a generated key stored in a K8s/Docker secret — **never vendor-accessible**).

**Online vs offline modes:**
- **Offline (default for air-gapped):** signature + local expiry only.
- **Online:** every 24h, POST `{lic_id, instance_fingerprint, version}` to the vendor's lightweight license API; receive `{status: active|revoked, expiry}`. On network failure, enter a **grace period** (`grace_days`); after grace, degrade to Community tier rather than hard-locking (the GitLab EE / Vault Enterprise pattern — features disable, data stays accessible).

**Comparable patterns:** Metabase, GitLab EE, HashiCorp Vault Enterprise, Portainer, and Netdata all validate a signed token locally and degrade gracefully on expiry rather than blocking access to existing data — SecureOps adopts the same "fail-open-to-Community" posture.

---

### 9. Dashboard UX Flow

**First-run wizard (cannot be skipped, ordered):**
1. **License** — enter key → live Ed25519 validation → shows tier/seats/expiry on success.
2. **LLM keys** — OpenAI / Anthropic / Azure OpenAI / custom OpenAI-compatible endpoint; test-call button; keys encrypted with client master key.
3. **Cloud onboarding** — pick AWS/GCP/Azure; UI **emits the exact IaC/CLI** to create a read-only role (CloudFormation/Terraform/gcloud/az snippet); paste back ARN/SA/credentials; connectivity test.
4. **Initial scan** — one click; progress bar; findings stream in live.

**Main sections:** Security Findings (filter/sort, RL-ranked), Compliance (CIS/SOC2/PCI mappings + report export), Asset Graph (interactive node-graph, click a node → blast radius, "explain path"), Remediation Queue (HITL approvals with diff preview + approve/deny + timeout countdown), Usage (per-provider token consumption + **client-side cost estimate** — there is no vendor billing), Profile/RBAC, License (status, renewal, feature flags).

**Cross-cutting:** WebSocket live updates for findings + remediation approvals; dark mode default; responsive; React SPA served as static assets from axum (`tower-http::ServeDir` with SPA fallback).

---

### 10. Token Compression Implementation Design

Implement a Rust `TokenBudget` abstraction:
```rust
struct TokenBudget { model: ModelId, window: usize, reserved_output: usize }
struct Evidence { id: EvId, kind: EvKind, raw: String, relevance: f32, est_tokens: usize }

impl TokenBudget {
    /// Greedy/knapsack pack: sort by relevance/token-cost ratio, fit within budget,
    /// summarize or drop the overflow tail.
    fn pack(&self, items: Vec<Evidence>) -> PackResult { /* ... */ }
}
```
Techniques layered in:
- **Semantic deduplication** — embed findings, cluster near-duplicates (cosine ≥ τ), send one representative + `count`.
- **Schema-reference compression** — define JSON schemas/control catalog **once** in the system prompt; reference by short ID in messages.
- **Evidence summarization (diff/delta)** — for IAM policies / K8s manifests, send only the **changed or violating fragment**, not the whole document.
- **Chunked map-reduce** — huge Terraform plans → chunk → parallel `summarize` → `reduce` into a single finding-relevant digest.
- **Provider prompt caching** — mark stable context (asset-graph summary, control catalog) with **Anthropic `cache_control`** / OpenAI prompt-caching so it isn't re-billed each call.
- **Structured-output compression** — request compact JSON (short internal field names, no whitespace), expand client-side.
- **Relevance filtering** — inject only assets/findings relevant to the specific task subgraph.

---

### 11. Security Knowledge Graph Design (Graphify-inspired)

**Node types:** `Asset` (EC2/GCE/VM, S3/GCS/Blob, RDS, Lambda, K8s workload…), `Identity` (user, role, service account), `Permission`/`Policy`, `Network` (VPC/subnet/SG/NSG/firewall), `Vulnerability`, `ComplianceControl`.

**Edge types:** `CAN_ASSUME` (identity→role), `HAS_PERMISSION` (identity→action on asset), `CONNECTS_TO` (network reachability), `EXPOSES` (asset→internet), `HAS_VULN`, `VIOLATES` (asset→control), `OWNS`.

**Queries:**
- **Attack path:** BFS/Dijkstra from `{nodes where EXPOSES→internet}` to `{assets tagged sensitive}`; edge weights = exploit difficulty.
- **Blast radius:** for each node, count sensitive nodes reachable if it is compromised → prioritization weight.
- **"Explain this path":** serialize the path → compress via `TokenBudget` → LLM narrative.

**Graph DB recommendation (decision):** Default to **Neo4j 5** for production tiers — Cypher gives concise variable-length path queries (`MATCH p=(:Internet)-[*..6]->(:Sensitive)`) essential for attack paths. For Community/single-binary simplicity, offer a **PostgreSQL + recursive CTE** mode (+ `pgvector` for semantic node search) so small deployments run one relational engine. Make this a `values.yaml` / compose-profile switch. Avoid DGraph/custom unless a specific scale need emerges.

---

### 12. LLM Bug-Hunting Module Design (Claude-BugHunter-inspired)

**Agentic loop (bounded):** system prompt primes the model as a cloud-pentest reasoner; supply few-shot misconfiguration exemplars; the model emits hypotheses, then for each one issues **tool calls** (function-calling) restricted to **read-only** cloud queries (e.g., `get_iam_policy`, `describe_sg`, `list_public_buckets`). Results are fed back; loop iterates to `max_depth` (e.g., 4) and `max_tool_calls` (e.g., 25) to bound cost. Final output is a strict JSON vulnerability report (title, attack vector, affected assets, evidence, suggested severity, remediation).

**Safety rails:** all tool calls are read-only and rate-limited; no mutation tools in the bug-hunt loop; outputs flow into the same scoring + finding stream as automated checks (the LLM never directly remediates — it only proposes findings).

---

### 13. Phase Plan P0–P9 (each ships Docker + Helm + Justfile)

- **P0 — Foundation & License (weeks 0–4).** Rust workspace; axum skeleton; **Ed25519 license system** (keygen tool + embedded-pubkey verify + encrypted storage + grace state machine); Postgres schema bootstrap + migrations; **multi-stage distroless Dockerfile + Compose + Helm parent/subchart skeleton + cosign signing**; **Justfile: `install/build/up/down/logs/status/license`**. *Deliverable: stack stands up, license validates offline.*
- **P1 — Dashboard MVP + Activation (weeks 4–8).** React SPA served by axum; first-run wizard (license → LLM keys → placeholder cloud step); WebSocket scaffold; RBAC; tier feature-flag plumbing. Helm `license-validate` post-install hook; Justfile unchanged. *Deliverable: browser auto-opens, license activates, dashboard renders.*
- **P2 — Multi-Cloud Scanning (weeks 8–14).** Collectors (AWS/GCP/Azure) with IRSA/Workload Identity; normalizer; **Cedar + Rego (regorus)** rule packs (CIS baseline); scoring; findings stream over WS; **Justfile `scan`, `add-cloud`**. HPA for scanner in Helm. *Deliverable: real findings from all 3 clouds.*
- **P3 — Knowledge Graph core (weeks 14–18).** Graph ingest; node/edge model; Neo4j subchart + pg-CTE fallback mode; asset-graph dashboard view. *Deliverable: explorable graph.*
- **P4 — Attack Paths & Blast Radius (weeks 18–22).** BFS/Dijkstra path engine; blast-radius scoring; interactive path visualization; "explain path" LLM hook. *Deliverable: attack paths shown + prioritized.*
- **P5 — LLM Bug-Hunting + Token Compression (weeks 22–28).** `TokenBudget` layer (dedup, schema-ref, diff, map-reduce, prompt caching); multi-provider client with fallback; agentic bug-hunt loop; Usage section (token/cost). *Deliverable: bug-hunt produces findings within a bounded token budget.*
- **P6 — Self-Healing (weeks 28–34).** Playbook engine; Safe/Reversible classes; dry-run; snapshot/rollback; immutable audit log; Justfile `backup/restore`. *Deliverable: Safe + Reversible auto-remediation.*
- **P7 — RL Feedback Loop (weeks 34–38).** Contextual bandit ranker; `rl_feedback` capture; online updates; model registry; batch eval gating. *Deliverable: rankings improve from analyst actions.*
- **P8 — Enterprise (weeks 38–46).** Destructive-class healing with HITL queue + timeout; SSO/SAML/OIDC; eBPF runtime agent (the only container granted `BPF`/`NET_RAW`); custom policy packs; audit-grade exports; federated threat intel. *Deliverable: full Enterprise tier.*
- **P9 — Hardening & GA (weeks 46–52).** Pen-test; SBOM + cosign attestations; chaos/rollback testing; performance tuning; docs; upgrade/migration runbooks; Justfile `upgrade`. *Deliverable: GA-ready.*

---

### 14. Worldwide Rollout W0–W7

- **W0 Internal alpha** (vendor + design partners, single cloud).
- **W1 Private beta** (≤10 design-partner tenants, all 3 clouds, offline license only).
- **W2 Public beta** (self-serve Community tier; online-mode heartbeat enabled).
- **W3 GA — North America.**
- **W4 GA — EU/EEA** (GDPR posture; since self-hosted, **data never leaves client tenancy** — emphasize this; provide EU-resident vendor license API endpoint).
- **W5 GA — UK + APAC.**
- **W6 GA — regulated/air-gapped** (offline-only license bundles; gov/defense; FIPS build of crypto).
- **W7 GA — global + partner/MSP channel** (multi-tenant license fleet management for MSPs).

Data-residency note: because the product is self-hosted, customer data residency = the client's own cloud region; the only cross-border flow is the optional license heartbeat, for which regional endpoints are provided.

---

### 15. Rust Crate Dependency Map

| Concern | Crates |
|---|---|
| Web/API | `axum`, `tower`, `tower-http`, `hyper`, `tonic` (gRPC), `tokio-tungstenite` (WS), `utoipa`+`utoipa-swagger-ui` |
| Async runtime | `tokio`, `futures`, `async-trait` |
| Serde/data | `serde`, `serde_json`, `serde_yaml` |
| DB | `sqlx` (Postgres, compile-checked), `neo4rs` (graph), `redis`/`deadpool-redis` |
| Policy | `cedar-policy`, `regorus` (Rego in pure Rust) |
| Crypto/license | `ed25519-dalek`, `ring`, `aes-gcm`, `argon2`, `jsonwebtoken`, `rand` |
| LLM | `async-openai`, custom Anthropic client over `reqwest`, `tiktoken-rs` |
| Cloud SDKs | `aws-sdk-*` (aws-sdk-rust), `google-cloud-rs`, `azure_*` |
| Graph algorithms | `petgraph`, `ndarray` |
| Observability | `tracing`, `tracing-subscriber`, `opentelemetry`, `opentelemetry-otlp` |
| Errors/util | `thiserror`, `anyhow`, `uuid`, `chrono`, `config` |

Workspace layout: `crates/{api, license, scan, graph, rl, selfheal, bughunt, tokenbudget, common}` + `tools/keygen`.

---

### 16. API Specification (selected)

**REST (`/api/v1`):**
- `POST /license/activate` `{key}` → `{tier, expiry, features}`; `GET /license`
- `POST /llm-keys` (encrypted store); `GET /llm-keys/usage`
- `POST /clouds` (onboard); `GET /clouds`
- `POST /scans` `{scope}`; `GET /scans/{id}`; `GET /findings?severity=&status=`
- `POST /findings/{id}/action` `{confirm|dismiss|escalate}` (feeds RL)
- `GET /graph/paths?from=internet&to=sensitive`; `GET /graph/blast-radius/{node}`
- `POST /bughunt` `{scope}` → job id; `GET /bughunt/{id}`
- `GET /remediations/queue`; `POST /remediations/{id}/approve|deny`
- `GET /compliance/reports?framework=cis|soc2|pci`

**gRPC services:** `ScanService`, `GraphService.ComputePaths`, `RlService.Rank/Feedback`, `RemediationService.Classify/Execute` (internal service-to-service).

**WebSocket channels:** `/ws/findings` (live), `/ws/remediation` (approvals), `/ws/scan-progress`.

---

### 17. Database Schema (Postgres + Graph)

**Postgres (abridged):**
```sql
licenses(id, tenant_id, tier, seats, features jsonb, expiry, mode, activated_payload bytea /*aes-gcm*/, created_at)
clouds(id, provider, account_ref, role_ref, status, added_at)
assets(id, cloud_id, type, arn, region, metadata jsonb, first_seen, last_seen)
identities(id, cloud_id, type, name, metadata jsonb)
findings(id, asset_id, rule_id, severity, confidence, status, score, rl_priority, evidence jsonb, created_at)
remediations(id, finding_id, playbook_id, class /*safe|reversible|destructive*/, state, snapshot_ref, approver, created_at)
rl_feedback(id, finding_id, features jsonb, action, reward, created_at)
usage_metrics(id, provider, tokens_in, tokens_out, est_cost_usd, occurred_at)
audit_log(id, actor, action, target, before jsonb, after jsonb, ts)  -- append-only; no UPDATE/DELETE grants
```
Audit immutability enforced via revoked UPDATE/DELETE privileges + optional hash-chain (`prev_hash`).

**Graph (Neo4j or pg-CTE mirror):** nodes `Asset/Identity/Permission/Network/Vulnerability/ComplianceControl`; relationships `CAN_ASSUME/HAS_PERMISSION/CONNECTS_TO/EXPOSES/HAS_VULN/VIOLATES`.

---

### 18. RL System Design

- **Model:** contextual bandit (LinUCB or Thompson sampling) — robust, online, explainable. Reward: `confirm=+1`, `escalate=+1.5`, `dismiss=-1` (false-positive penalty), decayed by time-to-action.
- **Features:** severity, asset criticality, blast radius, rule category, recency, cloud, exposure-to-internet flag.
- **Online update:** single posterior/gradient step per analyst action → immediate re-ranking.
- **Promotion gating:** periodic batch eval on held-out feedback (NDCG@k, precision@k); promote new weights only if improvement > threshold; archive prior weights in object store (model registry) for rollback.

---

### 19. Self-Healing Playbook Design

```yaml
# playbooks/s3-public-acl.yaml
id: s3-public-acl
matches: { rule_id: "S3.PUBLIC_READ" }
class: reversible           # safe | reversible | destructive
dry_run: { action: describe-bucket-acl }
snapshot: { capture: ["acl", "policy"] }
execute: { action: put-bucket-acl, args: { acl: private } }
health_check: { verify: "bucket not publicly readable" }
rollback: { action: put-bucket-acl, from: snapshot }
audit: required
```
Classification rubric: **Safe** = idempotent, no data/availability impact (e.g., add a tag, enable logging); **Reversible** = state-changing but snapshot-restorable (e.g., tighten an SG/ACL); **Destructive** = data loss or hard-to-reverse (e.g., delete a resource, revoke a role) → mandatory HITL with timeout. Every execution writes to the append-only `audit_log`.

---

### 20. Security Tier Feature Matrix

| Capability | Community (free, key still required) | Pro (paid) | Enterprise |
|---|---|---|---|
| Clouds | 1 | 3 (AWS+GCP+Azure) | 3 + unlimited accounts |
| Scans/day | Limited (e.g. 2) | Unlimited | Unlimited |
| Findings + compliance dashboard | ✓ basic | ✓ full reports | ✓ audit-grade exports |
| Knowledge graph + attack paths | View only | ✓ | ✓ |
| LLM analysis / bug-hunting | ✗ | ✓ | ✓ |
| RL prioritization | ✗ | ✓ | ✓ |
| Self-healing | ✗ | Safe class | Safe + Reversible + Destructive (HITL) |
| eBPF runtime agent | ✗ | ✗ | ✓ |
| SSO/SAML/OIDC | ✗ | ✗ | ✓ |
| Custom policy packs / federated threat intel | ✗ | ✗ | ✓ |
| Seats | Limited | Per license | Unlimited |
| Support | Community | Standard | SLA |

**Enforcement:** every gated capability checks `license.tier` and `license.features[]`; the check is compiled into a **Cedar policy evaluated at the API edge** (so the gate is declarative, auditable, and consistent across REST/gRPC/WS). Community still requires a (free) license key for install tracking and tier identification.

---

## Recommendations

1. **Build P0 license + container/Helm/Justfile foundation first and treat "offline Ed25519 verification with embedded public key" as a non-negotiable invariant.** Everything else depends on the deploy-and-activate path working in an air-gapped environment. *Threshold to proceed to P1:* `just install` brings the stack to all-healthy and a signed key activates with the vendor API unreachable.

2. **Default the data model to PostgreSQL + recursive CTEs for Community, and gate Neo4j behind Pro/Enterprise.** This minimizes the operational burden you push onto self-hosting clients while still delivering rich attack-path queries to paying tiers. *Switch to Neo4j-by-default only if* path queries at a design partner exceed ~p95 500 ms on the CTE engine.

3. **Ship the `TokenBudget` layer (P5) before the bug-hunt loop is exposed to customers.** Because the client pays their own LLM bills, an uncontrolled agentic loop is a trust-destroying cost event. *Gate:* bug-hunt must complete a full target-scope run under a configurable token ceiling (default e.g. 200k tokens) with prompt caching demonstrably reducing repeat-call cost.

4. **Make self-healing opt-in and start Safe-only.** Do not enable Reversible or Destructive classes by default in any tier; require explicit per-playbook opt-in plus the HITL queue for Destructive. *Promote a playbook from Reversible→default-on only after* it has executed with successful auto-rollback in staging across all three clouds.

5. **Keep the vendor license API stateless and minimal, and offer regional endpoints before EU/regulated GA (W4/W6).** It must carry only `{license_id, fingerprint, version}` and must never be on the data path. Provide an offline license bundle for air-gapped customers from W6.

6. **Verify the four cited external sources before building their inspired modules.** Treat the Claude-BugHunter, OpenHuman, Caveman, and Graphify designs in this spec as *target patterns to validate*, not confirmed reproductions (see Caveats).

---

## Caveats

- **The four external sources could not be retrieved.** Both the lead agent's and the subagent's web-search/fetch tools returned hard execution errors in this environment, so **Claude-BugHunter (elementalsouls), the OpenHuman/tinyhumans token-compression page, Caveman (JuliusBrussee), and Graphify (safishamsi) were not read**. Their feature sets, exact techniques, code patterns, README contents, token-compression ratios, and graph data models in this document are **reconstructed from the source names and standard domain patterns**, not verified from the live repos. Before implementing the bug-hunting, token-compression, Caveman-inspired, and knowledge-graph modules, a developer must fetch each repo/page and reconcile any differences. In particular, I could not confirm what "Caveman" actually does — it should be researched and its relevant features slotted into P2/P5 once known.
- **Crate selections are current best-fit recommendations, not pinned guarantees.** Some crates (e.g., `regorus` for Rego, `neo4rs`, cloud SDKs) evolve quickly; pin versions and re-verify maintenance status at implementation time. The Rego-in-Rust choice (`regorus`) and Cedar can coexist, but running two policy engines adds complexity — consider standardizing on Cedar if Rego rule packs are not strictly required.
- **License "fail-open-to-Community" is a business decision, not a technical mandate.** I recommend graceful degradation (the GitLab/Vault pattern) over hard-locking, but the vendor must confirm this matches commercial intent.
- **Timelines (week ranges) are planning estimates** for sequencing/dependency reasoning, not commitments; they assume a small dedicated team and will shift with staffing.
- **eBPF agent privileges are a real attack-surface tradeoff.** It is the one component requiring elevated capabilities (`BPF`/`NET_RAW`); isolate it as a separate DaemonSet/container with its own minimal scope, and keep it Enterprise-gated and optional.
- **"Cedar at the API edge for tier gating" assumes Cedar can express your full feature-flag matrix**; validate that seat-count and rate-limit style constraints (which are stateful/numeric) are enforced in application logic with Cedar handling the declarative allow/deny, rather than expecting Cedar to track counters.

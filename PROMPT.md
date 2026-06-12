# SecureOps - Claude Opus 4.8 Prompt Pack
## Phases P4 → P9 · Build + Test prompts · Master system prompt

> **How to use:** Open a new Claude Opus 4.8 conversation.
> 1. Paste the **MASTER SYSTEM PROMPT** first (sets context for the whole session).
> 2. Paste the **BUILD prompt** for the phase you are implementing.
> 3. After Claude generates code, paste the **TEST prompt** for the same phase.
> 4. Repeat BUILD→TEST until phase exit criteria pass, then move to the next phase.

---

## MASTER SYSTEM PROMPT
*~75 tokens · paste once per session · anchors all phase builds*

```
ROLE: SecureOps Senior Rust/Cloud-Security Engineer.
STACK: 16-crate Rust workspace - axum | cedar-policy | regorus | aya | tokio
       | sqlx | ed25519-dalek | async-openai | petgraph | ndarray.
PHASES DONE: P0-P3 (workspace+license-core, audit+harden,
  Ring-2: egress-proxy + DNS-sinkhole + signed-log + IPC unix socket).
LAW:
  ① compiles: cargo build --release
  ② every fn has #[test]
  ③ each phase ships: Dockerfile delta + Helm delta + Justfile recipe
  ④ no stubs, no todo!(), no unimplemented!()
  ⑤ audit_log is append-only (REVOKE UPDATE, DELETE) on every mutation
  ⑥ Cedar feature-gate every tier-locked capability
FORMAT: Rust code → SQL schema → Justfile recipe → tests → cargo test command.
Zero prose filler. Start with code.
```

---

## P4 - eBPF Kernel Enforcement
*Weeks 4-8 after P0-P3 · Feature-gated, Linux x86_64 · ~195 tokens build · ~90 tokens test*

### P4 BUILD

```
PHASE P4 - eBPF Kernel Enforcement
PRIOR STATE: secureops-bpf scaffolded, feature-gated off.
  Daemon has: IPC unix socket + AlertBus + append-only auditlog.

DELIVER:
1. aya kprobes: openat (filter: /root/.env /home/*/.env /etc/secrets/**) +
   connect → events into user-space ring buffer (aya::maps::RingBuf)
2. Per-PID correlation: DashMap<u32, PidState> with 500ms TTL.
   openat-then-connect within TTL = ExfilChain { pid, cred_path, dest }
3. LSM-BPF deny hook [#[cfg(feature="enforce")]]:
   deny connect() syscall on ExfilChain match → return EPERM to caller
4. Daemon wiring in secureops-daemon/src/bpf_wire.rs:
   spawn BpfAgent as JoinSet task, subscribe to AlertBus, push ExfilChain
5. seccomp generator: learn_mode() - ptrace-observe syscalls 30s →
   emit seccomp-bpf JSON allowlist suitable for systemd LoadFilter
6. Helm DaemonSet (Enterprise tier, label: tier=enterprise):
   hostPID: true, capabilities: add: [BPF, NET_RAW, SYS_ADMIN],
   readOnlyRootFilesystem: true, nodeSelector optional
7. Justfile: bpf-load, bpf-status, bpf-unload

OUTPUT FILES:
  secureops-bpf/src/lib.rs
  secureops-bpf/src/chain.rs
  secureops-bpf/src/seccomp.rs
  secureops-daemon/src/bpf_wire.rs
  deploy/helm/charts/bpf-agent/templates/daemonset.yaml
  Justfile additions
  #[cfg(test)] module with mock BpfEvent stream
```

### P4 TEST

```
P4 TEST VALIDATION - assert each:

UNIT openat("/root/.env") + connect("1.2.3.4:443") same PID within 400ms
  → ExfilChain alert fires on AlertBus within 50ms

UNIT openat("/tmp/readme.txt") + connect = NO alert (non-credential path)

UNIT PID state TTL: same pair 501ms apart = NO alert (state expired)

UNIT ENFORCE=true: mock connect() returns EPERM (Err(syscall denied))

INTEGRATION: bpf-load Justfile recipe on Linux → exits 0

MOCK-MODE: cargo test --features bpf-mock passes on macOS (no kernel needed)

QUALITY: cargo clippy --features bpf -- -D warnings → clean
```

### P4 Exit Criteria
- [ ] ExfilChain fires correctly in mock-mode on CI
- [ ] Helm DaemonSet applies to EKS test cluster without errors
- [ ] `just bpf-load` / `just bpf-status` / `just bpf-unload` all exit 0

---

## P5 - Platform Services (HTTP API + Storage Stack)
*Creates all storage infra · ~220 tokens build · ~110 tokens test*

### P5 BUILD

```
PHASE P5 - Platform Services (HTTP API + Storage Stack)
PRIOR STATE: P0-P3 done. No HTTP server, no Postgres, no Redis, no MinIO.

DELIVER:
1. secureops-api crate: axum router, utoipa OpenAPI, Cedar AuthZ middleware,
   dual auth: JWT (HMAC-SHA256) + per-tenant API key (hashed in DB)

2. REST surface (all under /api/v1):
   POST /license/activate  {key} → {tier,expiry,features}
   GET  /license
   POST /llm-keys          {provider, key_encrypted}
   GET  /llm-keys/usage
   POST /clouds            {provider, role_arn|sa_email|client_id}
   POST /scans             {scope:"all"|"aws"|"gcp"|"azure"|asset_id}
   GET  /scans/{id}
   GET  /findings          ?severity=&status=&limit=&offset=
   POST /findings/{id}/action  {action:"confirm"|"dismiss"|"escalate"}
   GET  /compliance/reports    ?framework=cis|soc2|pci&format=json|pdf

3. WebSocket hub: /ws/findings /ws/remediation /ws/scan-progress
   tokio::broadcast channel → per-connection fan-out task

4. sqlx migrations 001-006 (Postgres 16):
   001_licenses, 002_clouds, 003_assets_identities,
   004_findings, 005_remediations_feedback, 006_usage_audit
   audit_log: REVOKE UPDATE, DELETE ON audit_log FROM secureops_app;

5. Redis (deadpool-redis): scan job queue (LPUSH/BRPOP),
   asset-summary cache (SET EX 300), WS relay pub/sub

6. MinIO/S3-compat: presigned PUT for evidence upload,
   GET for snapshot restore, bucket: secureops-{tenant_id}

7. docker-compose.yml: api | scanner(stub) | postgres:16 | redis:7 |
   minio | otel-collector. Networks: frontend (api+ingress),
   backend (data stores, NOT exposed to frontend net)

8. Helm parent chart: api+postgres+redis+minio subcharts,
   NetworkPolicy default-deny + explicit allows,
   HPA scanner (cpu≥70%), PodSecurityStandard restricted

9. Justfile: up, down, logs [service], status, scan [target="all"]

OUTPUT:
  crates/api/src/{main,router,auth,ws,health}.rs
  migrations/00{1..6}_*.sql
  docker-compose.yml + .env.example
  secureops/ Helm tree with all subcharts
  Justfile additions
  Integration tests: sqlx::test macro + testcontainers-rs for Redis
```

### P5 TEST

```
P5 TEST VALIDATION - assert each:

API: POST /license/activate valid Ed25519 key → 200 {tier,expiry,features}
API: POST /license/activate tampered key → 403 {error:"invalid_signature"}
API: POST /license/activate expired key → 403 {error:"license_expired"}

AUTH: Cedar blocks a Pro-tier endpoint (/bughunt) for Community license → 403
AUTH: Missing JWT → 401 with WWW-Authenticate header

WS: INSERT into findings → /ws/findings subscriber receives event within 100ms

INFRA: just up → all compose services show "Up (healthy)"
INFRA: just status exits 0 when all healthy, non-zero when any down

DB: sqlx migrate run twice = idempotent (second run: no-op, exits 0)
DB: INSERT audit_log ok. UPDATE audit_log → permission denied error
DB: DELETE audit_log → permission denied error

QUALITY: cargo test -p secureops-api green
QUALITY: cargo clippy -p secureops-api -- -D warnings clean
```

### P5 Exit Criteria
- [ ] `just up` → all 6 services healthy
- [ ] `just scan` returns scan job id
- [ ] `/api/v1/findings` returns findings via WS within 100ms

---

## P6 - Intelligence Layer (Graph + LLM Bug-Hunt + TokenBudget)
*Builds knowledge graph + agentic loop · ~240 tokens build · ~125 tokens test*

### P6 BUILD

```
PHASE P6 - Intelligence Layer
PRIOR STATE: Postgres+Redis live, findings persisted.
  No graph DB, no LLM integration, no TokenBudget.

DELIVER:
1. secureops-graph crate:
   - Neo4j adapter (neo4rs) + pg-CTE fallback (values.yaml: graph.backend: neo4j|pg)
   - Typed edges: CAN_ASSUME | HAS_PERMISSION | CONNECTS_TO |
     EXPOSES | HAS_VULN | VIOLATES | OWNS
   - Attack-path: BFS from {EXPOSES→internet} to {tagged:sensitive}
     Dijkstra edge weight = exploit_difficulty (1.0=trivial, 10.0=hard)
     Returns Vec<AttackPath> sorted DESC by blast_radius
   - Blast radius: count reachable sensitive nodes per compromised node
     → write to findings.blast_radius column

2. secureops-tokenbudget crate:
   struct TokenBudget { model: ModelId, window: usize, reserved_output: usize }
   struct Evidence { id: Uuid, kind: EvidenceKind, raw: String,
                     relevance: f32, est_tokens: usize }
   fn pack(items: Vec<Evidence>) -> PackResult  // greedy knapsack by relevance/cost

   Compression techniques (all required):
   a) cosine-dedup: embed findings, cluster ≥0.85 → one representative + count N
   b) schema-ref: send JSON schema ONCE in system prompt, reference by id
   c) diff-delta: IAM policies/K8s manifests → extract ONLY violating fragment
   d) map-reduce: large TF plans → chunk(4096t) → parallel summarize → reduce
   e) prompt-cache: Anthropic cache_control OR OpenAI prompt-caching headers

3. secureops-bughunt crate:
   trait LlmProvider: async fn complete(req: CompletionReq) -> CompletionResp
   Adapters: OpenAiProvider | AnthropicProvider | LocalProvider
   Agentic loop (bounded: max_depth=4, max_tool_calls=25):
     hypothesize → read-only tool-call → verify → confirm|refute|refine → repeat
   Token ceiling enforced by TokenBudget.pack() before EVERY LLM call
   Output: FindingReport { title, attack_vector, affected_assets,
     evidence_refs, severity, cvss_like_score, remediation_steps } (strict JSON)

4. API additions:
   GET  /graph/paths           ?from=internet&to=sensitive&max_depth=6
   GET  /graph/blast-radius/{node_id}
   POST /bughunt               {scope: account_id|namespace|asset_id}
   GET  /bughunt/{job_id}

5. Helm: neo4j:5 subchart under Pro/Enterprise (graph.backend=neo4j),
   pg-CTE mode for Community (no extra container)
6. Justfile: graph-rebuild, bughunt [scope="all"]

OUTPUT:
  crates/{graph,tokenbudget,bughunt}/src/*.rs
  crates/bughunt/src/providers/{openai,anthropic,local}.rs
  API route additions, neo4j Helm subchart, Justfile additions
  #[cfg(test)] with mock neo4rs + mock LLM responses
```

### P6 TEST

```
P6 TEST VALIDATION - assert each:

GRAPH: ingest 50 mock assets + 20 identities
  → edge count correct (verify with Cypher MATCH or pg CTE COUNT)

GRAPH: BFS on 1000-node mock graph:
  internet→EC2(public-SG)→RDS(unencrypted) path found in <200ms

BUDGET: pack() with 100 Evidence items, window=4096
  → output ≤4096 tokens, highest-relevance items included

BUDGET: schema-ref uses fewer tokens than 10 full schemas
  (measure with tiktoken-rs, assert ratio < 0.5)

BUDGET: cosine-dedup clusters two near-identical findings → ONE representative

BUGHUNT: mock model requesting unlimited tools
  → loop halts at exactly max_depth=4 iterations

BUGHUNT: mock LLM returning valid JSON
  → FindingReport validates against schema (serde_json::from_str ok)

BUGHUNT: mock LLM returning malformed JSON
  → error propagated, job state=Failed, no panic

API: GET /graph/paths → 200 { paths: [...] }
API: POST /bughunt → 200 { job_id: "uuid" }
API: GET /bughunt/{id} → 200 { status:"completed", report:{...} } within 5s

QUALITY: cargo test -p secureops-{graph,tokenbudget,bughunt} green
QUALITY: cargo clippy -- -D warnings clean
```

### P6 Exit Criteria
- [ ] Attack-path BFS finds paths on 1k-node graph in <200ms
- [ ] TokenBudget compression ratio >40% on 20 real IAM policies
- [ ] Bug-hunt loop halts correctly at max_depth

---

## P7 - Autonomy (RL Ranking + Self-Healing Cloud Playbooks)
*All cloud mutation lives here · ~250 tokens build · ~140 tokens test*

### P7 BUILD

```
PHASE P7 - Autonomy (RL Engine + Self-Healing Playbooks)
PRIOR STATE: Findings scored+graphed, HITL queue table exists.
  No RL, no cloud mutations.

DELIVER:
1. secureops-rl crate: LinUCB contextual bandit
   Features: severity(0-4), blast_radius(norm 0-1), exposure_internet(bool→f32),
     rule_category(onehot), cloud(onehot), recency_decay
   Rewards: confirm=+1.0, escalate=+1.5, dismiss=-1.0, time_decay=0.95^hours
   Online update: single posterior step per rl_feedback INSERT
   Alt: Thompson sampling (feature flag ts_sampling=true)
   Model registry: weights versioned to MinIO (rl/weights/{semver}.bin)
   Batch eval (every 1000 feedbacks): NDCG@10 + Precision@5 on held-out 20%
   Auto-promote if improvement > 0.02; archive prior weights

2. secureops-selfheal crate: YAML PlaybookEngine
   Execution paths:
   - Safe:        dry_run→execute→audit_log
   - Reversible:  snapshot→execute→health_check
                   ├ pass: audit_log
                   └ fail: rollback(snapshot)→audit_log(state=RolledBack)
   - Destructive: push_hitl_queue→broadcast_ws→send_slack→await_approval(30min)
                   ├ approved: execute→audit_log
                   └ timeout/denied: state=Aborted, NO cloud call, audit_log

   Circuit breaker: error_rate(class, 5min) > 0.2
     → halt class → AlertBus CriticalAlert → requires manual reset via API

3. Cloud backends (trait CloudBackend for mock injection):
   AWS: put_bucket_acl, update_security_group_rules, put_bucket_encryption
   GCP: set_iam_policy, update_firewall_rule, enable_vpc_flow_logs
   Azure: update_nsg_rule, set_storage_account_https_only

4. Sample playbooks (embedded YAML):
   s3-public-acl.yaml          (class: reversible)
   sg-open-ssh-world.yaml      (class: reversible)
   gcs-public-bucket.yaml      (class: reversible)
   k8s-privileged-pod.yaml     (class: destructive)
   enable-cloudtrail.yaml      (class: safe)

5. API additions:
   GET  /remediations/queue
   POST /remediations/{id}/approve  {reason}
   POST /remediations/{id}/deny     {reason}
   GET  /rl/stats

6. Justfile: heal-dry [target], heal-approve [id], heal-status

OUTPUT:
  crates/{rl,selfheal}/src/*.rs
  playbooks/*.yaml (5 samples)
  trait CloudBackend + mock implementations
  API route additions, Justfile additions
  #[cfg(test)] suite - NO live cloud calls (all via mock backend)
```

### P7 TEST

```
P7 TEST VALIDATION - assert each:

RL: LinUCB matrices update correctly after 10 known-reward feedbacks
  (verify expected posterior within 1e-6 for 2-arm case)

RL: 20 confirm/dismiss cycles on 5 findings
  → confirmed findings rank higher (assert NDCG > random baseline)

RL: batch eval triggers auto-promote when NDCG@10 improves >0.02

CLASSIFY: s3-public-acl → PlaybookClass::Reversible
CLASSIFY: k8s-privileged-pod → PlaybookClass::Destructive
CLASSIFY: enable-cloudtrail → PlaybookClass::Safe

SAFE: execute() ok → audit_log row written (action + before + after)
SAFE: audit_log UPDATE attempt → Err(permission denied), no panic

REVERSIBLE: mock execute() returns Err
  → rollback() called → final state == snapshot (mock backend verified)

DESTRUCTIVE: no approval within 5s test timeout
  → state=Aborted, CloudBackend::execute NEVER called

DESTRUCTIVE: approval received within 5s
  → state=Completed, execute called once, audit_log written

CIRCUIT: 3 errors same class within 60s → class halted, CriticalAlert on bus

INFRA: just heal-dry aws-123 exits 0, outputs plan JSON (no mutations)
QUALITY: cargo test -p secureops-{rl,selfheal} green (all via mock backends)
```

### P7 Exit Criteria
- [ ] RL rankings measurably improve after 50 feedback events
- [ ] Reversible playbook auto-rolls back on failure
- [ ] Destructive playbook never executes without explicit approval

---

## P8 - Enterprise (React Dashboard + SSO + License UI + Audit Export)
*First visual user-facing layer · ~245 tokens build · ~150 tokens test*

### P8 BUILD

```
PHASE P8 - Enterprise (React Dashboard + SSO + License UI)
PRIOR STATE: All backend live (P5-P7). No web UI, no SSO, no signed export.

DELIVER:
1. React SPA (TypeScript, Vite, Tailwind, shadcn/ui):
   Embed as static in secureops-api via tower-http::ServeDir + SPA fallback

   First-run wizard (server-enforced redirect, cannot skip):
   /license      → POST /license/activate → show tier/expiry/features
   /setup/llm-keys → provider select → key entry → test-call button
   /setup/cloud  → AWS|GCP|Azure → emit IaC/CLI snippet → paste ARN → test
   /setup/scan   → one-click → POST /scans → WS progress bar

   Dashboard screens:
   /findings     - RL-ranked, filter(severity/cloud/status), CVSS badges
   /compliance   - framework heatmap, gap %, export PDF/CSV button
   /graph        - D3 force-directed; click→blast-radius; "explain path"
   /remediation  - HITL queue; diff preview; approve/deny; countdown timer
   /usage        - tokens in/out per provider; cost estimate chart
   /license      - status badge; expiry; tier; features list; renewal link
   /profile      - RBAC roles; API keys; notification settings

2. SAML/OIDC SSO (Enterprise, cedar gate: features contains "sso"):
   axum-oidc OR custom SAML2 SP. IdPs: Okta, Azure AD, Google.
   GET /auth/oidc/metadata
   GET /auth/oidc/callback → issue session JWT

3. Compliance export:
   PDF: headless rendering via subprocess (weasyprint or wkhtmltopdf)
   CSV: serde_csv serialization of findings+control_mappings
   Signed IR ZIP: evidence + audit_log segment + policy_version +
     Ed25519 signature of ZIP contents (verifiable with embedded vendor pubkey)
   GET /compliance/reports?framework=cis|soc2|pci&format=pdf|csv|zip

4. License server (tools/license-server/):
   Stateless Rust binary. Single VPS deployable.
   POST /heartbeat {lic_id, instance_fingerprint, version} → {status, expiry}
   POST /revoke    {lic_id, reason} (admin-key auth, 401 otherwise)
   No DB; validates Ed25519 signature + in-memory revocation list

5. Federated IOC (Enterprise, features contains "threat_intel"):
   Pull schedule (default 6h). minisign verify BEFORE parse.
   Version monotonicity: reject if feed_version <= current.
   Merge: global baseline + local overlay (local wins conflicts).

6. Justfile: upgrade (Helm rolling OR compose pull+migrate+up),
   zero-downtime: health-check poll during restart, abort on 5xx

OUTPUT:
  web/src/{App,components,pages}/**/*.tsx
  secureops-api/src/{sso,export,ioc_feed}.rs
  tools/license-server/src/main.rs + Dockerfile (<10MB image)
  Helm SSO config, Justfile upgrade recipe
```

### P8 TEST

```
P8 TEST VALIDATION - assert each:

UI: GET / with no activated license → HTTP 302 → /license (server-enforced)
UI: POST /license/activate success → wizard step 1→2 (Playwright E2E)
UI: full 4-step wizard completes, dashboard visible (Playwright)

SSO: mock IdP OIDC callback → JWT issued → GET /findings 200 (not 401)
SSO: Community license → GET /auth/oidc/metadata → 403 (Cedar gate)
SSO: Pro license without sso feature → 403 (same gate)

EXPORT: GET /compliance/reports?framework=cis&format=pdf
  → 200, Content-Type: application/pdf (non-zero bytes)
EXPORT: IR zip Ed25519 signature verifies with embedded vendor pubkey

LICENSE-SVC: POST /heartbeat valid lic_id → 200 {status:"active"} <50ms
LICENSE-SVC: POST /heartbeat revoked lic_id → 200 {status:"revoked"}
LICENSE-SVC: POST /revoke without admin key → 401

IOC: valid minisign sig + newer version → applied, indicator count increases
IOC: invalid minisign sig → rejected, count unchanged
IOC: version <= current → rejected (monotonicity), count unchanged

UPGRADE: just upgrade during k6 30s load (100 req/s /findings)
  → zero HTTP 5xx during rolling restart

QUALITY: cargo test -p secureops-api --features sso,export green
QUALITY: npx vitest run green; npx playwright test green
```

### P8 Exit Criteria
- [ ] First-run wizard flows end-to-end in Playwright E2E test
- [ ] SSO login works with mock IdP
- [ ] `just upgrade` produces zero 5xx in k6 load test

---

## P9 - Hardening & GA (Supply Chain + Chaos + Pen-Test + Docs)
*Ships GA-ready product · ~200 tokens build · ~145 tokens test*

### P9 BUILD

```
PHASE P9 - Hardening & GA
PRIOR STATE: All features live (P0-P8). No supply-chain attestation,
  chaos tests, or docs site.

DELIVER:
1. Supply-chain hardening:
   cargo-auditable: embed dep graph in every binary
   cargo-deny: policy.lock (license allowlist + ban list + RustSec check)
   cargo-vet: trust ledger (cargo vet init)
   CycloneDX SBOM: cargo-cyclonedx per binary per release
   cosign sign: every Docker image + SLSA-Level-2 provenance (keyless, sigstore)
   .github/workflows/release.yml:
     build→test→audit→sbom→docker-build→cosign-sign→publish ghcr.io

2. Chaos test suite (crates/chaos/src/lib.rs):
   Postgres down → GET /health returns 503 + Retry-After (no panic)
   Redis down → scan job → degrade to direct-call (log warning, no crash)
   LLM 429 × 3 → exponential backoff (2^n + jitter) → fallback provider → completes
   LLM 500 → retry 3x → job state=Failed (error details, no panic)
   License API unreachable → grace period activates, features still available
   MinIO down → evidence upload: log warning, finding still written to Postgres

3. Performance benchmarks (criterion crate, crates/bench/):
   Target: 10,000 assets scanned < 5 minutes (scanner-workers=4)
   Target: graph BFS p95 < 200ms on 10,000-node graph
   Target: TokenBudget compression > 40% token reduction (20 real IAM policies)
   Target: GET /findings p99 < 100ms at 200 req/s
   CI: cargo bench; fail if any target regresses > 10%

4. Upgrade runbook (automated):
   Helm pre-upgrade hook: db-migrate-job; fail install if migration fails
   Auto-rollback: helm rollback if post-upgrade healthcheck fails within 120s
   just upgrade: pull→migrate→rolling-restart→health-poll→abort-on-5xx

5. Documentation (mkdocs-material):
   architecture.md, api.md (from utoipa), deploy-aws.md, deploy-gcp.md,
   deploy-azure.md, playbooks.md, rl-feedback.md, license.md

6. Security pen-test checklist:
   SQLi: no format! in SQL; all sqlx calls parameterized
   SSRF: outbound allowlist (cloud APIs + LLM APIs + license svc only)
   JWT: alg=none → 401; wrong key → 401
   Secrets in logs: grep tracing! → no password|secret|api_key|token matches
   Container escape: cap audit (no CAP_SYS_ADMIN except bpf-agent DaemonSet)
   Path traversal: /evidence/../../../etc/passwd → 400

7. Reproducible builds:
   SOURCE_DATE_EPOCH pinned, --locked, cross for musl static targets
   sha256sum manifest + cosign bundle per GitHub release

OUTPUT:
  .github/workflows/{release,bench,chaos}.yml
  crates/{chaos,bench}/src/lib.rs
  docs/ (complete mkdocs site)
  SECURITY.md + pen-test-checklist.md
  Justfile (final, every recipe documented, just --list clean)
```

### P9 TEST

```
P9 TEST VALIDATION - assert each:

SUPPLY: cargo deny check exits 0 (no banned licenses, no RustSec advisories)
SUPPLY: cargo audit exits 0 (no known vulnerabilities)
SUPPLY: cosign verify ghcr.io/org/secureops-api:latest → "Verified OK"
SUPPLY: CycloneDX SBOM parses; contains all 16 workspace crates + transitive

CHAOS: Postgres stopped → GET /health returns 503 + Retry-After (no panic, no 500)
CHAOS: Redis stopped → scan job completes in degraded mode (warning logged)
CHAOS: LLM 429 × 3 → backoff → fallback provider → bug-hunt completes
CHAOS: license-api unreachable → grace period active, GET /license shows warning

PERF: cargo bench scan_10k_assets < 300s wall clock (5 min)
PERF: cargo bench graph_bfs_10k: p95 < 200ms
PERF: cargo bench tokenbudget: compression ratio > 0.40
PERF: k6 load 200 req/s GET /findings for 30s: p99 < 100ms

SECURITY: POST /findings?filter=%27+OR+1%3D1-- → 400 (not executed in DB)
SECURITY: JWT {alg:"none", sub:"admin"} → 401
SECURITY: GET /evidence/../../../etc/passwd → 400 (path traversal blocked)
SECURITY: grep tracing! in all crate sources → zero matches for secret|password|api_key

UPGRADE: bad migration SQL → helm hook fails → old version stays up (no downtime)
UPGRADE: just upgrade during k6 100 req/s → zero 5xx during rolling restart

DOCS: mkdocs build exits 0 (no broken links, all pages render)
FINAL: just --list → all recipes listed with descriptions, exits 0
```

### P9 Exit Criteria
- [ ] `cargo deny check` and `cargo audit` both green
- [ ] cosign verification passes on published image
- [ ] All performance benchmarks within targets
- [ ] Zero 5xx during `just upgrade` load test

---

## Quick Reference

| Phase | What it builds | Key test gate |
|-------|---------------|---------------|
| P4 eBPF | Kernel exfil-chain detection + deny | ExfilChain mock test green |
| P5 Platform | HTTP API + Postgres + Redis + Docker/Helm | `just up` all services healthy |
| P6 Intel | Knowledge graph + LLM bug-hunt + TokenBudget | BFS <200ms, compression >40% |
| P7 Autonomy | RL ranking + cloud self-healing playbooks | Reversible auto-rollback on failure |
| P8 Enterprise | React dashboard + SSO + license UI + IR export | Playwright E2E wizard passes |
| P9 GA | Supply chain + chaos + perf + pen-test + docs | cosign verified, zero 5xx upgrade |

## Sequencing rule
P4 → P5 → P6 → P7 → P8 → P9.
Do NOT begin P7 (cloud mutation) until P5 (storage/API) and P6 (graph) are fully tested.
Do NOT begin P8 (enterprise) until P7 playbooks have been validated in staging.

---
*Generated for SecureOps BYOI Security Platform · Build target: Claude Opus 4.8 · Rust 1.84+*

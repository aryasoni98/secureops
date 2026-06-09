<div align="center">

# SecureOps

**Out-of-band security for AI agents — audit, harden, and enforce from outside the agent process.**

[![CI](https://github.com/aryasoni98/secureops/actions/workflows/ci.yml/badge.svg)](https://github.com/aryasoni98/secureops/actions/workflows/ci.yml)
[![Supply chain](https://github.com/aryasoni98/secureops/actions/workflows/supply-chain.yml/badge.svg)](https://github.com/aryasoni98/secureops/actions/workflows/supply-chain.yml)
[![crates.io](https://img.shields.io/crates/v/secureops-cli.svg?logo=rust)](https://crates.io/crates/secureops-cli)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg?logo=rust)](https://www.rust-lang.org)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS-informational)](#install)

[Install](#install) · [Quick start](#quick-start) · [Architecture](#architecture) · [CLI](#cli-reference) · [Platform API](#platform-api) · [Configuration](#configuration) · [Contributing](#contributing)

</div>

---

## Overview

AI agents read secrets, call tools, and reach the network. When an agent is compromised, **in-process guardrails can be switched off by the attacker.** SecureOps moves the enforcement boundary **outside the agent process** — into a privileged daemon that keeps working even after the agent is owned.

SecureOps is a **Rust workspace** (v0.0.1 beta) that ports the [`@adversa/secureops`](https://www.npmjs.com/package/@adversa/secureops) TypeScript tool (v2.2.0 reference) while adding a three-trust-ring / PDP–PEP architecture described in [PRODUCT.md](PRODUCT.md).

### What problem it solves

| Problem | SecureOps response |
|---------|-------------------|
| Misconfigured gateways, credentials, and execution policies | OWASP-ASI–mapped audit with 0–100 score and CI gate |
| Drift after deployment | Hardening with timestamped backups and rollback |
| Exfiltration after compromise | Fail-closed egress proxy (HTTPS allowlist, `403`, 0 bytes on deny) |
| Runtime abuse (cost, credentials, skills) | Four runtime monitors + circuit breaker + kill switch |
| No audit trail | Hash-chained, Ed25519-signed JSONL audit log |
| Multi-tenant operations (enterprise) | Self-hosted platform API, license server, and dashboard scaffold |

### Target users

- **Platform / security engineers** running OpenClaw-style AI agent deployments
- **DevSecOps teams** gating CI/CD with `secureops audit --json`
- **Operators** who need out-of-band egress control via `HTTPS_PROXY`
- **Enterprise adopters** evaluating the self-hosted platform tier (API + Postgres + Redis)

### Product tiers (as implemented)

| Tier | Components | Maturity |
|------|------------|----------|
| **Host-local** | `secureops` CLI + `secureops-daemon` | Beta-ready — tested in CI on Linux and macOS |
| **Platform** | `secureops-api`, Postgres, Redis, MinIO, `web/` dashboard | MVP code + compose/Helm manifests; scanner worker and live cloud collectors incomplete |
| **Enterprise add-ons** | License server, SSO hooks, Neo4j/bpf-agent Helm subcharts | Partially implemented; subcharts disabled by default |

> [!NOTE]
> **Beta (`v0.0.1`).** Audit, harden, egress enforcement, monitors, kill switch, and audit-log primitives are live and covered by **272 workspace tests** (6 Postgres integration tests ignored without `DATABASE_URL`). Kernel eBPF enforce mode, TPM signing, full Rego/Cedar PDP wiring in the daemon, N-API Node packaging, and the platform scanner worker are **in progress** — see [Project status](#project-status).

---

## Features

### Host-local (Ring 0–2)

| Feature | Purpose | How it works | Key crates |
|---------|---------|--------------|------------|
| **Security audit** | Baseline posture assessment | Nine OWASP-ASI categories, 56 `SC-*` checks, MAESTRO cross-layer risk, 0–100 score | `secureops-checks`, `secureops-core` |
| **CI gate** | Fail pipelines below threshold | `secureops audit --json` exits `2` when score &lt; 80 | `secureops-cli` |
| **Hardening** | Auto-fix safe misconfigurations | Gateway, credentials, config, Docker, network modules with rollback | `secureops-harden` |
| **Egress enforcement** | Block unauthorized outbound traffic | HTTP `CONNECT` allowlist proxy on `127.0.0.1:8889`, fail-closed | `secureops-proxy`, `secureops-daemon` |
| **Runtime monitors** | Detect live abuse | Cost circuit-breaker, credential access, memory integrity, skill IOC scan | `secureops-monitors` |
| **Kill switch** | Emergency stop | Refuses daemon start; halts enforcement when active | `secureops-fs` |
| **Tamper-evident log** | Prove what happened | SHA-256 hash chain + Ed25519 signatures in `.secureops/audit.jsonl` | `secureops-auditlog` |
| **Policy engine** | Central allow/deny | Rego (regorus), Cedar, allowlist engine, decision cache | `secureops-policy` |
| **WASM sandbox** | Execution PEP (library) | wasmtime host with fuel/epoch caps | `secureops-sandbox` |
| **Kernel PEP** | Syscall correlation | eBPF chain correlator + seccomp profile generation (feature-gated) | `secureops-bpf`, `ebpf/` |

### Platform & intelligence (Phases 5–8)

| Feature | Purpose | Status |
|---------|---------|--------|
| **Platform API** | Multi-tenant REST + WebSocket hub | Implemented — Axum routes, Cedar authz, in-memory or Postgres store |
| **License activation** | Ed25519-signed keys → session JWT | Implemented |
| **Findings & scans** | Queue scans, list/action findings, RL ranking | Implemented — Redis enqueue degrades gracefully without worker |
| **Bug hunt** | Bounded LLM agentic loop | Implemented with `LocalProvider` mock; live LLM providers feature-gated |
| **Security graph** | Attack paths, blast radius | In-memory engine; Neo4j subchart optional, not validated |
| **Self-heal** | YAML playbooks with HITL | Implemented — defaults to `NoopCloud` (no real mutations) |
| **RL ranker** | LinUCB finding prioritization | Implemented |
| **Token budget** | Evidence packing for LLM context | Library crate with benchmarks |
| **License server** | Heartbeat + revoke | Stateless Axum service on `:8090` |
| **Dashboard** | Web UI for findings/graph/remediation | React/Vite — built + vitest + Playwright E2E run in CI |
| **Scanner worker** | BRPOP scan jobs → persist findings | `secureops-scanner` binary; wired into platform compose |
| **Cloud self-heal** | Live AWS/GCP/Azure mutation backends | `aws::AwsCloud` real SDK (gated `aws`); GCP/Azure dry impls |
| **Chaos suite** | Degraded-mode integration tests | `secureops-chaos` (DB-down → 503, Redis-absent degraded) |
| **Benchmarks** | criterion perf gates | `secureops-bench` (graph BFS, tokenbudget pack, RL ranking) |

Items requiring external infrastructure (real eBPF kernel load, TPM hardware,
sigstore keyless creds, live cloud accounts, live OIDC IdP) are listed in
[`DEFERRED.md`](DEFERRED.md) with the trait seam each one plugs into.

---

## Architecture

The agent (**Ring 0**) is assumed hostile. Audit/monitor logic (**Ring 1**) runs in-process and can be bypassed once the agent is owned. The **Ring 2** daemon runs as a separate process and remains the root of trust for egress, monitors, and the persisted audit log.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#334155', 'clusterBkg': '#F8FAFC', 'titleColor': '#1A1A1A', 'clusterTextColor': '#1A1A1A', 'textColor': '#1A1A1A', 'edgeLabelBackground': '#FFFFFF'}}}%%
flowchart TB
  subgraph R0["Ring 0 — Untrusted"]
    AGENT[AI agent / LLM]
    SKILLS[Skills & plugins]
    SECRETS[.env · credentials]
  end

  subgraph R1["Ring 1 — Degraded trust (in-process)"]
    direction LR
    NAPI[N-API seam secureops-napi]
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
    DAEMON --> PEP1 & PEP2
    DAEMON --> LOG
    PEP1 -.->|"today: AllowlistPdp"| PDP
  end

  subgraph PLATFORM["Platform tier (optional)"]
    API[secureops-api]
    PG[(Postgres)]
    REDIS[(Redis)]
    S3[(MinIO / S3)]
    API --> PG & REDIS & S3
  end

  R0 -->|"same process; dies with agent"| R1
  R1 -.->|"unix socket JSON-RPC"| R2
  R0 -->|"HTTPS_PROXY / syscalls"| PEP1 & PEP2
  CLI -.->|"operators"| API

  classDef ring0 fill:#D64545,stroke:#9B2E2E,color:#FFFFFF,stroke-width:2px
  classDef ring1 fill:#F4A832,stroke:#C4841A,color:#1A1A1A,stroke-width:2px
  classDef ring2 fill:#248358,stroke:#186B44,color:#FFFFFF,stroke-width:2px
  classDef platform fill:#2563EB,stroke:#1D4ED8,color:#FFFFFF,stroke-width:2px

  class AGENT,SKILLS,SECRETS ring0
  class NAPI,CLI,CHECKS ring1
  class DAEMON,PDP,PEP1,PEP2,PEP3,LOG ring2
  class API,PG,REDIS,S3 platform

  style R0 fill:#D64545,stroke:#9B2E2E,color:#FFFFFF
  style R1 fill:#F4A832,stroke:#C4841A,color:#1A1A1A
  style R2 fill:#248358,stroke:#186B44,color:#FFFFFF
  style PLATFORM fill:#E0E7FF,stroke:#2563EB,color:#1A1A1A
```

| Ring | Runs where | Trust | If the agent is owned |
|------|------------|-------|-----------------------|
| **0** | Agent process | None | Attacker controls everything here |
| **1** | Agent process (N-API) or operator CLI | Low | Audit/monitor can be bypassed |
| **2** | `secureops-daemon` (privileged, separate) | High | Egress proxy and audit log still apply |

### Egress decision flow

```mermaid
sequenceDiagram
  participant A as Agent
  participant P as Egress proxy :8889
  participant PDP as Allowlist PDP
  participant U as Internet

  A->>P: CONNECT api.evil.com
  P->>PDP: Host in allowlist?
  alt deny or PDP error
    PDP-->>P: Deny
    P-->>A: 403 — 0 bytes to upstream
  else allow
    PDP-->>P: Allow
    P->>U: Tunnel
  end
  Note over P: Per-decision audit append — TODO in daemon
```

### Platform data flow

```mermaid
flowchart LR
  OP[Operator / Dashboard] -->|JWT or API key| API[secureops-api]
  API -->|persist| PG[(Postgres)]
  API -->|enqueue scan| REDIS[(Redis)]
  API -->|presign evidence| S3[(MinIO)]
  WORKER[Scanner worker] -.->|"placeholder"| REDIS
  API -->|WebSocket events| OP
```

> Deep architecture, deployment topology, and design proposals: **[PRODUCT.md](PRODUCT.md)** · operational runbooks: **[docs/RUNNING.md](docs/RUNNING.md)** · AWS/K8s walkthrough: **[docs/DEPLOY_AWS_K8S.md](docs/DEPLOY_AWS_K8S.md)**

---

## Tech stack

| Layer | Technologies |
|-------|--------------|
| **Language** | Rust 2021 edition, MSRV 1.80 |
| **Async runtime** | Tokio |
| **CLI** | clap 4 |
| **HTTP API** | axum, tower-http, utoipa (OpenAPI) |
| **Auth** | jsonwebtoken (HS256), Ed25519 license keys, Cedar policy engine |
| **Policy** | regorus (Rego), cedar-policy |
| **Proxy** | hyper (HTTP CONNECT), hickory-proto (DNS sinkhole) |
| **Sandbox** | wasmtime 27 + WASI preview1 |
| **Kernel** | aya (Linux eBPF, feature-gated) |
| **Crypto** | argon2, aes-gcm, ed25519-dalek, keyring, tss-esapi (TPM, optional) |
| **Monitors** | SQLite (alerts), tokio tasks |
| **Database** | PostgreSQL 16 (platform), sqlx migrations |
| **Queue / cache** | Redis 7 |
| **Object storage** | MinIO / S3-compatible (evidence presigning) |
| **Observability** | tracing, OpenTelemetry collector (compose/Helm) |
| **Frontend** | React 18, Vite 5, TypeScript (dashboard scaffold) |
| **Containers** | Docker multi-stage (debian:bookworm-slim), tini |
| **Orchestration** | Docker Compose, Kustomize (`deploy/k8s/`), Helm (`deploy/helm/`) |
| **CI/CD** | GitHub Actions — build/test/clippy/fmt, crates.io publish on tag, release binaries, supply-chain (cargo-deny, RustSec, CycloneDX SBOM) |
| **Local automation** | [just](https://github.com/casey/just) (`Justfile`) |

---

## Project structure

```text
secureops/
├── Cargo.toml              # Workspace manifest (23 member crates)
├── Justfile                # Local dev, Docker, K8s, platform recipes
├── PRODUCT.md              # Deep architecture & design extension
├── CHANGELOG.md            # Release notes
├── SECURITY.md             # Vulnerability reporting + pen-test checklist
├── deny.toml               # cargo-deny policy
├── mkdocs.yml              # Documentation site config
├── crates/
│   ├── secureops-core/     # Types, Check trait, scoring (no I/O)
│   ├── secureops-checks/   # Nine audit categories (56 SC-* checks)
│   ├── secureops-fs/       # AuditContext, kill switch, behavioral baseline
│   ├── secureops-intel/    # IOC feed, typosquat, tree-sitter scan
│   ├── secureops-crypto/   # Keystore, signing (keychain / TPM optional)
│   ├── secureops-harden/   # Hardening + rollback
│   ├── secureops-monitors/ # Runtime monitors + AlertBus + SQLite
│   ├── secureops-cli/      # `secureops` binary
│   ├── secureops-napi/     # Node native addon seam (FFI, not full napi release)
│   ├── secureops-ipc/      # Unix JSON-RPC + SO_PEERCRED
│   ├── secureops-policy/   # PDP: Rego, Cedar, allowlist
│   ├── secureops-proxy/    # Egress PEP + DNS sinkhole
│   ├── secureops-bpf/      # Kernel PEP + exfil-chain correlator
│   ├── secureops-sandbox/  # WASM execution PEP
│   ├── secureops-auditlog/ # Hash chain + Ed25519 JSONL
│   ├── secureops-daemon/   # Ring-2 supervisor binary
│   ├── secureops-api/      # Platform HTTP API + migrations
│   ├── secureops-license-server/  # License heartbeat/revoke server
│   ├── secureops-tokenbudget/     # LLM evidence packing
│   ├── secureops-graph/           # Attack-path graph engine
│   ├── secureops-bughunt/           # Agentic bug-hunt loop
│   ├── secureops-rl/                # LinUCB finding ranker
│   └── secureops-selfheal/          # Self-healing playbooks
├── ebpf/                   # Kernel eBPF programs (Linux, separate build)
├── web/                    # React dashboard scaffold
├── deploy/
│   ├── docker/             # Dockerfile, compose (daemon + platform)
│   ├── k8s/                # Kustomize — host-local daemon + audit cronjob
│   └── helm/               # Platform API chart + bpf-agent / neo4j subcharts
├── docs/                   # RUNNING, DEPLOY_AWS_K8S, architecture notes
├── scripts/release.sh      # Version bump + tag helper
└── .github/workflows/      # ci.yml, release.yml, supply-chain.yml
```

---

## Install

### Prebuilt binaries (GitHub Releases)

Download a release archive for your platform from **[Releases](https://github.com/aryasoni98/secureops/releases)**. Archives include four binaries:

| Binary | Role |
|--------|------|
| `secureops-cli` | Operator CLI (`secureops`) |
| `secureops-daemon` | Ring-2 enforcement daemon |
| `secureops-api` | Platform HTTP API |
| `secureops-license-server` | License heartbeat/revoke server |

```sh
# linux-x86_64 · linux-arm64 · macos-x86_64 · macos-arm64
TAG=v0.0.1
curl -L "https://github.com/aryasoni98/secureops/releases/download/${TAG}/secureops-${TAG}-linux-x86_64.tar.gz" | tar xz
sudo mv secureops-cli /usr/local/bin/secureops
sudo mv secureops-daemon /usr/local/bin/secureops-daemon
secureops --help
```

### From crates.io

```sh
cargo install secureops-cli
cargo install secureops-daemon
cargo install secureops-api
cargo install secureops-license-server
```

### From source

```sh
git clone https://github.com/aryasoni98/secureops.git
cd secureops
cargo build --release -p secureops-cli -p secureops-daemon -p secureops-api -p secureops-license-server
```

### As a library

Depend on individual workspace crates (23 published on tag push). Example:

```toml
[dependencies]
secureops-core = "0.0.1"
secureops-checks = "0.0.1"
```

### Container / Kubernetes

| Deployment | Manifest | Default entrypoint |
|------------|----------|-------------------|
| Host-local daemon | `deploy/docker/docker-compose.yml` | `secureops-daemon` |
| Platform stack | `deploy/docker/docker-compose.platform.yml` | `secureops-api` |
| K8s (daemon) | `deploy/k8s/` (Kustomize) | `secureops-daemon` |
| K8s/Helm (platform) | `deploy/helm/` | `secureops-api` |

Build the image from the repo root:

```sh
docker build -f deploy/docker/Dockerfile -t secureops-rust:latest .
```

> The Docker image builds `secureops`, `secureops-daemon`, and `secureops-api` only. Run `secureops-license-server` from a release binary or extend the Dockerfile if needed.

---

## Quick start

### Host-local

```sh
export OPENCLAW_STATE_DIR=~/.openclaw

secureops init
secureops audit
secureops audit --json          # CI gate: exits 2 if score < 80
secureops harden
secureops status
```

Enable **egress enforcement**:

```sh
# 1. Configure allowlist in $OPENCLAW_STATE_DIR/openclaw.json (see Configuration)
# 2. Start the daemon (binds 127.0.0.1:8889 when allowlist enabled)
secureops-daemon
# 3. Point the agent at the proxy
export HTTPS_PROXY=http://127.0.0.1:8889
```

### One-command bootstrap (contributors)

Requires [`just`](https://github.com/casey/just):

```sh
just setup      # check deps → build → test → init demo state
just --list     # audit, harden, daemon, docker-*, k8s-*, platform-*
```

### Platform API (local, in-memory store)

```sh
SECUREOPS_API_ADDR=127.0.0.1:8080 cargo run -p secureops-api
curl -s http://127.0.0.1:8080/livez
```

Full stack with Postgres, Redis, and MinIO:

```sh
cp deploy/docker/.env.example deploy/docker/.env   # edit secrets
just platform-up
```

---

## Configuration

### OpenClaw state directory

State lives under `$OPENCLAW_STATE_DIR` (default `~/.openclaw`).

| Path | Purpose |
|------|---------|
| `openclaw.json` | Agent + SecureOps configuration |
| `.secureops/` | Keystore, kill-switch file, audit log, behavioral baseline |

Egress enforcement reads `openclaw.json`:

```json
{
  "secureops": {
    "network": {
      "egressAllowlistEnabled": true,
      "egressAllowlist": ["api.anthropic.com", "api.openai.com"]
    }
  }
}
```

### Environment variables

| Variable | Required | Default | Used by | Description |
|----------|----------|---------|---------|-------------|
| `OPENCLAW_STATE_DIR` | No | `~/.openclaw` | CLI, daemon, containers | State root for config, keystore, audit log |
| `HTTPS_PROXY` | No | — | Agent runtime | Point agent HTTPS traffic at `http://127.0.0.1:8889` |
| `SECUREOPS_BPF_OBJ` | No | unset | `secureops-bpf`, daemon | Path to compiled eBPF object (Linux) |
| `SECUREOPS_BPF_ENFORCE` | No | unset | daemon | Set to `1` for enforce mode (Linux+eBPF only; else observe) |
| `SECUREOPS_IOC_FEED_PUBKEY` | No | unset | `secureops-intel` | Ed25519 public key for signed IOC feed verification |
| `SECUREOPS_API_ADDR` | No | `0.0.0.0:8080` | `secureops-api` | API listen address |
| `SECUREOPS_JWT_SECRET` | **Yes (prod)** | `dev-insecure-secret` | `secureops-api` | HMAC secret for session JWTs |
| `SECUREOPS_LICENSE_PUBKEY` | **Yes (prod)** | dev key (`[7u8;32]`) | API, license server | Base64url 32-byte Ed25519 vendor public key |
| `DATABASE_URL` | No | unset → in-memory | `secureops-api` | Postgres DSN; migrations run on boot |
| `REDIS_URL` | No | unset | `secureops-api` | Redis for scan queue (degraded if unreachable) |
| `MINIO_ROOT_USER` | No | unset | `secureops-api` | S3 access key for evidence presigner |
| `MINIO_ROOT_PASSWORD` | No | unset | `secureops-api` | S3 secret key for evidence presigner |
| `S3_ENDPOINT` | No | `minio:9000` | `secureops-api` | S3-compatible host |
| `AWS_REGION` | No | `us-east-1` | `secureops-api` | SigV4 region for presigning |
| `S3_SCHEME` | No | `http` | `secureops-api` | `http` or `https` for presigned URLs |
| `SECUREOPS_WEB_DIR` | No | unset | `secureops-api` | Path to built dashboard (`web/dist`) for SPA fallback |
| `SECUREOPS_LICENSE_ADDR` | No | `0.0.0.0:8090` | license server | License server listen address |
| `SECUREOPS_ADMIN_KEY` | **Yes (prod)** | `dev-admin-key` | license server | Bearer token for `/revoke` |
| `RUST_LOG` / `tracing` | No | `info` | all binaries | Log filter via `tracing-subscriber` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | unset | platform compose | OpenTelemetry collector endpoint |
| `POSTGRES_USER` | Yes (compose) | — | `docker-compose.platform.yml` | Postgres user |
| `POSTGRES_PASSWORD` | Yes (compose) | — | platform compose | Postgres password |
| `POSTGRES_DB` | Yes (compose) | — | platform compose | Postgres database name |
| `SECUREOPS_NETWORK_MODE` | No | `bridge` | `docker-compose.yml` | Set to `host` on Linux EC2 for egress PEP |

Platform secrets template: [`deploy/docker/.env.example`](deploy/docker/.env.example).

---

## Development

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Rust | ≥ 1.80 | `rust-version` in workspace `Cargo.toml` |
| Node.js | ≥ 18 (22 in CI) | Required for `secureops-napi` build (`napi-build`) |
| just | latest | Optional but recommended |
| Docker | latest | For compose workflows |
| sqlx-cli | latest | For `just db-migrate` against Postgres |

### Build and test

```sh
cargo build --workspace
cargo test --workspace          # 272 passed; 6 ignored without DATABASE_URL
just ci                         # fmt-check + clippy -D warnings + test
```

### Formatting and linting

```sh
cargo fmt --all
cargo clippy --workspace -- -D warnings
```

### Optional Linux enforcement features

```sh
cargo build -p secureops-bpf --features ebpf        # needs aya / bpf-linker toolchain
cargo build -p secureops-sandbox --features seccomp
cargo build -p secureops-crypto --features tpm      # needs libtss2-dev
just bpf-build                                      # eBPF object in ebpf/
```

### Frontend (dashboard scaffold)

```sh
just web-dev      # Vite dev server, proxies to API
just web-build    # emits web/dist
```

> `web/` has no lockfile and is **not** built in CI. See [Project status](#project-status).

### Database migrations

Migrations live in `crates/secureops-api/migrations/` and run automatically when `DATABASE_URL` is set:

```sh
export DATABASE_URL=postgres://secureops_app:password@localhost:5432/secureops
just db-migrate
```

| Migration | Tables / purpose |
|-----------|------------------|
| `001_licenses.sql` | `licenses`, `api_keys` |
| `002_clouds.sql` | Cloud account linkage |
| `003_assets_identities.sql` | Assets and identities for graph |
| `004_findings.sql` | `scans`, `findings` |
| `005_remediations_feedback.sql` | Remediations + RL feedback |
| `006_usage_audit.sql` | Append-only usage audit (tamper resistance) |

Live Postgres integration tests:

```sh
DATABASE_URL=postgres://... cargo test -p secureops-api -- --ignored
```

---

## CLI reference

```
secureops <COMMAND>
```

| Command | What it does |
|---------|--------------|
| `init` | Scaffold `.secureops/` state dir + Argon2id keystore |
| `audit` | Run audit; `--deep` for port probes; `--json` for CI gate |
| `harden` | Apply auto-fixable remediations; `--full` for all; `--rollback <id>` |
| `status` | Score, kill-switch state, monitor toggles |
| `monitor` | Start runtime monitors (Ctrl-C to stop) |
| `behavioral` | Rolling tool-call baseline stats (`--window 60`) |
| `kill` | Emergency stop; `--deactivate` to resume; `--reason <text>` |
| `export-incident` | Bundle audit + findings into portable incident report |

`secureops-daemon` runs the Ring-2 loop: kill-switch check → monitors → optional egress proxy → kernel correlator.

---

## Platform API

Base URL: `http://<host>:8080` (default). OpenAPI: `GET /api/v1/openapi.json`.

### Authentication

| Method | Header | Notes |
|--------|--------|-------|
| Session JWT | `Authorization: Bearer <token>` | Minted by `POST /api/v1/license/activate`; HS256 only |
| API key | `X-API-Key: <key>` | Stored as SHA-256 hash in Postgres |

Tier-locked routes additionally require Cedar feature flags on the JWT claims (e.g. `scans`, `findings`, `compliance`, `sso`, `bughunt`).

### Health

| Endpoint | Auth | Response |
|----------|------|----------|
| `GET /livez` | None | `200` — process alive |
| `GET /readyz` | None | `200` if store healthy, else `503` + `Retry-After` |

### REST endpoints (`/api/v1`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/license/activate` | None | Verify Ed25519 license key; returns JWT |
| `GET` | `/license` | JWT/API key | Active license for tenant |
| `POST` | `/scans` | JWT + `scans` | Queue a scan job |
| `GET` | `/scans/{id}` | JWT | Scan status (tenant-scoped) |
| `GET` | `/findings` | JWT + `findings` | List findings (RL-ranked) |
| `POST` | `/findings/{id}/action` | JWT | `confirm` / `dismiss` / `escalate` |
| `GET` | `/compliance/reports` | JWT + `compliance` | `?framework=cis\|soc2\|pci&format=json\|csv\|zip` |
| `POST` | `/bughunt` | JWT + `bughunt` | Queue bounded LLM bug hunt |
| `GET` | `/bughunt/{job_id}` | JWT | Bug-hunt job status |
| `POST` | `/graph/rebuild` | JWT | Rebuild in-memory security graph |
| `GET` | `/graph/paths` | JWT | Internet→sensitive attack paths |
| `GET` | `/graph/blast-radius/{node}` | JWT | Blast radius for a node |
| `POST` | `/rl/feedback` | JWT | Submit ranking feedback |
| `GET` | `/rl/stats` | JWT | LinUCB model stats |
| `POST` | `/remediations` | JWT | Create remediation plan |
| `GET` | `/remediations/queue` | JWT | HITL approval queue |
| `POST` | `/remediations/{id}/approve` | JWT | Approve (uses `NoopCloud` by default) |
| `POST` | `/remediations/{id}/deny` | JWT | Deny remediation |
| `GET` | `/auth/oidc/metadata` | JWT + `sso` | OIDC SP metadata |
| `POST` | `/auth/oidc/callback` | None | Exchange IdP token for session JWT |
| `GET` | `/openapi.json` | None | OpenAPI 3 document |

### WebSocket

| Path | Events |
|------|--------|
| `/ws/findings` | `finding.action`, etc. |
| `/ws/scan-progress` | `scan.queued`, progress updates |
| `/ws/remediation` | Remediation queue updates |

### Example: activate license and queue a scan

```sh
# Activate
curl -s -X POST http://127.0.0.1:8080/api/v1/license/activate \
  -H 'Content-Type: application/json' \
  -d '{"key":"<signed-license-key>"}'

# Queue scan (use token from activate response)
export TOKEN=<jwt>
curl -s -X POST http://127.0.0.1:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"scope":"all"}'
```

### License server (`secureops-license-server`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | None | Health check |
| `POST` | `/heartbeat` | None | Verify license key; returns `active` / `expired` / `revoked` |
| `POST` | `/revoke` | `Authorization: Bearer <SECUREOPS_ADMIN_KEY>` | Revoke license by id |

### Error handling

| HTTP status | Meaning |
|-------------|---------|
| `401` | Missing or invalid JWT/API key |
| `403` | Cedar denied capability or forged license |
| `404` | Resource not found (tenant-scoped) |
| `503` | Store unhealthy (`/readyz`) |

---

## Deployment

### Docker Compose — host-local daemon

```sh
just docker-build
just docker-up
just docker-audit    # one-shot audit via tools profile
```

On Linux EC2, set `SECUREOPS_NETWORK_MODE=host` so agents on the host can reach the egress proxy.

### Docker Compose — platform

```sh
cp deploy/docker/.env.example deploy/docker/.env
just platform-up
just platform-status
```

Services: `api`, `postgres`, `redis`, `minio`, `otel-collector`. The `scanner` worker is a **placeholder** — enable with `--profile workers` once `secureops-scanner` exists.

### Kubernetes (host-local)

```sh
just k8s-apply
just k8s-logs
```

Includes daemon `Deployment`, PVC, `ConfigMap` for `openclaw.json`, and `CronJob` for scheduled `secureops audit --json`.

### Helm (platform API)

```sh
helm install secureops deploy/helm/ -f deploy/helm/values.yaml
```

Subcharts (disabled by default):

- `bpf-agent` — kernel PEP DaemonSet (enterprise)
- `neo4j` — graph backend (pro/enterprise)

### GitHub Actions

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | push/PR to `master`, tags | Build, test, clippy, fmt; publish 23 crates on `v*` tag |
| `release.yml` | `v*` tag | GitHub Release + cross-compiled binaries (4 binaries × 4 targets) |
| `supply-chain.yml` | push/PR + weekly | cargo-deny, RustSec audit, CycloneDX SBOM, bench compile |

### Release script

```sh
./scripts/release.sh 0.1.0   # bump version, CI gate, git tag (maintainer)
```

---

## Monitoring & operations

| Concern | Implementation |
|---------|----------------|
| **Health checks** | API: `/livez`, `/readyz`; Docker/Helm probes wired |
| **Logging** | `tracing` structured logs; `RUST_LOG` filter |
| **Metrics / traces** | OTel collector in platform compose; export endpoint via `OTEL_EXPORTER_OTLP_ENDPOINT` |
| **Alerting** | Monitor alerts → stdout + `.secureops/audit.jsonl`; platform WebSocket hub |
| **Audit trail** | Daemon JSONL hash chain; Postgres usage audit (migration 006, append-only) |
| **Circuit breaker** | Cost monitor trips → daemon logs `circuit_tripped` event |

### Troubleshooting

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| Daemon refuses to start | Kill switch active | `secureops kill --deactivate` |
| Egress proxy off | Allowlist not enabled | Set `egressAllowlistEnabled: true` in `openclaw.json` |
| Agent cannot reach proxy | Docker bridge networking | Use `SECUREOPS_NETWORK_MODE=host` on Linux or run daemon natively |
| API uses in-memory store | `DATABASE_URL` unset | Set Postgres DSN; check migrations on boot |
| Scans stay `queued` | No scanner worker | Expected today — worker is placeholder |
| `audit --json` exits 2 | Score below 80 | Run `secureops audit` (human report); remediate with `secureops harden` |
| BPF enforce ineffective | Not Linux or missing object | Build `ebpf/`; set `SECUREOPS_BPF_OBJ`; use `SECUREOPS_BPF_ENFORCE=1` |

---

## Security

SecureOps is a security tool. Report vulnerabilities **privately** — see [SECURITY.md](SECURITY.md) (GitHub Security Advisory or security@adversa.ai).

| Area | Approach |
|------|----------|
| **Authentication** | HS256 JWT, SHA-256-hashed API keys, Ed25519 license verification |
| **Authorization** | Cedar default-deny per feature flag |
| **Secrets** | Dev defaults for local runs; production requires explicit `SECUREOPS_JWT_SECRET`, `SECUREOPS_ADMIN_KEY`, `SECUREOPS_LICENSE_PUBKEY` |
| **Audit integrity** | Hash-chained JSONL + Ed25519 (daemon uses `InMemorySigner` today — keychain/TPM wiring in progress) |
| **Egress** | Fail-closed allowlist; denied hosts get `403` before upstream connect |
| **Remediation safety** | Destructive playbooks require HITL approval; default cloud backend is `NoopCloud` |
| **Supply chain** | `cargo-deny`, `cargo-audit`, CycloneDX SBOM in CI |
| **Containers** | Restricted Pod Security Standard in Helm; non-root UID 65532 |

---

## Crates

23 workspace crates, layered inward on `secureops-core`.

| Crate | Ring / tier | Responsibility |
|-------|-------------|----------------|
| `secureops-core` | 0 | Types, traits, scoring — no I/O |
| `secureops-checks` | 1 | Nine audit categories |
| `secureops-fs` | 1 | `tokio::fs` context, kill switch, behavioral baseline |
| `secureops-intel` | 1 | IOC, typosquat, tree-sitter scan |
| `secureops-crypto` | 1 | Argon2id keystore, AES-GCM, keychain / TPM signing |
| `secureops-harden` | 1 | Harden + rollback (5 modules) |
| `secureops-monitors` | 1 | Four monitors, AlertBus, SQLite |
| `secureops-cli` | 1 | `secureops` binary |
| `secureops-napi` | 1 | Node FFI seam (TS wire compatibility) |
| `secureops-policy` | 2 | PDP: Rego, Cedar, allowlist |
| `secureops-proxy` | 2 | Egress PEP + DNS sinkhole |
| `secureops-bpf` | 2 | Kernel PEP (Linux eBPF; `ebpf` feature) |
| `secureops-sandbox` | 2 | wasmtime execution PEP |
| `secureops-auditlog` | 2 | Hash chain + Ed25519 |
| `secureops-ipc` | 2 | Unix JSON-RPC + peer-cred auth |
| `secureops-daemon` | 2 | Ring-2 supervisor |
| `secureops-api` | Platform | HTTP API, store, WebSocket |
| `secureops-license-server` | Platform | License heartbeat/revoke |
| `secureops-tokenbudget` | Intelligence | LLM evidence packing |
| `secureops-graph` | Intelligence | Attack paths, blast radius |
| `secureops-bughunt` | Intelligence | Bounded agentic bug hunt |
| `secureops-rl` | Autonomy | LinUCB finding ranking |
| `secureops-selfheal` | Autonomy | YAML playbooks + HITL |

---

## Project status

`v0.0.1` is a beta. The default build is cross-platform (Linux + macOS) with no system libraries required.

| Capability | State |
|------------|-------|
| Audit · harden · score · CI gate | ✅ Live |
| Egress proxy (allowlist, fail-closed) | ✅ Live |
| Runtime monitors · kill switch · audit log append | ✅ Live (daemon uses dev signer) |
| Policy engine (Rego / Cedar / allowlist) | ✅ Library complete; daemon uses `AllowlistPdp` today |
| Platform API + Postgres store + Cedar authz | ✅ MVP — 272 tests |
| License server | ✅ Live |
| Web dashboard | 🚧 Scaffold only |
| Scanner / collector worker | 🚧 Placeholder in compose |
| Live cloud collectors (AWS/GCP/Azure) | 🚧 Self-heal AWS backend started; no full ingestion |
| Kernel PEP enforce (eBPF LSM deny) | 🚧 `--features ebpf`, `SECUREOPS_BPF_ENFORCE=1` |
| Execution sandbox in daemon | 🚧 Library ready; daemon logs "WASM PEP DISABLED" |
| TPM-backed signing | 🚧 `--features tpm` (Linux + `libtss2-dev`) |
| N-API Node package release | 🚧 FFI seam only; npm shim in separate repo |
| Egress per-decision audit append | 🚧 Proxy lacks daemon callback |
| Neo4j graph backend | 🚧 Helm subchart; not validated |

---

## Contributing

Contributions are welcome — issues, bug reports, and PRs.

1. Fork and branch from `master`.
2. Keep the gate green: `just ci` (or `cargo fmt --all --check && cargo clippy --workspace -- -D warnings && cargo test --workspace`).
3. Add tests for new behavior; keep the JSON wire format stable with the TS tool.
4. Use clear, conventional commit messages; open a PR describing the change and its rationale.

New to the codebase? Start with [PRODUCT.md](PRODUCT.md), then `crates/secureops-core` for the type/scoring contract, then [docs/RUNNING.md](docs/RUNNING.md) for hands-on workflows.

---

## License

[MIT](LICENSE)

<sub>Rust port of the <a href="https://www.npmjs.com/package/@adversa/secureops"><code>@adversa/secureops</code></a> TypeScript tool (v2.2.0 reference). The npm shim is released from a separate repository.</sub>

# SecureOps Rust workspace — local dev, Docker, and K8s helpers.
# Install: brew install just   OR   cargo install just
# One-shot bootstrap:  just setup

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# OpenClaw state directory (override: OPENCLAW_STATE_DIR=/path just setup)
state_dir := env_var_or_default("OPENCLAW_STATE_DIR", "/tmp/secureops-demo")

# Built CLI binary (debug after `just build`)
cli := "target/debug/secureops"
daemon := "target/debug/secureops-daemon"

# Docker paths (context = repo root)
docker_dir := "deploy/docker"
image := "secureops-rust:latest"

default:
    @just --list

# --- One-command local setup -------------------------------------------------

# Prerequisites check → build workspace → run tests → create state dir → init keystore
setup: check-deps build test state-init
    @echo ""
    @echo "✓ Local setup complete."
    @echo "  State dir: {{state_dir}}"
    @echo "  Next steps:"
    @echo "    just audit          # security audit"
    @echo "    just monitor        # live monitors (Ctrl-C)"
    @echo "    just daemon         # Ring-2 daemon"
    @echo "  Docs: docs/RUNNING.md"

check-deps:
    @echo "Checking toolchain..."
    @command -v cargo >/dev/null || { echo "Missing: cargo (install Rust 1.80+)"; exit 1; }
    @command -v rustc >/dev/null || { echo "Missing: rustc"; exit 1; }
    @rustc --version
    @command -v node >/dev/null || { echo "Missing: node 18+ (needed for secureops-napi build)"; exit 1; }
    @node --version
    @# just is optional for this recipe (you already have it if you ran `just setup`)

build:
    cargo build --workspace

build-release:
    cargo build --release --workspace

test:
    cargo test --workspace

test-quick pkg="secureops-checks":
    cargo test -p {{pkg}}

clippy:
    cargo clippy --workspace -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

ci: fmt-check clippy test
    @echo "✓ CI checks passed"

# --- State dir + CLI ---------------------------------------------------------

state-init:
    mkdir -p "{{state_dir}}"
    OPENCLAW_STATE_DIR="{{state_dir}}" {{cli}} init

audit *FLAGS="":
    OPENCLAW_STATE_DIR="{{state_dir}}" {{cli}} audit {{FLAGS}}

audit-json:
    OPENCLAW_STATE_DIR="{{state_dir}}" {{cli}} audit --json

audit-deep:
    OPENCLAW_STATE_DIR="{{state_dir}}" {{cli}} audit --deep

harden *FLAGS="":
    OPENCLAW_STATE_DIR="{{state_dir}}" {{cli}} harden {{FLAGS}}

status:
    OPENCLAW_STATE_DIR="{{state_dir}}" {{cli}} status

monitor:
    OPENCLAW_STATE_DIR="{{state_dir}}" {{cli}} monitor

behavioral window="60":
    OPENCLAW_STATE_DIR="{{state_dir}}" {{cli}} behavioral --window {{window}}

kill reason="drill":
    OPENCLAW_STATE_DIR="{{state_dir}}" {{cli}} kill --reason "{{reason}}"

kill-off:
    OPENCLAW_STATE_DIR="{{state_dir}}" {{cli}} kill --deactivate

export-incident:
    OPENCLAW_STATE_DIR="{{state_dir}}" {{cli}} export-incident

daemon:
    OPENCLAW_STATE_DIR="{{state_dir}}" {{daemon}}

# N-API addon (optional; needs Node for napi-build)
napi:
    cargo build --release -p secureops-napi
    @echo "Built: target/release/libsecureops_napi.*"
    @echo "Copy to TS package: cp target/release/libsecureops_napi.* ../secureops/secureops.node"

# --- Docker (EC2 / any host with Docker) -------------------------------------

docker-build:
    docker build -f {{docker_dir}}/Dockerfile -t {{image}} .

docker-up:
    docker compose -f {{docker_dir}}/docker-compose.yml up -d --build

docker-down:
    docker compose -f {{docker_dir}}/docker-compose.yml down

docker-logs:
    docker compose -f {{docker_dir}}/docker-compose.yml logs -f secureops-daemon

docker-audit:
    docker compose -f {{docker_dir}}/docker-compose.yml --profile tools run --rm secureops-audit

docker-shell:
    docker compose -f {{docker_dir}}/docker-compose.yml exec secureops-daemon sh

# --- Kubernetes --------------------------------------------------------------

k8s-apply:
    kubectl apply -k deploy/k8s/

k8s-delete:
    kubectl delete -k deploy/k8s/ --ignore-not-found

k8s-audit:
    kubectl -n secureops create job --from=cronjob/secureops-audit secureops-audit-manual-$(date +%s) || \
      kubectl -n secureops run secureops-audit --rm -it --restart=Never \
        --image=secureops-rust:latest --command -- secureops audit --json

k8s-logs:
    kubectl -n secureops logs -l app.kubernetes.io/name=secureops-daemon -f

# --- eBPF (Linux only; separate crate) ---------------------------------------

bpf-build:
    cd ebpf && \
    CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=bpf-linker \
      cargo build --target bpfel-unknown-none -Z build-std=core --release

bpf-daemon:
    SECUREOPS_BPF_OBJ=ebpf/target/bpfel-unknown-none/release/secureops-ebpf \
      OPENCLAW_STATE_DIR="{{state_dir}}" {{daemon}}

# Build + attach the kernel PEP (Linux only; no-op elsewhere).
bpf-load:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! uname -s | grep -qi linux; then
      echo "bpf-load: kernel PEP is Linux-only — no-op on $(uname -s)."; exit 0
    fi
    just bpf-build
    echo "eBPF object built. Start the PEP with: just bpf-daemon"

# Show attached SecureOps eBPF programs (Linux only; needs bpftool + root).
bpf-status:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! uname -s | grep -qi linux; then
      echo "bpf-status: Linux-only — no-op on $(uname -s)."; exit 0
    fi
    sudo bpftool prog show 2>/dev/null | grep -i secureops || echo "no SecureOps eBPF programs attached"

# Detach the kernel PEP (programs unpin when the daemon exits).
bpf-unload:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! uname -s | grep -qi linux; then
      echo "bpf-unload: Linux-only — no-op on $(uname -s)."; exit 0
    fi
    echo "Stop secureops-daemon to detach; eBPF programs are unpinned on exit."

# Demo the exfil-chain detector on ANY OS (no kernel): runs the daemon with a
# mock event source that injects a read-.env→connect chain.
bpf-mock-demo:
    OPENCLAW_STATE_DIR="{{state_dir}}" cargo run -p secureops-daemon --features mock

# --- Platform services (Phase 5: API + Postgres + Redis + MinIO + OTel) -------

platform_compose := "deploy/docker/docker-compose.platform.yml"

# Bring up the platform stack. Copy deploy/docker/.env.example → .env first.
platform-up:
    docker compose -f {{platform_compose}} --env-file deploy/docker/.env up -d --build

platform-down:
    docker compose -f {{platform_compose}} --env-file deploy/docker/.env down

platform-logs service="api":
    docker compose -f {{platform_compose}} logs -f {{service}}

platform-status:
    docker compose -f {{platform_compose}} ps

# Run the API locally (in-memory store; no Postgres needed for the 5a surface).
api:
    SECUREOPS_API_ADDR=127.0.0.1:8080 cargo run -p secureops-api

# Run the scan-job worker locally (needs a reachable REDIS_URL).
scanner:
    cargo run -p secureops-scanner

# Aliases the prompt-pack expects.
up: platform-up
down: platform-down

# Smoke: queue a scan via the API after `just up` (export TOKEN first).
scan target="all":
    curl -fsS -X POST http://127.0.0.1:8080/api/v1/scans \
      -H "Authorization: Bearer ${TOKEN:-}" -H 'Content-Type: application/json' \
      -d '{"scope":"{{target}}"}' | jq .

# Queue a scan via the running API (export TOKEN from /license/activate first).
platform-scan target="all":
    curl -fsS -X POST http://127.0.0.1:8080/api/v1/scans \
      -H "Authorization: Bearer ${TOKEN:-}" -H 'Content-Type: application/json' \
      -d '{"scope":"{{target}}"}'

# Apply SQL migrations to $DATABASE_URL (needs sqlx-cli: cargo install sqlx-cli).
db-migrate:
    sqlx migrate run --source crates/secureops-api/migrations

# --- Intelligence layer (Phase 6: graph + LLM bug-hunt + token budget) -------

# Run the intelligence-engine unit tests (graph algorithms, knapsack, agentic loop).
intel-test:
    cargo test -p secureops-tokenbudget -p secureops-graph -p secureops-bughunt

# Rebuild the security knowledge graph from a sample 2-node topology (demo).
graph-rebuild:
    curl -fsS -X POST http://127.0.0.1:8080/api/v1/graph/rebuild \
      -H "Authorization: Bearer ${TOKEN:-}" -H 'Content-Type: application/json' \
      -d '{"nodes":[{"id":"internet","kind":"net","exposed":true},{"id":"db","kind":"rds","sensitive":true}],"edges":[{"from":"internet","to":"db","kind":"Exposes","difficulty":1.0}]}' | jq .

# Queue an LLM bug-hunt via the running API (export TOKEN; tier must include 'bughunt').
bughunt scope="all":
    curl -fsS -X POST http://127.0.0.1:8080/api/v1/bughunt \
      -H "Authorization: Bearer ${TOKEN:-}" -H 'Content-Type: application/json' \
      -d '{"scope":"{{scope}}"}'

# --- Autonomy (Phase 7: RL ranking + self-healing playbooks) -----------------

# Run the autonomy unit tests (LinUCB ranking, playbook engine, circuit breaker).
autonomy-test:
    cargo test -p secureops-rl -p secureops-selfheal

# Show the remediation HITL queue + RL stats (export TOKEN; needs running API).
heal-status:
    @curl -fsS http://127.0.0.1:8080/api/v1/remediations/queue \
      -H "Authorization: Bearer ${TOKEN:-}" | jq . || \
      echo "heal-status: set TOKEN via /license/activate and start the API (just api)."
    @curl -fsS http://127.0.0.1:8080/api/v1/rl/stats \
      -H "Authorization: Bearer ${TOKEN:-}" | jq . || true

# Queue a remediation for finding_id using playbook_id (mock backend, no real cloud).
heal-dry finding_id="finding-1" playbook="s3-public-acl":
    curl -fsS -X POST http://127.0.0.1:8080/api/v1/remediations \
      -H "Authorization: Bearer ${TOKEN:-}" -H 'Content-Type: application/json' \
      -d '{"finding_id":"{{finding_id}}","playbook_id":"{{playbook}}"}' | jq .

# Approve a queued remediation (executes through the playbook engine).
heal-approve id="":
    curl -fsS -X POST http://127.0.0.1:8080/api/v1/remediations/{{id}}/approve \
      -H "Authorization: Bearer ${TOKEN:-}" | jq .

# Deny a queued remediation (no cloud call, audit logged).
heal-deny id="":
    curl -fsS -X POST http://127.0.0.1:8080/api/v1/remediations/{{id}}/deny \
      -H "Authorization: Bearer ${TOKEN:-}" | jq .

# Reset a halted circuit-breaker class (safe|reversible|destructive).
heal-reset class="reversible":
    curl -fsS -X POST http://127.0.0.1:8080/api/v1/remediations/circuit/{{class}}/reset \
      -H "Authorization: Bearer ${TOKEN:-}" | jq .

# --- Enterprise (Phase 8: dashboard + license server) ------------------------

# Run the stateless license server locally.
license-server:
    SECUREOPS_ADMIN_KEY="${SECUREOPS_ADMIN_KEY:-dev-admin-key}" cargo run -p secureops-license-server

# Dashboard dev server (needs Node 18+; proxies /api + /ws to the running API).
web-dev:
    cd web && npm install && npm run dev

# Build the dashboard for production (emits web/dist).
web-build:
    cd web && npm install && npm run build

# Zero-downtime-ish platform upgrade: pull → migrate → rolling restart → health poll.
platform-upgrade:
    #!/usr/bin/env bash
    set -euo pipefail
    docker compose -f {{platform_compose}} --env-file deploy/docker/.env pull
    just db-migrate || echo "migrate skipped (set DATABASE_URL + install sqlx-cli)"
    docker compose -f {{platform_compose}} --env-file deploy/docker/.env up -d --no-deps api
    for i in $(seq 1 30); do
      if curl -fsS http://127.0.0.1:8080/livez >/dev/null 2>&1; then echo "api healthy after upgrade"; exit 0; fi
      sleep 2
    done
    echo "health check failed after upgrade" >&2; exit 1

# --- Docs --------------------------------------------------------------------

docs:
    @echo "See docs/RUNNING.md"

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

# --- Docs --------------------------------------------------------------------

docs:
    @echo "See docs/RUNNING.md"

# Running SecureOps (Rust)

Step-by-step guide for **local development**, **AWS EC2 + Docker**, and **Kubernetes**.

| Environment | One-command entry | Full path |
|-------------|-------------------|-----------|
| **Local (macOS/Linux)** | `just setup` | [§1 Local](#1-local-development-macos--linux) |
| **AWS EC2 + Docker** | `just docker-up` (on the instance) | [§2 EC2 + Docker](#2-aws-ec2--docker--docker-compose) |
| **Kubernetes** | `just k8s-apply` (after image load) | [§3 Kubernetes](#3-kubernetes) |

Prerequisites for all paths: **[README.md](../README.md)** (crate map, tests, N-API).

---

## Tooling overview

| Tool | Role |
|------|------|
| **[just](https://github.com/casey/just)** | Single entry point: `just setup`, `just audit`, `just docker-up`, `just k8s-apply` |
| **Cargo** | Build `secureops` (CLI) and `secureops-daemon` (Ring 2) |
| **Node 18+** | Required at compile time for `secureops-napi` (`napi-build`); not needed to run CLI/daemon only |
| **Docker / Compose** | EC2 or any Linux VM |
| **kubectl + kustomize** | Kubernetes |

Install `just`:

```sh
brew install just          # macOS
# or
cargo install just
```

---

## 1. Local development (macOS / Linux)

### 1.1 Prerequisites

| Requirement | Version | Check |
|-------------|---------|-------|
| Rust | ≥ 1.80 | `rustc --version` |
| Cargo | (with Rust) | `cargo --version` |
| Node.js | ≥ 18 (22 in CI) | `node --version` |
| just | latest | `just --version` |

Optional:

- **eBPF kernel PEP**: Linux only — [§1.6 eBPF](#16-ebpf-linux-only)
- **N-API / TS parity**: Node + `../secureops` npm build — [§1.7](#17-optional-n-api-and-ts-parity)

### 1.2 One-command setup

From the repo root:

```sh
just setup
```

This runs, in order:

1. `check-deps` — `cargo`, `rustc`, `node` on PATH  
2. `build` — `cargo build --workspace`  
3. `test` — `cargo test --workspace` (~165 tests)  
4. `state-init` — creates `OPENCLAW_STATE_DIR` (default `/tmp/secureops-demo`) and runs `secureops init`

Override the state directory:

```sh
OPENCLAW_STATE_DIR=$HOME/.openclaw just setup
```

### 1.3 Day-to-day commands (Justfile)

All recipes use `OPENCLAW_STATE_DIR` (default `/tmp/secureops-demo`). Run from the repo root:

| Command | What it does |
|---------|----------------|
| `just audit` | Human-readable security audit |
| `just audit-json` | JSON audit; exit code `2` if score &lt; 80 (CI gate) |
| `just audit-deep` | Slower, higher-coverage audit |
| `just harden` | Safe auto-fixes |
| `just status` | Kill switch, score, monitor toggles |
| `just monitor` | Live monitors (Ctrl-C to stop) |
| `just daemon` | Ring-2 daemon (monitors + optional egress PEP) |
| `just behavioral` | Rolling tool-call stats (`--window 60` default) |
| `just kill` | Emergency kill switch |
| `just kill-off` | Deactivate kill switch |
| `just ci` | `fmt-check` + `clippy` + `test` (matches CI) |
| `just --list` | All recipes |

Without `just`, equivalent manual flow:

```sh
cargo build --workspace
cargo test --workspace
export OPENCLAW_STATE_DIR=/tmp/secureops-demo
mkdir -p "$OPENCLAW_STATE_DIR"
cargo run -p secureops-cli -- init
cargo run -p secureops-cli -- audit
```

### 1.4 Ring-2 daemon and egress PEP (local)

```sh
just daemon
# or: OPENCLAW_STATE_DIR=/tmp/secureops-demo cargo run -p secureops-daemon
```

Enable egress allowlist in `$OPENCLAW_STATE_DIR/openclaw.json`:

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

The proxy listens on **`127.0.0.1:8889`**. Point the agent at:

```sh
export HTTPS_PROXY=http://127.0.0.1:8889
```

Non-allowlisted hosts receive **403**; no bytes leave the host.

### 1.5 Targeted tests

```sh
just test-quick secureops-proxy
cargo test -p secureops-policy -- rego_pdp_tests
cargo test -p secureops-policy -- cedar_tests
```

See [README.md § Selected test targets](../README.md#selected-test-targets).

### 1.6 eBPF (Linux only)

The `ebpf/` crate is **outside** the main workspace.

```sh
cargo install bpf-linker
cd ebpf
CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=bpf-linker \
  cargo build --target bpfel-unknown-none -Z build-std=core --release
```

Run daemon with the BPF object:

```sh
just bpf-daemon
# or set SECUREOPS_BPF_OBJ=ebpf/target/bpfel-unknown-none/release/secureops-ebpf
```

On **macOS**, skip eBPF; the workspace builds and tests without it.

### 1.7 Optional: N-API and TS parity

```sh
just napi
# Copy dylib/so to ../secureops/secureops.node per README
```

TS vs Rust findings diff: [README.md § TS faithfulness](../README.md#ts-faithfulness-cross-check).

---

## 2. AWS EC2 + Docker / docker-compose

Use this when you want a **long-running Ring-2 daemon** on a VM (audit jobs, monitors, optional egress PEP on the same host as the agent).

### 2.1 EC2 instance sizing (starting point)

| Workload | Instance | Notes |
|----------|----------|-------|
| Daemon + monitors only | `t3.small` | 2 vCPU, 2 GiB RAM |
| Daily audit CronJob-style runs | `t3.micro` for one-shot containers | Spike CPU during `audit --deep` |
| Egress PEP + agent on same host | `t3.medium+` | Prefer **same host** as OpenClaw agent |

OS: **Amazon Linux 2023** or **Ubuntu 22.04+** (Linux required for host-network egress; see below).

### 2.2 Install Docker on EC2

**Amazon Linux 2023:**

```sh
sudo dnf update -y
sudo dnf install -y docker
sudo systemctl enable --now docker
sudo usermod -aG docker ec2-user
# Log out and back in so group membership applies
```

**Ubuntu:**

```sh
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker ubuntu
```

### 2.3 Deploy from the repo

On the EC2 instance:

```sh
git clone https://github.com/aryasoni98/secureops.git
cd secureops
```

**Option A — Just (recommended):**

```sh
# Install just on the instance (once)
cargo install just   # needs Rust on EC2, or download just binary from GitHub releases

just docker-up
```

**Option B — Compose directly:**

```sh
docker compose -f deploy/docker/docker-compose.yml up -d --build
```

### 2.4 First-time state initialization

```sh
docker compose -f deploy/docker/docker-compose.yml --profile tools run --rm secureops-init
# or: just docker-audit   # after init; audit expects .secureops/
```

### 2.5 Operations

| Task | Command |
|------|---------|
| Logs | `just docker-logs` |
| One-shot audit (JSON) | `just docker-audit` |
| Shell into container | `just docker-shell` |
| Stop | `just docker-down` |

Persisted state: Docker volume `secureops-state` → `/data/openclaw` inside containers (`OPENCLAW_STATE_DIR`).

### 2.6 Egress PEP on EC2

The daemon binds the egress proxy to **`127.0.0.1:8889`** inside the container network namespace. For an agent running **on the EC2 host** (not inside Docker), use **host network** on Linux:

```sh
export SECUREOPS_NETWORK_MODE=host
just docker-up
```

Then on the host:

```sh
export HTTPS_PROXY=http://127.0.0.1:8889
```

Enable allowlist in the mounted state dir’s `openclaw.json` (edit on volume or bake into image).

**Mac Docker Desktop** does not support host networking the same way; run `just daemon` natively on macOS for egress testing.

### 2.7 Security groups

| Port | When | Source |
|------|------|--------|
| 22 | SSH admin | Your IP |
| 8889 | Egress PEP (bridge mode only) | Usually **not** exposed publicly; loopback/host-only |

Do **not** expose the state directory or daemon admin interfaces to the internet.

### 2.8 CI-style audit on EC2 (cron)

```sh
# /etc/cron.d/secureops-audit
0 6 * * * ec2-user cd /home/ec2-user/secureops/rust && docker compose -f deploy/docker/docker-compose.yml --profile tools run --rm secureops-audit >> /var/log/secureops-audit.log 2>&1
```

Exit code `2` from `audit --json` means score below threshold — treat as failure in monitoring.

---

## 3. Kubernetes

Manifests live in **`deploy/k8s/`** (Kustomize). They deploy:

- **Deployment** `secureops-daemon` — Ring-2 daemon (init container runs `secureops init`)
- **CronJob** `secureops-audit` — daily `secureops audit --json` (06:00 UTC)
- **PVC** `openclaw-state` — shared state at `/data/openclaw`
- **ConfigMap** `openclaw-config` — sample `openclaw.json`

### 3.1 Prerequisites

| Requirement | Notes |
|-------------|-------|
| Cluster | EKS, GKE, AKS, or local kind/minikube |
| `kubectl` | Configured for the cluster |
| Container image | `secureops-rust:latest` (build and load/push — below) |

### 3.2 Build and publish the image

**On your laptop or CI:**

```sh
docker build -f deploy/docker/Dockerfile -t secureops-rust:latest .
```

**Push to your registry (EKS example):**

```sh
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.us-east-1.amazonaws.com
docker tag secureops-rust:latest ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/secureops-rust:latest
docker push ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/secureops-rust:latest
```

Edit `deploy/k8s/kustomization.yaml` `images` section to point at your registry/tag.

**Local kind cluster:**

```sh
kind load docker-image secureops-rust:latest
```

### 3.3 Install manifests

```sh
just k8s-apply
# or: kubectl apply -k deploy/k8s/
```

Verify:

```sh
kubectl -n secureops get pods,pvc,cronjob
kubectl -n secureops logs -l app.kubernetes.io/name=secureops-daemon -f
```

### 3.4 Manual audit Job

```sh
just k8s-audit
```

Or:

```sh
kubectl -n secureops create job --from=cronjob/secureops-audit audit-$(date +%s)
kubectl -n secureops logs job/audit-XXXX -f
```

### 3.5 Configuration

1. Edit **`deploy/k8s/configmap-openclaw.yaml`** for `egressAllowlistEnabled` / hosts.  
2. Re-apply: `kubectl apply -k deploy/k8s/`.  
3. Restart daemon: `kubectl -n secureops rollout restart deployment/secureops-daemon`.

### 3.6 Egress PEP on Kubernetes

The proxy binds **loopback inside the pod**. Options:

| Pattern | When |
|---------|------|
| **hostNetwork: true** on daemon Deployment | Agent processes run on the same node and should use `127.0.0.1:8889` |
| **Sidecar** in the agent pod | Share network namespace; both containers see the same loopback |
| **Off** (`egressAllowlistEnabled: false`) | Monitors only; no proxy |

Uncomment in `deployment-daemon.yaml`:

```yaml
hostNetwork: true
dnsPolicy: ClusterFirstWithHostNet
```

### 3.7 Production hardening checklist

- [ ] Pin image digest in Kustomize, not `:latest`  
- [ ] Restrict RBAC; dedicated ServiceAccount (add in a follow-up manifest if needed)  
- [ ] Encrypt PVC (storage class with encryption at rest)  
- [ ] NetworkPolicy: deny ingress to daemon pod except where required  
- [ ] Alert on CronJob failures and audit exit code 2  
- [ ] Backup volume snapshots for `/data/openclaw/.secureops`

### 3.8 Uninstall

```sh
just k8s-delete
```

---

## 4. Environment variables

| Variable | Default | Used by |
|----------|---------|---------|
| `OPENCLAW_STATE_DIR` | `~/.openclaw` (CLI/daemon) or `/tmp/secureops-demo` (Justfile) | CLI, daemon, containers |
| `SECUREOPS_BPF_OBJ` | (unset) | Daemon — path to eBPF object (Linux) |
| `SECUREOPS_NETWORK_MODE` | `bridge` | docker-compose — set `host` on Linux EC2 for egress |

---

## 5. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `napi-build` / Node errors on build | Install Node 18+; or build only CLI/daemon: `cargo build -p secureops-cli -p secureops-daemon` |
| `just: command not found` | `brew install just` or use manual `cargo` commands in §1.3 |
| Daemon exits immediately | Kill switch active — `just kill-off` or remove `$STATE_DIR/.secureops/killswitch` |
| Egress proxy unreachable from host | Use `SECUREOPS_NETWORK_MODE=host` on Linux, or run daemon natively |
| K8s `ImagePullBackOff` | Push image to cluster registry or `kind load docker-image` |
| Audit exit code 2 | Score &lt; 80 — inspect JSON findings; not a crash |

---

## 6. File map

```
secureops/                      # repo root = Rust workspace
  Justfile                      # just setup, audit, docker-*, k8s-*
  docs/RUNNING.md               # this document
  deploy/
    docker/
      Dockerfile
      docker-compose.yml
    k8s/
      kustomization.yaml
      namespace.yaml
      pvc.yaml
      configmap-openclaw.yaml
      deployment-daemon.yaml
      cronjob-audit.yaml
```

CI reference: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (`cargo build/test/clippy/fmt` on ubuntu + macOS).

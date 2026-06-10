# Deploying SecureOps on AWS and Kubernetes

Step-by-step guides for running SecureOps on **AWS EC2 (Docker)** and **Kubernetes (EKS / GKE / AKS / kind)**.

What you deploy:

- **`secureops-daemon`** — the long-running Ring-2 process: runtime monitors + (optional) fail-closed egress proxy on `127.0.0.1:8889` + signed audit log.
- **`secureops` CLI** — used for `init`, scheduled `audit --json` (CI/cron gate), `harden`, and `kill`.

State (keystore, baselines, audit log, `openclaw.json`) lives under `OPENCLAW_STATE_DIR` (the containers use `/data/openclaw`).

> Quick decision:
> - **Audit only, no enforcement?** Just install the CLI binary (see §0) and run `secureops audit --json` from cron/CI. No Docker/K8s needed.
> - **Live egress enforcement + monitors?** Run the daemon via Docker (§1) or Kubernetes (§2).

---

## 0. Audit-only (no containers)

On any Linux box or in CI:

```sh
cargo install secureops-cli            # or download a release binary
export OPENCLAW_STATE_DIR=/var/lib/openclaw
secureops init
secureops audit --json                 # exits 2 below --threshold (default 80) → fail the build
```

That is the whole audit-gate path. The rest of this doc is for **enforcement** (the daemon).

> Want to run locally and only *inspect* AWS read-only (no cost, no impact) before deploying? See **[LOCAL_AND_AWS_READONLY.md](LOCAL_AND_AWS_READONLY.md)**.

---

## 1. AWS EC2 + Docker

Run the daemon on a Linux VM — ideally the **same host as the agent**, so the agent can reach the egress proxy on loopback.

### 1.1 Launch an EC2 instance

| Workload | Instance | Notes |
|----------|----------|-------|
| Daemon + monitors | `t3.small` (2 vCPU / 2 GiB) | baseline |
| Egress PEP + agent on same host | `t3.medium`+ | recommended layout |
| One-shot `audit --deep` | `t3.micro` burst | CPU spike during deep audit |

- **AMI:** Amazon Linux 2023 or Ubuntu 22.04+ (Linux required for host-network egress).
- **Security group:** allow `22` (SSH, your IP only). Do **not** expose `8889` or the state dir to the internet — the proxy is loopback/host-only.

### 1.2 Install Docker

**Amazon Linux 2023:**

```sh
sudo dnf update -y
sudo dnf install -y docker git
sudo systemctl enable --now docker
sudo usermod -aG docker ec2-user
# log out / back in so the group applies
```

**Ubuntu:**

```sh
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2 git
sudo systemctl enable --now docker
sudo usermod -aG docker ubuntu
```

### 1.3 Get SecureOps and build the image

The compose file builds the image from source (`secureops-rust:latest`):

```sh
git clone https://github.com/aryasoni98/secureops.git
cd secureops
docker compose -f deploy/docker/docker-compose.yml build
```

### 1.4 Initialize state (first deploy only)

```sh
docker compose -f deploy/docker/docker-compose.yml --profile tools run --rm secureops-init
```

This creates `.secureops/` (keystore, machine id) in the `secureops-state` volume mounted at `/data/openclaw`.

### 1.5 Configure the egress allowlist

Edit `openclaw.json` inside the state volume to allow only the hosts the agent may reach. Easiest: write it from a one-off container.

```sh
docker compose -f deploy/docker/docker-compose.yml --profile tools run --rm \
  --entrypoint sh secureops-init -c 'cat > /data/openclaw/openclaw.json <<JSON
{
  "secureops": {
    "network": {
      "egressAllowlistEnabled": true,
      "egressAllowlist": ["api.anthropic.com", "api.openai.com"]
    }
  }
}
JSON'
```

### 1.6 Start the daemon

```sh
docker compose -f deploy/docker/docker-compose.yml up -d
docker compose -f deploy/docker/docker-compose.yml logs -f secureops-daemon
```

You should see `egress proxy: ON at 127.0.0.1:8889 … fail-closed`.

### 1.7 Point the agent at the proxy (host-network egress)

The proxy binds `127.0.0.1:8889` **inside the container's** network namespace. For an agent running **on the EC2 host**, use host networking (Linux only):

```sh
export SECUREOPS_NETWORK_MODE=host
docker compose -f deploy/docker/docker-compose.yml up -d

# then, where the agent runs:
export HTTPS_PROXY=http://127.0.0.1:8889
```

Allowed host → tunnels. Anything else → `403 Forbidden`, **0 bytes** to the upstream.

> macOS Docker Desktop has no equivalent host networking — run the daemon natively there (`just daemon`) for egress testing.

### 1.8 Operations

```sh
# one-shot audit (JSON, exit 2 if score < 80)
docker compose -f deploy/docker/docker-compose.yml --profile tools run --rm secureops-audit

# logs / shell / stop
docker compose -f deploy/docker/docker-compose.yml logs -f secureops-daemon
docker compose -f deploy/docker/docker-compose.yml exec secureops-daemon sh
docker compose -f deploy/docker/docker-compose.yml down
```

Daily audit via cron on the host:

```cron
# /etc/cron.d/secureops-audit
0 6 * * * ec2-user cd /home/ec2-user/secureops && docker compose -f deploy/docker/docker-compose.yml --profile tools run --rm secureops-audit >> /var/log/secureops-audit.log 2>&1
```

Exit code `2` = score below threshold → alert on it.

---

## 2. Kubernetes (EKS / GKE / AKS / kind)

Manifests are in [`deploy/k8s/`](https://github.com/aryasoni98/secureops/tree/master/deploy/k8s) (Kustomize). They create, in namespace `secureops`:

| Object | Name | Role |
|--------|------|------|
| Deployment | `secureops-daemon` | Ring-2 daemon (initContainer runs `secureops init`) |
| CronJob | `secureops-audit` | daily `secureops audit --json` (06:00 UTC) |
| PVC | `openclaw-state` | shared state at `/data/openclaw` |
| ConfigMap | `openclaw-config` | `openclaw.json` (egress allowlist) |

### 2.1 Prerequisites

- A cluster (EKS, GKE, AKS, or local kind/minikube) + `kubectl` configured.
- A container registry the cluster can pull from (ECR for EKS).

### 2.2 Build and push the image to a registry

The manifests reference `secureops-rust:latest`. A real cluster cannot pull a local tag — push it to your registry.

**AWS ECR (for EKS):**

```sh
git clone https://github.com/aryasoni98/secureops.git
cd secureops

ACCOUNT=123456789012; REGION=us-east-1
REPO="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/secureops-rust"

aws ecr create-repository --repository-name secureops-rust --region $REGION 2>/dev/null || true
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin "$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"

docker build -f deploy/docker/Dockerfile -t "$REPO:0.0.1" .
docker push "$REPO:0.0.1"
```

**Local kind cluster (no registry needed):**

```sh
docker build -f deploy/docker/Dockerfile -t secureops-rust:latest .
kind load docker-image secureops-rust:latest
```

### 2.3 Point Kustomize at your image

Edit the `images:` block in [`deploy/k8s/kustomization.yaml`](https://github.com/aryasoni98/secureops/blob/master/deploy/k8s/kustomization.yaml):

```yaml
images:
  - name: secureops-rust
    newName: 123456789012.dkr.ecr.us-east-1.amazonaws.com/secureops-rust
    newTag: "0.0.1"
```

(For kind, leave `newName: secureops-rust`, `newTag: latest`.)

### 2.4 Configure the egress allowlist

Edit [`deploy/k8s/configmap-openclaw.yaml`](https://github.com/aryasoni98/secureops/blob/master/deploy/k8s/configmap-openclaw.yaml):

```yaml
data:
  openclaw.json: |
    {
      "secureops": {
        "network": {
          "egressAllowlistEnabled": true,
          "egressAllowlist": ["api.anthropic.com", "api.openai.com"]
        }
      }
    }
```

> Default ships `egressAllowlistEnabled: false` (monitors only). Set `true` to enforce.

### 2.5 Apply

```sh
kubectl apply -k deploy/k8s/

kubectl -n secureops get pods,pvc,cronjob
kubectl -n secureops logs -l app.kubernetes.io/name=secureops-daemon -f
```

The Deployment's initContainer runs `secureops init` into the PVC; the daemon then starts.

### 2.6 Egress PEP on Kubernetes

The proxy binds loopback **inside the pod**. To let agents use it, pick one:

| Pattern | When | How |
|---------|------|-----|
| **`hostNetwork: true`** on the daemon Deployment | agents run on the same node, use `127.0.0.1:8889` | uncomment `hostNetwork` + `dnsPolicy: ClusterFirstWithHostNet` in `deployment-daemon.yaml` |
| **Sidecar** in the agent pod | share the network namespace | add the daemon container to the agent's pod spec |
| **Off** | monitors only | `egressAllowlistEnabled: false` |

After editing: `kubectl apply -k deploy/k8s/` then `kubectl -n secureops rollout restart deployment/secureops-daemon`.

### 2.7 Run an audit on demand

```sh
kubectl -n secureops create job --from=cronjob/secureops-audit audit-$(date +%s)
kubectl -n secureops logs -l app.kubernetes.io/name=secureops-audit -f
```

Audit exit code `2` = score < 80 (not a crash). Alert on CronJob failures.

### 2.8 Production hardening checklist

- [ ] Pin an image **digest** in Kustomize, not `:latest`.
- [ ] Dedicated ServiceAccount + least-privilege RBAC.
- [ ] Encrypt the PVC (storage class with encryption at rest); back up `/data/openclaw/.secureops`.
- [ ] NetworkPolicy: deny ingress to the daemon pod except where required.
- [ ] Alert on CronJob failures and audit `exit 2`.
- [ ] Keep the daemon `runAsNonRoot` (already set: uid/gid `65532`).

### 2.9 Uninstall

```sh
kubectl delete -k deploy/k8s/ --ignore-not-found
```

---

## 3. Environment variables

| Variable | Default | Used by |
|----------|---------|---------|
| `OPENCLAW_STATE_DIR` | `/data/openclaw` (containers) | CLI, daemon |
| `HTTPS_PROXY` | — | the agent → `http://127.0.0.1:8889` |
| `SECUREOPS_NETWORK_MODE` | `bridge` | docker-compose — set `host` on Linux EC2 for egress |
| `SECUREOPS_BPF_OBJ` | unset | daemon — compiled eBPF object path (Linux, `ebpf` feature) |

---

## 4. Troubleshooting

| Symptom | Fix |
|---------|-----|
| K8s `ImagePullBackOff` | Push the image to a registry (§2.2) and set `kustomization.yaml` `images.newName`; or `kind load docker-image` |
| Daemon exits immediately | Kill switch active → `secureops kill --deactivate` (or remove `$STATE_DIR/.secureops/killswitch`) |
| Egress proxy unreachable from host | Use `SECUREOPS_NETWORK_MODE=host` on Linux EC2, or run the daemon natively |
| Audit `exit 2` | Score < 80 — inspect JSON findings; not a crash |
| `audit` says no state | Run `secureops init` first (K8s does this in the initContainer) |

See also: [docs/RUNNING.md](RUNNING.md) (local dev + more detail) and [PRODUCT.md](https://github.com/aryasoni98/secureops/blob/master/PRODUCT.md) (architecture).

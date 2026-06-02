# Running SecureOps locally + safely inspecting AWS (read-only, $0)

How to run SecureOps on your machine and inspect an AWS account using your
existing `aws configure` credentials **without creating anything, without cost,
and without impacting the account.**

> **Key fact:** SecureOps has **no AWS integration**. It audits *OpenClaw agent*
> configs on the local filesystem — it does not read your AWS account, instances,
> or IAM. Your AWS credentials are only relevant when you *deploy the daemon* to
> EC2/EKS (see [DEPLOY_AWS_K8S.md](DEPLOY_AWS_K8S.md)), which **does** cost money.
> Everything in this doc is local + read-only.

---

## Safety rules

1. **Only `describe` / `list` / `get` / `sts` calls.** These are free (AWS does not
   bill describe/list API calls) and cannot change state.
2. **Never** run `create-*`, `run-instances`, `ecr ... push`, `kubectl apply`,
   `delete-*`, `put-*`, or `modify-*` against a real account without explicit
   intent — those can incur cost and change infrastructure.
3. **Never deploy to a production account/cluster** casually. Use a dedicated,
   isolated, non-prod target.
4. After any inspection, **verify state is unchanged** (see §4).

---

## 1. Verify the AWS CLI is configured (read-only)

```sh
aws --version
aws configure list            # keys are masked by AWS; shows region + source
aws configure list-profiles
aws sts get-caller-identity   # account id + IAM ARN — read-only, free
aws configure get region
```

Pick a profile/region explicitly if you have several:

```sh
export AWS_PROFILE=default
export AWS_REGION=us-east-1
```

---

## 2. Read-only resource inventory (free)

See what exists (e.g. to plan a future deploy) — none of this changes anything:

```sh
R="${AWS_REGION:-us-east-1}"

# EC2 — running instances are what cost money (you are NOT starting any here)
aws ec2 describe-instances --region "$R" \
  --query 'Reservations[].Instances[].{id:InstanceId,type:InstanceType,state:State.Name}' \
  --output table

# ECR repositories (image registry — a deploy target)
aws ecr describe-repositories --region "$R" --query 'repositories[].repositoryName' --output json

# EKS clusters (k8s deploy target)
aws eks list-clusters --region "$R" --output json

# default VPC (for any future EC2)
aws ec2 describe-vpcs --region "$R" --filters Name=isDefault,Values=true \
  --query 'Vpcs[].VpcId' --output json
```

---

## 3. Run SecureOps locally (no AWS)

Install the CLI (from crates.io or a release binary), then run it entirely
locally — it makes **zero** AWS calls:

```sh
cargo install secureops-cli            # or download a release binary
export OPENCLAW_STATE_DIR=/tmp/secureops-demo
secureops init
secureops audit                        # score your local OpenClaw config
secureops audit --json                 # exits 2 if score < 80 (CI gate)
```

For live egress enforcement locally, run the daemon and point an agent at it:

```sh
cargo install secureops-daemon
secureops-daemon                       # binds 127.0.0.1:8889, fail-closed
export HTTPS_PROXY=http://127.0.0.1:8889
```

---

## 4. Verify zero AWS impact (the double review)

Snapshot resource counts twice and compare — identical counts prove the
read-only inspection changed nothing. Also confirm no SecureOps resources were
created:

```sh
R="${AWS_REGION:-us-east-1}"
snapshot() {
  echo "ec2_total=$(aws ec2 describe-instances --region "$R" --query 'length(Reservations[].Instances[])' --output text)" \
       "ec2_running=$(aws ec2 describe-instances --region "$R" --filters Name=instance-state-name,Values=running --query 'length(Reservations[].Instances[])' --output text)" \
       "ecr=$(aws ecr describe-repositories --region "$R" --query 'length(repositories)' --output text)" \
       "eks=$(aws eks list-clusters --region "$R" --query 'length(clusters)' --output text)"
}
echo "review 1: $(snapshot)"
sleep 2
echo "review 2: $(snapshot)"

# expect <none> / 0 — nothing was created
aws ecr describe-repositories --region "$R" --query "repositories[?contains(repositoryName,'secureops')].repositoryName" --output text
aws eks list-clusters --region "$R" --query "clusters[?contains(@,'secureops')]" --output text
aws ec2 describe-instances --region "$R" --filters Name=tag:Name,Values='*secureops*' --query 'length(Reservations[].Instances[])' --output text
```

If both reviews print identical counts and the secureops queries are empty/`0`,
the inspection was zero-impact and zero-cost.

---

## 5. Zero-cost way to exercise the AWS/K8s deploy

To test the Kubernetes manifests **without** touching AWS (no cost), use a local
`kind` cluster instead of EKS:

```sh
kind create cluster
docker build -f deploy/docker/Dockerfile -t secureops-rust:latest .
kind load docker-image secureops-rust:latest
kubectl apply -k deploy/k8s/
kubectl -n secureops get pods,pvc,cronjob
# tear down (removes everything):
kind delete cluster
```

When you genuinely want it on AWS (this costs money), follow
[DEPLOY_AWS_K8S.md](DEPLOY_AWS_K8S.md) against a **dedicated, non-production**
account or cluster.

---

## Summary

| Action | AWS cost | AWS impact |
|--------|----------|------------|
| `aws sts` / `describe-*` / `list-*` | $0 | none (read-only) |
| Run SecureOps CLI/daemon locally | $0 | none (no AWS calls) |
| `kind` local K8s deploy | $0 | none (no AWS) |
| Push image to ECR | ~storage cents | adds an artifact |
| EC2 / EKS deploy | **billed** | **changes infrastructure** — non-prod only |

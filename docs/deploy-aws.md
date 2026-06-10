# Deploy on AWS

## Read-only setup (host-local audit)

See [`docs/LOCAL_AND_AWS_READONLY.md`](LOCAL_AND_AWS_READONLY.md). One-liner:

```bash
aws iam create-role --role-name SecureOpsReader \
  --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name SecureOpsReader \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

## Full platform on ECS / EKS

The Helm chart in `deploy/helm/` ships an API deployment + NetworkPolicy +
optional Neo4j and bpf-agent subcharts.

```bash
helm install secureops deploy/helm/ \
  --set api.image=ghcr.io/<org>/secureops:<tag> \
  --set postgres.password=$(openssl rand -hex 32) \
  --set redis.enabled=true \
  --set minio.enabled=true
```

### Region + IRSA

Use IAM Roles for Service Accounts (IRSA) instead of shipping access keys:

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<acct>:role/SecureOpsReader
```

## Read-then-write boundary

By default SecureOps holds **read-only** AWS credentials. Cloud mutations only
happen via the self-healing engine, gated by HITL approval. Granting write
capabilities is an explicit per-playbook step.

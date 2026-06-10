# Self-Healing Playbooks

Every remediation is a YAML file under `playbooks/`. Each playbook maps a
finding rule id to a structured cloud action and declares the execution path
through its `class`:

| Class | Execution path |
| --- | --- |
| `safe` | `dry_run → execute → audit` |
| `reversible` | `snapshot → execute → health_check`; rollback on failure |
| `destructive` | requires HITL `Approved` before any cloud call |

A per-class circuit breaker halts a class once its 5-minute error rate exceeds
20%. Reset it via `POST /api/v1/remediations/circuit/{class}/reset` or
`just heal-reset reversible`.

## Sample playbooks shipped today

```text
playbooks/
├── s3-public-acl.yaml          (reversible)
├── sg-open-ssh-world.yaml      (reversible)
├── gcs-public-bucket.yaml      (reversible)
├── azure-nsg-open-rdp.yaml     (reversible)
├── k8s-privileged-pod.yaml     (destructive)
└── enable-cloudtrail.yaml      (safe)
```

## Authoring a playbook

```yaml
id: my-finding-fix
matches: [SC-MY-001]
class: reversible
snapshot: "capture current resource state"
execute: "service.op key1=value1 key2=value2"
health_check: "assert post-condition"
rollback: "restore from snapshot"
audit_required: true
```

The `execute` field is parsed by `secureops_selfheal::parse_step` into a
`CloudAction` enum. Add a new variant + a backend handler when you introduce a
new op.

## Cloud backends

| Backend | Default | Live |
| --- | --- | --- |
| `NoopCloud` | yes | dev/CI; no real mutations |
| `AwsCloud` | no | feature `aws` (AWS SDK v1) |
| `GcpCloud` | no | dry; live SDK lands behind a `gcp-live` feature |
| `AzureCloud` | no | dry; live SDK lands behind an `azure-live` feature |

## Running a remediation

```bash
export TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/v1/license/activate \
  -H 'content-type: application/json' -d '{"key":"..."}' | jq -r .token)

# Queue
just heal-dry finding-1 s3-public-acl
# Approve (replace the id with the response above)
just heal-approve <id>
# Or deny
just heal-deny <id>
```

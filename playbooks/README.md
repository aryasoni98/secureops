# SecureOps Self-Healing Playbooks

Each playbook describes a remediation that maps a finding rule id to a
structured cloud action. The execution path is driven by `class`:

| Class | Path |
|---|---|
| `safe` | `dry_run → execute → audit` |
| `reversible` | `snapshot → execute → health_check`, rollback on failure |
| `destructive` | requires HITL `Approved` before any cloud call |

A per-class circuit breaker halts a class once its 5-minute error rate exceeds
20%. Operators reset via `/api/v1/remediations/circuit/{class}/reset`.

All cloud calls go through the `CloudBackend` trait:
mock (default) → `NoopCloud`, live → `AwsCloud` (feature `aws`),
`GcpCloud` (feature `gcp`), `AzureCloud` (feature `azure`).

Add new playbooks here; load them at startup via
`secureops_selfheal::load_dir("playbooks")`.

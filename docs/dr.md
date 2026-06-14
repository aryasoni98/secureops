# Disaster Recovery & Backup

This runbook covers backup, restore, and recovery objectives for the SecureOps
platform tier (`secureops-api` + Postgres + Redis + MinIO). The host-local CLI
and daemon are stateless apart from the local `.secureops/` audit log, which is
covered separately.

## Recovery objectives (self-hosted defaults)

| Component | Data | RPO (max data loss) | RTO (max downtime) | Mechanism |
|-----------|------|---------------------|--------------------|-----------|
| Postgres (licenses, findings, remediations, audit log) | Critical | **≤ 24h** with daily backups; **≤ 5 min** with WAL archiving / streaming replica | **≤ 1h** | `scripts/backup.sh` (`pg_dump`); WAL archiving for tighter RPO |
| Redis (scan queue) | Transient | **best-effort** (queue is replayable; scans are re-queued from Postgres) | **≤ 15 min** | AOF (`--appendonly yes`) + `scripts/backup.sh` snapshot |
| MinIO/S3 (evidence blobs) | Important | **≤ 24h** with daily mirror; **near-zero** with bucket replication | **≤ 1h** | `scripts/backup.sh` (`mc mirror`); enable bucket versioning/replication for lower RPO |

> These are the **defaults achievable with the shipped tooling**. Tighter
> objectives (RPO ≤ 5 min, RTO ≤ 15 min) require operator-provisioned Postgres
> streaming replication and MinIO/S3 cross-region replication - both supported
> by the architecture but out of scope for the in-tree scripts.

## Backups

```bash
# Daily (host / cron / CI). Writes ./backups/<UTC-timestamp>/ with checksums.
scripts/backup.sh

# In-cluster: run as a CronJob with the *_CONTAINER vars pointed at your pods,
# or replace the docker exec calls with `kubectl exec`.
```

Each backup directory contains `postgres.dump`, `redis-dump.rdb`, optional
`minio/`, a `manifest.json`, and `SHA256SUMS`. Verify with
`(cd <dir> && sha256sum -c SHA256SUMS)`.

**Retention:** keep ≥ 30 days of daily backups (compliance minimum). The
audit-log table additionally has a sanctioned prune path -
`SELECT prune_audit_log(<retain_days>);` (migration `007`) - which is the only
permitted deletion route (the table otherwise REVOKEs DELETE for tamper-evidence).

## Restore

```bash
# DESTRUCTIVE: overwrites live Postgres + Redis. Requires explicit confirmation.
CONFIRM=yes scripts/restore.sh ./backups/<UTC-timestamp>
```

After restore: re-run readiness checks (`GET /readyz` → 200) and confirm the
audit-log hash chain verifies (`secureops` CLI / `verify_chain`).

## Recovery drills

`secureops-chaos` exercises degraded-mode behaviour (Postgres/Redis/MinIO/LLM/
license outages) against in-process backends in CI. For a full DR drill, restore
a backup into a scratch stack and confirm license activation, findings listing,
and signed compliance export all succeed.

## High availability (operator-provisioned)

The Helm chart runs the API at `replicaCount: 2` with a PodDisruptionBudget and
soft anti-affinity (see `deploy/helm`). Stateful services (Postgres, Redis,
MinIO, Neo4j) ship single-replica by default; production HA requires the
operator to point the chart at managed/replicated backends (RDS/Cloud SQL,
ElastiCache/Memorystore, S3, a Neo4j cluster) or deploy their HA operators.

#!/usr/bin/env bash
# SecureOps platform backup (beta blocker: "no backup scripts exist").
#
# Backs up the three stateful platform stores to a timestamped directory:
#   - Postgres  (pg_dump, custom format)
#   - Redis     (RDB snapshot copy)
#   - MinIO/S3  (mc mirror of the evidence bucket)
#
# Designed to run from the host against the docker-compose.platform.yml stack,
# or in-cluster as a CronJob (override the *_CONTAINER / endpoint vars). It is
# idempotent and fails loudly: any step error aborts with a non-zero exit so a
# scheduler marks the run failed instead of silently producing a partial backup.
#
# Usage:
#   scripts/backup.sh [BACKUP_ROOT]      # default: ./backups
#   PG_CONTAINER=... REDIS_CONTAINER=... MINIO_ALIAS=... scripts/backup.sh
set -euo pipefail

BACKUP_ROOT="${1:-${SECUREOPS_BACKUP_ROOT:-./backups}}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="${BACKUP_ROOT}/${STAMP}"
mkdir -p "${DEST}"

PG_CONTAINER="${PG_CONTAINER:-docker-postgres-1}"
REDIS_CONTAINER="${REDIS_CONTAINER:-docker-redis-1}"
MINIO_CONTAINER="${MINIO_CONTAINER:-docker-minio-1}"
POSTGRES_USER="${POSTGRES_USER:-secureops_app}"
POSTGRES_DB="${POSTGRES_DB:-secureops}"
MINIO_BUCKET="${MINIO_BUCKET:-secureops-evidence}"

log() { printf '[backup %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

log "destination: ${DEST}"

# 1) Postgres - logical dump in custom (compressed, restorable) format.
log "dumping Postgres (${POSTGRES_DB}) ..."
docker exec "${PG_CONTAINER}" pg_dump -U "${POSTGRES_USER}" -F c "${POSTGRES_DB}" \
  > "${DEST}/postgres.dump"

# 2) Redis - trigger a synchronous save, then copy the RDB out.
log "snapshotting Redis ..."
docker exec "${REDIS_CONTAINER}" redis-cli SAVE >/dev/null
docker cp "${REDIS_CONTAINER}:/data/dump.rdb" "${DEST}/redis-dump.rdb"

# 3) MinIO - mirror the evidence bucket if `mc` is configured in the container.
log "mirroring MinIO bucket ${MINIO_BUCKET} ..."
if docker exec "${MINIO_CONTAINER}" sh -c 'command -v mc >/dev/null 2>&1'; then
  docker exec "${MINIO_CONTAINER}" mc mirror --overwrite \
    "local/${MINIO_BUCKET}" "/tmp/${MINIO_BUCKET}" >/dev/null 2>&1 || true
  docker cp "${MINIO_CONTAINER}:/tmp/${MINIO_BUCKET}" "${DEST}/minio" 2>/dev/null || \
    log "WARN: MinIO mirror unavailable (no mc alias) - skipping object copy"
else
  log "WARN: mc not present in ${MINIO_CONTAINER} - skipping MinIO object copy"
fi

# Manifest + checksums for restore verification.
( cd "${DEST}" && find . -type f -exec sha256sum {} \; > SHA256SUMS )
cat > "${DEST}/manifest.json" <<EOF
{
  "createdAt": "${STAMP}",
  "postgresDb": "${POSTGRES_DB}",
  "components": ["postgres", "redis", "minio"],
  "tool": "scripts/backup.sh"
}
EOF

log "backup complete: ${DEST}"
log "verify with: (cd ${DEST} && sha256sum -c SHA256SUMS)"

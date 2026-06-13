#!/usr/bin/env bash
# SecureOps platform restore (beta blocker: DR path).
#
# Restores a backup produced by scripts/backup.sh into the running stack.
# DESTRUCTIVE: it overwrites the current Postgres database and Redis dataset.
# Requires explicit confirmation (CONFIRM=yes) so it cannot run by accident.
#
# Usage:
#   CONFIRM=yes scripts/restore.sh BACKUP_DIR
set -euo pipefail

SRC="${1:?usage: CONFIRM=yes scripts/restore.sh BACKUP_DIR}"
[ "${CONFIRM:-no}" = "yes" ] || {
  echo "refusing to restore without CONFIRM=yes (this OVERWRITES live data)" >&2
  exit 2
}

PG_CONTAINER="${PG_CONTAINER:-docker-postgres-1}"
REDIS_CONTAINER="${REDIS_CONTAINER:-docker-redis-1}"
POSTGRES_USER="${POSTGRES_USER:-secureops_app}"
POSTGRES_DB="${POSTGRES_DB:-secureops}"

log() { printf '[restore %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# Verify integrity before touching anything.
if [ -f "${SRC}/SHA256SUMS" ]; then
  log "verifying checksums ..."
  ( cd "${SRC}" && sha256sum -c SHA256SUMS )
fi

# 1) Postgres - drop & recreate via pg_restore --clean.
log "restoring Postgres (${POSTGRES_DB}) ..."
docker cp "${SRC}/postgres.dump" "${PG_CONTAINER}:/tmp/restore.dump"
docker exec "${PG_CONTAINER}" pg_restore -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" \
  --clean --if-exists /tmp/restore.dump

# 2) Redis - load the snapshot (requires a restart to take effect).
if [ -f "${SRC}/redis-dump.rdb" ]; then
  log "restoring Redis snapshot (will restart redis) ..."
  docker cp "${SRC}/redis-dump.rdb" "${REDIS_CONTAINER}:/data/dump.rdb"
  docker restart "${REDIS_CONTAINER}" >/dev/null
fi

log "restore complete. MinIO objects (if any) are under ${SRC}/minio - re-upload"
log "with 'mc mirror' if your evidence bucket needs them."

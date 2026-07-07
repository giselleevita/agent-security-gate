#!/usr/bin/env bash
#
# Back up Agent Security Gate state into a timestamped bundle:
#   - Postgres logical dump (approvals, policy_exceptions, schema_migrations)
#   - the hash-chained audit log
#   - a manifest with checksums
#
# Usage:
#   scripts/backup.sh [OUTPUT_DIR]
#
# Env:
#   PG_SERVICE   docker compose service for Postgres (default: postgres)
#   PG_USER      Postgres user   (default: asg)
#   PG_DB        Postgres db     (default: asg)
#   AUDIT_LOG    audit log path  (default: audit/events.jsonl)
#
set -euo pipefail

OUT_ROOT="${1:-backups}"
PG_SERVICE="${PG_SERVICE:-postgres}"
PG_USER="${PG_USER:-asg}"
PG_DB="${PG_DB:-asg}"
AUDIT_LOG="${AUDIT_LOG:-audit/events.jsonl}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="${OUT_ROOT}/asg-backup-${TS}"
mkdir -p "${DEST}/audit"

echo "[backup] postgres dump (${PG_SERVICE}:${PG_DB}) -> ${DEST}/postgres.sql"
docker compose exec -T "${PG_SERVICE}" pg_dump -U "${PG_USER}" -d "${PG_DB}" --clean --if-exists \
  > "${DEST}/postgres.sql"

if [[ -f "${AUDIT_LOG}" ]]; then
  echo "[backup] audit log -> ${DEST}/audit/"
  cp "${AUDIT_LOG}" "${DEST}/audit/"
  [[ -f "${AUDIT_LOG}.head" ]] && cp "${AUDIT_LOG}.head" "${DEST}/audit/" || true
else
  echo "[backup] WARNING: audit log ${AUDIT_LOG} not found (using external sink only?)"
fi

echo "[backup] writing manifest"
{
  echo "created_utc=${TS}"
  echo "pg_db=${PG_DB}"
  echo "audit_log=${AUDIT_LOG}"
  echo "sha256:"
  # macOS uses shasum; Linux uses sha256sum.
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${DEST}" && find . -type f ! -name manifest.txt -exec sha256sum {} +)
  else
    (cd "${DEST}" && find . -type f ! -name manifest.txt -exec shasum -a 256 {} +)
  fi
} > "${DEST}/manifest.txt"

echo "[backup] done: ${DEST}"
echo "${DEST}"

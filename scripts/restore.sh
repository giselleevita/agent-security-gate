#!/usr/bin/env bash
#
# Restore an Agent Security Gate backup bundle produced by scripts/backup.sh.
#
# Usage:
#   scripts/restore.sh BUNDLE_DIR
#
# Env:
#   PG_SERVICE   docker compose service for Postgres (default: postgres)
#   PG_USER      Postgres user   (default: asg)
#   PG_DB        target database (default: asg)  -- use a scratch db for drills
#   AUDIT_LOG    audit log path to restore into  (default: audit/events.jsonl)
#   RESTORE_AUDIT set to "0" to skip audit restore (default: 1)
#
# WARNING: the dump is taken with --clean --if-exists, so it DROPs and recreates the
# target tables. Point PG_DB at a scratch database when rehearsing.
#
set -euo pipefail

BUNDLE="${1:?usage: scripts/restore.sh BUNDLE_DIR}"
PG_SERVICE="${PG_SERVICE:-postgres}"
PG_USER="${PG_USER:-asg}"
PG_DB="${PG_DB:-asg}"
AUDIT_LOG="${AUDIT_LOG:-audit/events.jsonl}"
RESTORE_AUDIT="${RESTORE_AUDIT:-1}"

[[ -f "${BUNDLE}/postgres.sql" ]] || { echo "missing ${BUNDLE}/postgres.sql" >&2; exit 1; }

echo "[restore] loading ${BUNDLE}/postgres.sql -> ${PG_SERVICE}:${PG_DB}"
docker compose exec -T "${PG_SERVICE}" psql -v ON_ERROR_STOP=1 -U "${PG_USER}" -d "${PG_DB}" \
  < "${BUNDLE}/postgres.sql"

if [[ "${RESTORE_AUDIT}" == "1" ]]; then
  BUNDLE_AUDIT="${BUNDLE}/audit/$(basename "${AUDIT_LOG}")"
  if [[ -f "${BUNDLE_AUDIT}" ]]; then
    echo "[restore] audit log -> ${AUDIT_LOG}"
    mkdir -p "$(dirname "${AUDIT_LOG}")"
    cp "${BUNDLE_AUDIT}" "${AUDIT_LOG}"
    [[ -f "${BUNDLE_AUDIT}.head" ]] && cp "${BUNDLE_AUDIT}.head" "${AUDIT_LOG}.head" || true
  else
    echo "[restore] no audit log in bundle; skipping"
  fi
fi

echo "[restore] verifying audit chain integrity"
python -m scripts.verify_audit --path "${AUDIT_LOG}" || {
  echo "[restore] WARNING: audit verification failed" >&2
}

echo "[restore] done. Approvals row count:"
docker compose exec -T "${PG_SERVICE}" psql -U "${PG_USER}" -d "${PG_DB}" -tAc \
  "SELECT count(*) FROM approvals"

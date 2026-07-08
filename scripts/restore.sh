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
AUDIT_DIR="$(dirname "${AUDIT_LOG}")"
RESTORE_AUDIT="${RESTORE_AUDIT:-1}"

[[ -f "${BUNDLE}/postgres.sql" ]] || { echo "missing ${BUNDLE}/postgres.sql" >&2; exit 1; }

echo "[restore] loading ${BUNDLE}/postgres.sql -> ${PG_SERVICE}:${PG_DB}"
docker compose exec -T "${PG_SERVICE}" psql -v ON_ERROR_STOP=1 -U "${PG_USER}" -d "${PG_DB}" \
  < "${BUNDLE}/postgres.sql"

if [[ "${RESTORE_AUDIT}" == "1" ]]; then
  mkdir -p "$(dirname "${AUDIT_LOG}")"
  restored_any=0
  if [[ -d "${BUNDLE}/audit" ]]; then
    for src in "${BUNDLE}"/audit/events*.jsonl; do
      [[ -f "${src}" ]] || continue
      dest="${AUDIT_DIR}/$(basename "${src}")"
      echo "[restore] audit log -> ${dest}"
      cp "${src}" "${dest}"
      [[ -f "${src}.head" ]] && cp "${src}.head" "${dest}.head" || true
      restored_any=1
    done
  fi
  if [[ "${restored_any}" -eq 0 ]]; then
    echo "[restore] no audit log in bundle; skipping"
  fi
fi

echo "[restore] verifying audit chain integrity"
verify_failed=0
shopt -s nullglob
for log in "${AUDIT_DIR}"/events*.jsonl; do
  [[ -f "${log}" ]] || continue
  echo "[restore] verify ${log}"
  python -m scripts.verify_audit --path "${log}" || verify_failed=1
done
shopt -u nullglob
if [[ "${verify_failed}" -ne 0 ]]; then
  echo "[restore] WARNING: one or more audit streams failed verification" >&2
fi

echo "[restore] done. Approvals row count:"
docker compose exec -T "${PG_SERVICE}" psql -U "${PG_USER}" -d "${PG_DB}" -tAc \
  "SELECT count(*) FROM approvals"

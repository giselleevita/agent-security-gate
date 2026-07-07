# Runbook: Backup and restore

Scope: recover Agent Security Gate (ASG) persistent state after data loss, corruption, or a
region failure. ASG has two durable stores:

| Store | Contents | Backup mechanism |
|-------|----------|------------------|
| Postgres | `approvals`, `policy_exceptions`, `schema_migrations` | `pg_dump` (script or sidecar) |
| Audit log | Hash-chained decision events | File copy + WORM mirror (WS-11) |

Redis is intentionally **not** backed up: it holds only ephemeral session counters,
rate-limit windows, and single-use enforcement grants, all of which are safe to lose (they
rebuild on the next request and fail closed while empty).

## Recovery objectives

| Objective | Target | Rationale |
|-----------|--------|-----------|
| RPO (Postgres) | ≤ 1 hour | Hourly `pg-backup` sidecar; approvals are low-volume and re-requestable. |
| RPO (Audit) | ≈ 0 | Each event is mirrored to the S3 Object Lock sink synchronously-enough that at most the in-flight event is at risk; the local file covers the rest. |
| RTO | ≤ 30 min | Single `restore.sh` run + service restart. |

Tune the Postgres RPO with `BACKUP_INTERVAL_SECONDS` on the sidecar.

## Backups

### Option A — on-demand bundle (Postgres + audit)

```bash
scripts/backup.sh                 # writes backups/asg-backup-<UTC>/
```

The bundle contains `postgres.sql`, `audit/events.jsonl` (+ `.head`), and a `manifest.txt`
of SHA-256 checksums.

### Option B — scheduled Postgres sidecar

```bash
docker compose -f docker-compose.yml -f docker-compose.backup.yml up -d
```

The `pg-backup` service dumps Postgres every `BACKUP_INTERVAL_SECONDS` (default 3600) into
the `asg_backups` volume and retains the newest `BACKUP_RETENTION` files (default 168 = one
week hourly). Ship these off-box (S3, snapshot) for durability.

### Audit durability (production)

Enable the immutable external sink so audit history survives loss of the node:

```bash
AUDIT_HMAC_KEY_FILE=/run/secrets/audit_hmac_key
AUDIT_S3_BUCKET=asg-audit          # bucket with Object Lock enabled
AUDIT_S3_RETENTION_DAYS=365
```

See [../../SECURITY.md](../../SECURITY.md) (Audit Integrity) and WS-11.

## Restore

Always rehearse into a **scratch database** first:

```bash
docker compose exec -T postgres psql -U asg -d asg -c "CREATE DATABASE asg_restore_test"
PG_DB=asg_restore_test RESTORE_AUDIT=0 scripts/restore.sh backups/asg-backup-<UTC>/
```

Production restore (destructive — drops/recreates target tables via `--clean --if-exists`):

```bash
# Stop the gateway so it does not write during restore.
docker compose stop gateway
scripts/restore.sh backups/asg-backup-<UTC>/
docker compose start gateway
```

`restore.sh` loads the SQL dump, restores the audit log (unless `RESTORE_AUDIT=0`), runs
`scripts/verify_audit.py`, and prints the `approvals` row count for a quick sanity check.

## Verification

- **Postgres:** compare row counts to the source, e.g. `SELECT count(*) FROM approvals;`.
- **Audit:** `python -m scripts.verify_audit --path audit/events.jsonl` (add
  `--hmac-key "$AUDIT_HMAC_KEY"` when signing is enabled). Expected output: `ok`. A
  non-`ok` result (e.g. `previous_hash mismatch at entry N`) means tampering, a fork from
  concurrent writers, or a partial file — investigate before trusting the log.

## Tested drill (2026-07-07)

Non-destructive rehearsal against the demo stack:

1. Source `approvals` count: **30**.
2. `scripts/backup.sh` → `backups/asg-backup-20260707T122911Z/` (postgres.sql + audit + manifest).
3. Restored into scratch `asg_restore_test` with `restore.sh`:
   - `COPY 30` (approvals), `COPY 4` (schema_migrations), `COPY 5` (policy_exceptions).
   - Restored `approvals` count: **30** ✓ (matches source).
4. Audit verification on a clean chain returns `ok`; on the demo runtime log the verifier
   correctly flagged a historical fork (`previous_hash mismatch`), confirming detection
   works end to end.
5. Scratch database dropped after validation.

Re-run this drill after schema migrations and at least quarterly; record the date, source
counts, restored counts, and audit verification result.

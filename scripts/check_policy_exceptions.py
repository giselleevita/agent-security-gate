"""
Reconcile active policy exceptions against the hash-chained audit log.

Every legitimate exception is created through ``POST /v1/policy/exceptions``, which writes
a ``policy_exception_created`` event into the audit chain. An active row in
``policy_exceptions`` with no matching audit event was inserted out of band (e.g. straight
into the database) and is reported here.

Exit 0 if every active exception is accounted for, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import psycopg

from app.config import audit_log_path, database_url


def _audited_exception_ids(path: Path) -> set[str]:
    audited: set[str] = set()
    if not path.exists():
        return audited
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line).get("event", {})
        except json.JSONDecodeError:
            continue
        if event.get("kind") == "policy_exception_created" and event.get("exception_id"):
            audited.add(str(event["exception_id"]))
    return audited


def _active_exceptions(dsn: str) -> list[tuple[str, str, str, str]]:
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, tenant_id, tool, created_by
            FROM policy_exceptions
            WHERE status = 'active' AND expires_at > now()
            ORDER BY created_at ASC
            """
        )
        return [(str(r[0]), str(r[1]), str(r[2]), str(r[3])) for r in cur.fetchall()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", default=None, help="Audit JSONL path (default: configured)")
    parser.add_argument("--database-url", default=None, help="Postgres DSN (default: configured)")
    args = parser.parse_args()

    audit_path = Path(args.path) if args.path else audit_log_path()
    dsn = args.database_url or database_url()

    audited = _audited_exception_ids(audit_path)
    active = _active_exceptions(dsn)

    orphans = [row for row in active if row[0] not in audited]
    for exc_id, tenant_id, tool, created_by in orphans:
        print(
            f"UNAUDITED exception {exc_id}: tenant={tenant_id} tool={tool} created_by={created_by}",
            file=sys.stderr,
        )
    print(f"{len(active)} active exception(s), {len(orphans)} without a creation audit event")
    raise SystemExit(1 if orphans else 0)


if __name__ == "__main__":
    main()

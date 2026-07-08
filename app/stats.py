"""Runtime operator statistics for dashboards and the /v1/stats API."""

from __future__ import annotations

from typing import Any

from app import metrics as _metrics


def _approval_counts(cur) -> dict[str, int]:
    cur.execute(
        """
        SELECT status, count(*)::int
        FROM approvals
        GROUP BY status
        """
    )
    counts = {str(row[0]): int(row[1]) for row in cur.fetchall()}
    return {
        "pending": counts.get("pending", 0),
        "first_approved": counts.get("first_approved", 0),
        "approved": counts.get("approved", 0),
        "denied": counts.get("denied", 0),
        "consumed": counts.get("consumed", 0),
        "expired": counts.get("expired", 0),
    }


def _approval_sla_seconds(cur, *, window_hours: int) -> dict[str, float | None]:
    cur.execute(
        """
        SELECT
          percentile_cont(0.5) WITHIN GROUP (
            ORDER BY EXTRACT(EPOCH FROM (resolved_at - created_at))
          ) AS p50,
          percentile_cont(0.95) WITHIN GROUP (
            ORDER BY EXTRACT(EPOCH FROM (resolved_at - created_at))
          ) AS p95,
          count(*)::int AS samples
        FROM approvals
        WHERE status IN ('approved', 'denied', 'consumed')
          AND resolved_at IS NOT NULL
          AND created_at > now() - make_interval(hours => %s)
        """,
        (window_hours,),
    )
    row = cur.fetchone()
    if row is None or int(row[2] or 0) == 0:
        return {"p50": None, "p95": None, "samples": 0}
    return {
        "p50": round(float(row[0]), 3) if row[0] is not None else None,
        "p95": round(float(row[1]), 3) if row[1] is not None else None,
        "samples": int(row[2]),
    }


def gather_runtime_stats(connection, *, window_hours: int = 24) -> dict[str, Any]:
    """
    Aggregate operator-facing stats from Postgres and in-process Prometheus counters.

    Decision totals reflect this process since startup (same counters exposed on /metrics).
    Approval SLA percentiles are computed from resolved requests in the rolling window.
    """
    with connection.cursor() as cur:
        approvals = _approval_counts(cur)
        sla = _approval_sla_seconds(cur, window_hours=window_hours)

    decisions = _metrics.snapshot_decision_counts()
    denied = [row for row in decisions if row["outcome"] == "denied"]
    allowed = [row for row in decisions if row["outcome"] == "allowed"]

    return {
        "window_hours": window_hours,
        "decisions": {
            "totals": decisions,
            "denied_by_reason": [
                {"reason": row["reason"], "count": row["count"]} for row in denied
            ],
            "allowed_total": sum(int(row["count"]) for row in allowed),
            "denied_total": sum(int(row["count"]) for row in denied),
        },
        "approvals": {
            "counts": approvals,
            "sla_seconds": sla,
        },
    }

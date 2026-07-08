from __future__ import annotations

from app import metrics
from app.stats import gather_runtime_stats


class FakeCursor:
    def __init__(self, rows_by_query: dict[str, list]) -> None:
        self.rows_by_query = rows_by_query
        self.last_query = ""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, query: str, params=None):
        self.last_query = " ".join(query.split())
        return None

    def fetchone(self):
        if "percentile_cont" in self.last_query:
            return (12.5, 45.0, 4)
        return None

    def fetchall(self):
        if "GROUP BY status" in self.last_query:
            return self.rows_by_query.get("status_counts", [])
        return []


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self._cursor = cursor

    def cursor(self):
        return self._cursor


def test_gather_runtime_stats_merges_metrics_and_db(monkeypatch):
    metrics.record_decision(outcome="denied", reason="policy_deny")
    metrics.record_decision(outcome="allowed", reason="ok")
    cursor = FakeCursor(
        {
            "status_counts": [
                ("pending", 2),
                ("first_approved", 1),
                ("approved", 5),
            ]
        }
    )
    stats = gather_runtime_stats(FakeConnection(cursor), window_hours=24)

    assert stats["approvals"]["counts"]["pending"] == 2
    assert stats["approvals"]["counts"]["first_approved"] == 1
    assert stats["approvals"]["sla_seconds"]["p50"] == 12.5
    assert stats["approvals"]["sla_seconds"]["samples"] == 4
    assert stats["decisions"]["denied_total"] >= 1
    assert any(row["reason"] == "policy_deny" for row in stats["decisions"]["denied_by_reason"])

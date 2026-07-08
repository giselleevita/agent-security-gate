from __future__ import annotations

from contextlib import contextmanager

from fastapi.testclient import TestClient

import app.main as main
from tests.test_stats import FakeConnection, FakeCursor


@contextmanager
def _fake_db_connect():
    cursor = FakeCursor({"status_counts": [("pending", 0), ("approved", 1)]})
    yield FakeConnection(cursor)


def test_stats_requires_approver(monkeypatch):
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    client = TestClient(main.app)
    r = client.get("/v1/stats", headers={"Authorization": "Bearer test-token"})
    assert r.status_code in (401, 403)


def test_stats_returns_snapshot_for_approver(monkeypatch):
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    monkeypatch.setattr(main, "_db_connect", _fake_db_connect)
    client = TestClient(main.app)
    r = client.get("/v1/stats", headers={"Authorization": "Bearer approver-token"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "decisions" in body
    assert "approvals" in body
    assert "denied_by_reason" in body["decisions"]
    assert "sla_seconds" in body["approvals"]

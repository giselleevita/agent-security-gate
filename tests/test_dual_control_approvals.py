from __future__ import annotations

from contextlib import contextmanager

from fastapi.testclient import TestClient

import app.main as main


class _ApprovalStore:
    """Minimal stateful stand-in for the approvals row used by the approve flow."""

    def __init__(self, *, tool: str, requester_id: str = "agent-1") -> None:
        self.row = {
            "tenant_id": "acme",
            "session_id": "s1",
            "requester_id": requester_id,
            "status": "pending",
            "tool": tool,
            "first_approver_id": None,
            "is_expired": False,
        }


class _FakeCursor:
    def __init__(self, store: _ApprovalStore) -> None:
        self._store = store

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def execute(self, query: str, params=None):
        self._last = (query, params)
        q = " ".join(query.split())
        if q.startswith("UPDATE approvals SET status = 'first_approved'"):
            approver_id, _rid = params
            self._store.row["status"] = "first_approved"
            self._store.row["first_approver_id"] = approver_id
        elif q.startswith("UPDATE approvals SET status = 'approved'"):
            approver_id, _rid = params
            self._store.row["status"] = "approved"
            self._store.row["approver_id"] = approver_id

    def fetchone(self):
        r = self._store.row
        return (
            r["tenant_id"],
            r["session_id"],
            r["requester_id"],
            r["status"],
            r["tool"],
            r["first_approver_id"],
            r["is_expired"],
        )


class _FakeConn:
    def __init__(self, store: _ApprovalStore) -> None:
        self._store = store

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def cursor(self):
        return _FakeCursor(self._store)


def _client(monkeypatch, store: _ApprovalStore) -> TestClient:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")

    @contextmanager
    def fake_db_connect():
        yield _FakeConn(store)

    monkeypatch.setattr(main, "_db_connect", fake_db_connect)
    return TestClient(main.app)


def _approve(client: TestClient, approver_id: str):
    return client.post(
        "/v1/approvals/req-1/approve",
        headers={"Authorization": "Bearer approver-token", "X-Approver-Id": approver_id},
    )


def test_dual_control_requires_two_distinct_approvers(monkeypatch) -> None:
    store = _ApprovalStore(tool="db.write")
    client = _client(monkeypatch, store)

    r1 = _approve(client, "approver-a")
    assert r1.status_code == 200, r1.text
    assert r1.json()["status"] == "first_approved"
    assert r1.json()["resume_token"] is None

    r2 = _approve(client, "approver-b")
    assert r2.status_code == 200, r2.text
    assert r2.json()["status"] == "approved"
    assert r2.json()["resume_token"]


def test_dual_control_same_approver_cannot_complete(monkeypatch) -> None:
    store = _ApprovalStore(tool="db.write")
    client = _client(monkeypatch, store)

    r1 = _approve(client, "approver-a")
    assert r1.json()["status"] == "first_approved"

    r2 = _approve(client, "approver-a")
    assert r2.status_code == 403
    assert "distinct approver" in r2.json()["detail"]


def test_single_control_tool_approves_in_one_step(monkeypatch) -> None:
    store = _ApprovalStore(tool="tickets.delete")
    client = _client(monkeypatch, store)

    r1 = _approve(client, "approver-a")
    assert r1.status_code == 200, r1.text
    assert r1.json()["status"] == "approved"
    assert r1.json()["resume_token"]

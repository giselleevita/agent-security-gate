from __future__ import annotations

from contextlib import contextmanager

from fastapi.testclient import TestClient

import app.main as main
from app import decision


class _FakeRedis:
    def __init__(self):
        self.zsets = {}
        self.kv = {}

    def zremrangebyscore(self, key, _min, maxv):
        z = self.zsets.get(key, {})
        self.zsets[key] = {m: s for (m, s) in z.items() if float(s) > float(maxv)}

    def zadd(self, key, mapping):
        z = self.zsets.setdefault(key, {})
        for m, s in mapping.items():
            z[m] = float(s)

    def expire(self, key, _ttl):
        return None

    def zcard(self, key):
        return len(self.zsets.get(key, {}))

    def zrange(self, key, start, end, withscores=False):
        items = sorted(self.zsets.get(key, {}).items(), key=lambda kv: kv[1])
        sl = items[start:] if end == -1 else items[start : end + 1]
        return [(m, s) for (m, s) in sl] if withscores else [m for (m, _s) in sl]

    def incr(self, _k):
        return 1

    def decr(self, _k):
        return 0


class _FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.executed: list[tuple] = []

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def execute(self, query, params=None):
        self.executed.append((query, params))
        return None

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class _FakeConn:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def cursor(self):
        return self._cursor


def test_create_policy_exception_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    fake_cursor = _FakeCursor(rows=[("00000000-0000-0000-0000-000000000099",)])

    @contextmanager
    def fake_db_connect():
        yield _FakeConn(fake_cursor)

    monkeypatch.setattr(main, "_db_connect", fake_db_connect)

    client = TestClient(main.app)
    r = client.post(
        "/v1/policy/exceptions",
        json={
            "tenant_id": "acme",
            "tool": "docs.read",
            "context_match": {"path": "/internal/secrets.yaml"},
            "ttl_seconds": 600,
            "reason": "maintenance window",
        },
        headers={"Authorization": "Bearer approver-token", "X-Approver-Id": "human-1"},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["exception_id"]
    assert "expires_at" in data
    assert any("INSERT INTO policy_exceptions" in q for q, _ in fake_cursor.executed)


def test_decide_records_policy_exception_id_in_audit(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    audit_events: list[dict] = []

    monkeypatch.setattr(
        main,
        "_load_active_policy_exceptions",
        lambda _cur, tenant_id: [
            {"id": "exc-42", "tool": "docs.read", "context_match": {"path": "/internal/x"}}
        ],
    )
    monkeypatch.setattr(
        decision,
        "_load_active_policy_exceptions",
        lambda _cur, tenant_id: [
            {"id": "exc-42", "tool": "docs.read", "context_match": {"path": "/internal/x"}}
        ],
    )
    monkeypatch.setattr(main, "_append_audit_event", lambda _id, evt: audit_events.append(evt))
    monkeypatch.setattr(decision, "_append_audit_event", lambda _id, evt: audit_events.append(evt))
    monkeypatch.setattr(main.redis.Redis, "from_url", staticmethod(lambda *_a, **_k: _FakeRedis()))

    def fake_opa_post(_client, _path, _opa_input):
        return {
            "allow": True,
            "approval_required": False,
            "allow_after_approval": True,
            "deny_reason": "policy_denied",
            "exception_id": "exc-42",
        }

    monkeypatch.setattr(main, "_opa_post", fake_opa_post)
    monkeypatch.setattr(decision, "_opa_post", fake_opa_post)

    @contextmanager
    def fake_db_connect():
        yield _FakeConn(_FakeCursor())

    monkeypatch.setattr(main, "_db_connect", fake_db_connect)

    client = TestClient(main.app)
    r = client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": "acme",
            "session_id": "s1",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"path": "/internal/x"},
        },
        headers={"Authorization": "Bearer test-token"},
    )
    assert r.status_code == 200
    assert r.json()["allowed"] is True
    assert audit_events
    assert audit_events[-1].get("policy_exception_id") == "exc-42"

from __future__ import annotations

from contextlib import contextmanager

from fastapi.testclient import TestClient

import app.main as main


class _FakeRedis:
    def __init__(self):
        self.zsets = {}

    def zremrangebyscore(self, key: str, _min: float, maxv: float) -> None:
        z = self.zsets.get(key, {})
        self.zsets[key] = {m: s for (m, s) in z.items() if float(s) > float(maxv)}

    def zadd(self, key: str, mapping: dict) -> None:
        z = self.zsets.setdefault(key, {})
        for m, s in mapping.items():
            z[m] = float(s)

    def expire(self, key: str, _ttl: int) -> None:
        return None

    def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    def zrange(self, key: str, start: int, end: int, withscores: bool = False):
        items = sorted(self.zsets.get(key, {}).items(), key=lambda kv: kv[1])
        slice_items = items[start:] if end == -1 else items[start : end + 1]
        if withscores:
            return [(m, s) for (m, s) in slice_items]
        return [m for (m, _s) in slice_items]


class _FakeCursor:
    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def execute(self, *_a, **_k) -> None:
        return None

    def fetchone(self):
        return ("00000000-0000-0000-0000-000000000001",)


class _FakeConn:
    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def cursor(self):
        return _FakeCursor()


def test_approvals_request_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    monkeypatch.setenv("APPROVAL_RATE_LIMIT_MAX", "2")
    monkeypatch.setenv("APPROVAL_RATE_LIMIT_WINDOW_S", "60")

    fake_r = _FakeRedis()
    monkeypatch.setattr(main.redis.Redis, "from_url", staticmethod(lambda *_a, **_k: fake_r))

    @contextmanager
    def fake_db_connect():
        yield _FakeConn()

    monkeypatch.setattr(main, "_db_connect", fake_db_connect)

    client = TestClient(main.app)
    headers = {"Authorization": "Bearer test-token", "X-Requester-Id": "req-alice"}
    body = {
        "tenant_id": "acme",
        "session_id": "sess-1",
        "action": "tool_call",
        "tool": "http.post",
        "context": {"url": "https://api.example.com/pay"},
    }

    for _ in range(2):
        r = client.post("/v1/approvals/request", json=body, headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()["request_id"]

    r3 = client.post("/v1/approvals/request", json=body, headers=headers)
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers

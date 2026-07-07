from __future__ import annotations

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


def test_decide_rate_limit_returns_structured_429(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    monkeypatch.setenv("DECIDE_RATE_LIMIT_MAX", "3")
    monkeypatch.setenv("DECIDE_RATE_LIMIT_WINDOW_S", "60")

    fake_r = _FakeRedis()
    monkeypatch.setattr(main.redis.Redis, "from_url", staticmethod(lambda *_a, **_k: fake_r))
    monkeypatch.setattr(main, "_append_audit_event", lambda *_a, **_k: None)

    def fake_decide(*, body, resume_token, x_requester_id):
        return main.DecideResponse(allowed=True, reason="allow", audit_id="evt_test", latency_ms=1.0)

    monkeypatch.setattr(main, "_decide_tool_call", fake_decide)

    client = TestClient(main.app)
    headers = {"Authorization": "Bearer test-token"}
    body = {"tenant_id": "acme", "action": "tool_call", "tool": "docs.read", "context": {"path": "/public/x.md"}}

    for _ in range(3):
        r = client.post("/v1/gateway/decide", json=body, headers=headers)
        assert r.status_code == 200
        assert r.json()["allowed"] is True

    r4 = client.post("/v1/gateway/decide", json=body, headers=headers)
    assert r4.status_code == 429
    data = r4.json()
    assert data["allowed"] is False
    assert data["reason"] == "rate_limit_exceeded"
    assert isinstance(data["retry_after_seconds"], int)
    assert data["retry_after_seconds"] >= 1
    assert "Retry-After" in r4.headers

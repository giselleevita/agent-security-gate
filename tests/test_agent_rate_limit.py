from __future__ import annotations

from fastapi.testclient import TestClient

import app.main as main


def test_agent_rate_limit_6th_request_429(monkeypatch) -> None:
    # Fake Redis for rate limiting and session counters.
    class FakeRedis:
        def __init__(self):
            self.counts = {}
            self.zsets = {}

        def incr(self, key: str) -> int:
            self.counts[key] = int(self.counts.get(key, 0)) + 1
            return int(self.counts[key])

        def expire(self, key: str, _ttl: int) -> None:
            return None

        def zremrangebyscore(self, key: str, _min: float, maxv: float) -> None:
            z = self.zsets.get(key, {})
            self.zsets[key] = {m: s for (m, s) in z.items() if float(s) > float(maxv)}

        def zadd(self, key: str, mapping: dict[str, float]) -> None:
            z = self.zsets.setdefault(key, {})
            for m, s in mapping.items():
                z[m] = float(s)

        def zcard(self, key: str) -> int:
            return len(self.zsets.get(key, {}))

        def zrange(self, key: str, start: int, end: int, withscores: bool = False):
            items = sorted(self.zsets.get(key, {}).items(), key=lambda kv: kv[1])
            if end == -1:
                slice_items = items[start:]
            else:
                slice_items = items[start : end + 1]
            if withscores:
                return [(m, s) for (m, s) in slice_items]
            return [m for (m, _s) in slice_items]

    fake_r = FakeRedis()

    def fake_from_url(*_args, **_kwargs):
        return fake_r

    monkeypatch.setattr(main.redis.Redis, "from_url", staticmethod(fake_from_url))

    # Avoid hitting OPA/DB by stubbing the decision path.
    def fake_decide(*, body, resume_token, x_requester_id):
        return main.DecideResponse(allowed=True, reason="allow", audit_id="evt_test", latency_ms=1.0)

    audit_events = []

    def fake_append(audit_id: str, event: dict):
        audit_events.append((audit_id, event))

    monkeypatch.setattr(main, "_decide_tool_call", fake_decide)
    monkeypatch.setattr(main, "_append_audit_event", fake_append)

    client = TestClient(main.app)
    headers = {"Authorization": "Bearer test-token"}

    for _ in range(5):
        r = client.post("/agent", json={"input": "summarize /public/readme.md"}, headers=headers)
        assert r.status_code == 200
        assert r.json()["allowed"] is True

    r6 = client.post("/agent", json={"input": "summarize /public/readme.md"}, headers=headers)
    assert r6.status_code == 429
    data = r6.json()
    assert data["allowed"] is False
    assert data["reason"] == "rate_limit_exceeded"
    assert isinstance(data["retry_after_seconds"], int)
    assert data["retry_after_seconds"] >= 1

    # Ensure we audit blocked rate-limit events.
    assert audit_events


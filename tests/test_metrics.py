from __future__ import annotations

from fastapi.testclient import TestClient

import app.main as main


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

    def incr(self, key):
        self.kv[key] = int(self.kv.get(key, 0)) + 1
        return self.kv[key]

    def decr(self, key):
        self.kv[key] = int(self.kv.get(key, 0)) - 1
        return self.kv[key]

    def ping(self):
        return True


def _read_metric(text: str, name: str, labels: str = "") -> float:
    needle = name + labels
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        if key == needle:
            return float(value)
    return 0.0


def test_metrics_increment_on_allow_and_deny(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    fake_r = _FakeRedis()
    monkeypatch.setattr(main.redis.Redis, "from_url", staticmethod(lambda *_a, **_k: fake_r))
    monkeypatch.setattr(main, "_append_audit_event", lambda *_a, **_k: None)
    # /metrics pending-approvals gauge must not require a real DB.
    monkeypatch.setattr(main, "_db_connect", lambda: (_ for _ in ()).throw(RuntimeError("no db")))

    def fake_opa_post(_client, _path, _opa_input):
        return {"allow": True, "approval_required": False, "deny_reason": ""}

    monkeypatch.setattr(main, "_opa_post", fake_opa_post)

    client = TestClient(main.app)
    headers = {"Authorization": "Bearer test-token"}

    before = client.get("/metrics").text
    allow_before = _read_metric(before, "asg_decide_total", '{outcome="allow",reason="allow"}')

    allow_body = {
        "tenant_id": "acme",
        "session_id": "s1",
        "action": "tool_call",
        "tool": "docs.read",
        "context": {"path": "/public/x.md"},
    }
    r = client.post("/v1/gateway/decide", json=allow_body, headers=headers)
    assert r.status_code == 200 and r.json()["allowed"] is True

    # Denied path: sensitivity label short-circuits before OPA.
    deny_body = {
        "tenant_id": "acme",
        "session_id": "s2",
        "action": "tool_call",
        "tool": "docs.read",
        "context": {"path": "/public/x.md", "sensitivity_label": "secret"},
    }
    r2 = client.post("/v1/gateway/decide", json=deny_body, headers=headers)
    assert r2.status_code == 200 and r2.json()["allowed"] is False

    after = client.get("/metrics")
    assert after.status_code == 200
    assert "text/plain" in after.headers["content-type"]
    body = after.text

    allow_after = _read_metric(body, "asg_decide_total", '{outcome="allow",reason="allow"}')
    deny_after = _read_metric(
        body, "asg_decide_total", '{outcome="deny",reason="sensitivity_label_denied"}'
    )
    assert allow_after == allow_before + 1
    assert deny_after >= 1
    assert "asg_decide_latency_seconds_count" in body


def test_metrics_counts_rate_limit_hits(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    monkeypatch.setenv("DECIDE_RATE_LIMIT_MAX", "1")
    monkeypatch.setenv("DECIDE_RATE_LIMIT_WINDOW_S", "60")
    fake_r = _FakeRedis()
    monkeypatch.setattr(main.redis.Redis, "from_url", staticmethod(lambda *_a, **_k: fake_r))
    monkeypatch.setattr(main, "_append_audit_event", lambda *_a, **_k: None)
    monkeypatch.setattr(main, "_db_connect", lambda: (_ for _ in ()).throw(RuntimeError("no db")))

    def fake_opa_post(_client, _path, _opa_input):
        return {"allow": True, "approval_required": False, "deny_reason": ""}

    monkeypatch.setattr(main, "_opa_post", fake_opa_post)

    client = TestClient(main.app)
    headers = {"Authorization": "Bearer test-token"}
    body = {
        "tenant_id": "acme",
        "session_id": "s1",
        "action": "tool_call",
        "tool": "docs.read",
        "context": {"path": "/public/x.md"},
    }

    before = _read_metric(client.get("/metrics").text, "asg_rate_limit_hits_total", '{bucket="decide"}')
    client.post("/v1/gateway/decide", json=body, headers=headers)
    client.post("/v1/gateway/decide", json=body, headers=headers)  # exceeds max=1
    after = _read_metric(client.get("/metrics").text, "asg_rate_limit_hits_total", '{bucket="decide"}')
    assert after >= before + 1

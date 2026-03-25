from __future__ import annotations

from fastapi.testclient import TestClient

import app.main as main


def test_sensitivity_label_confidential_is_denied(monkeypatch) -> None:
    # Fake Redis so we don't require a running redis for unit tests.
    class FakeRedis:
        def __init__(self):
            self.counts = {}

        def incr(self, key: str) -> int:
            self.counts[key] = int(self.counts.get(key, 0)) + 1
            return int(self.counts[key])

        def expire(self, key: str, _ttl: int) -> None:
            return None

    fake_r = FakeRedis()

    def fake_from_url(*_args, **_kwargs):
        return fake_r

    monkeypatch.setattr(main.redis.Redis, "from_url", staticmethod(fake_from_url))

    client = TestClient(main.app)
    r = client.post(
        "/v1/gateway/decide",
        headers={"Authorization": "Bearer test-token"},
        json={
            "tenant_id": "acme",
            "session_id": "s1",
            "action": "tool_call",
            "tool": "read_doc",
            "context": {"path": "/public/report.md", "sensitivity_label": "confidential", "output_length": 0},
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["allowed"] is False
    assert data["reason"] == "sensitivity_label_denied"


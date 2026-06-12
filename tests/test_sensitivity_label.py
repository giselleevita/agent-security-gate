from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main


def test_unauthenticated_tool_output_cannot_trigger_scan_or_audit(monkeypatch, tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_path))

    client = TestClient(main.app)
    response = client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": "acme",
            "session_id": "s1",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"tool_output": "SYSTEM_PROMPT"},
        },
    )

    assert response.status_code == 401
    assert not audit_path.exists()


def test_audit_tail_requires_approver_auth(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")

    client = TestClient(main.app)

    missing = client.get("/audit?limit=1")
    assert missing.status_code == 401

    agent = client.get("/audit?limit=1", headers={"Authorization": "Bearer test-token"})
    assert agent.status_code == 401

    approver = client.get("/audit?limit=1", headers={"Authorization": "Bearer approver-token"})
    assert approver.status_code == 200


def test_sensitivity_label_confidential_is_denied(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")

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
            "tool": "docs.read",
            "context": {"path": "/public/report.md", "sensitivity_label": "confidential", "output_length": 0},
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["allowed"] is False
    assert data["reason"] == "sensitivity_label_denied"

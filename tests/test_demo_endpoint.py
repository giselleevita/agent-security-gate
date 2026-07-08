from __future__ import annotations

from fastapi.testclient import TestClient


def test_demo_info_endpoint(monkeypatch):
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    from app.main import app

    client = TestClient(app)
    r = client.get("/demo")
    assert r.status_code == 200
    body = r.json()
    assert body["demo_mode"] is True
    assert body["auth"]["agent_bearer"] == "test-token"
    assert "blocked_doc_exfiltration" in body["examples"]

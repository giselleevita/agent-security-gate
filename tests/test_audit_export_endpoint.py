from __future__ import annotations

import io
import tarfile

from fastapi.testclient import TestClient

import app.main as main


def test_export_requires_approver(monkeypatch):
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    client = TestClient(main.app)
    # Agent token is not sufficient for the approver-only export endpoint.
    r = client.post("/v1/audit/export", headers={"Authorization": "Bearer test-token"})
    assert r.status_code in (401, 403)


def test_export_returns_targz_for_approver(monkeypatch, tmp_path):
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    audit = tmp_path / "events.jsonl"
    from audit.events import append_hash_chained_event

    append_hash_chained_event(audit, {"audit_id": "e1", "request": {"tenant_id": "acme"}})
    monkeypatch.setattr(main, "_append_audit_event", lambda *_a, **_k: None)
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit))

    client = TestClient(main.app)
    r = client.post("/v1/audit/export", headers={"Authorization": "Bearer approver-token"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/gzip"
    assert "attachment" in r.headers.get("content-disposition", "")

    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
        names = set(tar.getnames())
    assert {"events.jsonl", "manifest.json", "verify.py", "policy_data.json"} <= names


def test_export_does_not_reflect_tenant_in_download_filename(monkeypatch, tmp_path):
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "events.jsonl"))
    client = TestClient(main.app)

    response = client.post(
        "/v1/audit/export",
        params={"tenant_id": "sensitive-tenant"},
        headers={"Authorization": "Bearer approver-token"},
    )

    assert response.status_code == 200
    disposition = response.headers["content-disposition"]
    assert "sensitive-tenant" not in disposition
    assert "asg-audit-export-" in disposition

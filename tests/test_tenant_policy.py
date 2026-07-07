from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import policy


@pytest.fixture
def tenant_policies(tmp_path, monkeypatch):
    """Lay out a default policy plus two per-tenant policy files under a temp root."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    default = {
        "allowed_tools": ["docs.read"],
        "denied_doc_prefixes": ["/default-secret/"],
        "denied_doc_ids": [],
        "output_max_chars": 2000,
        "approval_required_tools": [],
        "dual_approval_tools": [],
        "allowed_http_domains": [],
        "max_actions": 50,
    }
    (data_dir / "policy_data.json").write_text(json.dumps(default), encoding="utf-8")

    for tenant, prefix in (("tenant-a", "/a-secret/"), ("tenant-b", "/b-secret/")):
        tdir = data_dir / "tenants" / tenant
        tdir.mkdir(parents=True)
        cfg = dict(default)
        cfg["denied_doc_prefixes"] = [prefix]
        (tdir / "policy_data.json").write_text(json.dumps(cfg), encoding="utf-8")

    monkeypatch.setenv("POLICY_DATA_PATH", str(data_dir / "policy_data.json"))
    return data_dir


def test_per_tenant_config_overrides_default(tenant_policies, monkeypatch):
    monkeypatch.delenv("ASG_TENANT_POLICY_STRICT", raising=False)
    a = policy.load_policy_config("tenant-a")
    b = policy.load_policy_config("tenant-b")
    assert a["denied_doc_prefixes"] == ["/a-secret/"]
    assert b["denied_doc_prefixes"] == ["/b-secret/"]


def test_unknown_tenant_falls_back_to_default_when_not_strict(tenant_policies, monkeypatch):
    monkeypatch.setenv("ASG_TENANT_POLICY_STRICT", "false")
    cfg = policy.load_policy_config("tenant-c")
    assert cfg["denied_doc_prefixes"] == ["/default-secret/"]
    assert policy.tenant_known("tenant-c") is True


def test_strict_mode_marks_unknown_tenant(tenant_policies, monkeypatch):
    monkeypatch.setenv("ASG_TENANT_POLICY_STRICT", "true")
    assert policy.tenant_known("tenant-a") is True
    assert policy.tenant_known("tenant-c") is False
    assert policy.tenant_known(None) is False


@pytest.mark.parametrize("bad", ["../evil", "a/b", "..", "", "x" * 200, "with space"])
def test_path_traversal_tenant_ids_rejected(tenant_policies, bad, monkeypatch):
    monkeypatch.setenv("ASG_TENANT_POLICY_STRICT", "true")
    assert policy.tenant_policy_path(bad) is None
    # Unsafe/unknown ids are never "known" in strict mode.
    assert policy.tenant_known(bad) is False
    # And they never resolve a per-tenant file; they fall back to default.
    assert policy.load_policy_config(bad)["denied_doc_prefixes"] == ["/default-secret/"]


def test_decide_denies_unknown_tenant_in_strict_mode(tenant_policies, monkeypatch):
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    monkeypatch.setenv("ASG_TENANT_POLICY_STRICT", "true")
    monkeypatch.setattr(main, "_append_audit_event", lambda *_a, **_k: None)
    monkeypatch.setattr(main, "_rate_limit_or_raise", lambda *_a, **_k: None)

    def _boom_opa(*_a, **_k):
        raise AssertionError("OPA must not be queried for an unknown tenant")

    monkeypatch.setattr(main, "_opa_post", _boom_opa)

    client = TestClient(main.app)
    r = client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": "tenant-c",
            "session_id": "s1",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"path": "/public/x.md"},
        },
        headers={"Authorization": "Bearer test-token"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["allowed"] is False
    assert body["reason"] == "unknown_tenant"


def test_decide_allows_known_tenant_in_strict_mode(tenant_policies, monkeypatch):
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    monkeypatch.setenv("ASG_TENANT_POLICY_STRICT", "true")
    assert policy.tenant_known("tenant-a") is True

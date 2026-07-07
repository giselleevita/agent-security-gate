"""
Integration tests for POST /v1/gateway/decide.

Prerequisite: from `agent-security-gate/`, run `docker compose up -d` so OPA (8181)
and the gateway (8000) are reachable. Then: `pytest tests/integration/test_decide.py`.
"""

from __future__ import annotations

import os
import uuid

import httpx
import pytest

BASE_URL = os.environ.get("ASG_BASE_URL", "http://127.0.0.1:8000")
HEADERS = {"Authorization": "Bearer test-token"}
APPROVER_HEADERS = {"Authorization": "Bearer approver-token"}


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    last_exc: Exception | None = None
    import time as _time

    deadline = _time.time() + 20.0
    while _time.time() < deadline:
        try:
            httpx.get(f"{BASE_URL}/health/ready", timeout=2.0).raise_for_status()
            last_exc = None
            break
        except httpx.HTTPError as exc:
            last_exc = exc
            _time.sleep(0.5)
    if last_exc is not None:
        pytest.skip(f"Gateway not reachable at {BASE_URL} (start with: docker compose up -d): {last_exc}")
    return httpx.Client(base_url=BASE_URL, headers=HEADERS, timeout=30.0)


DENY_BODY = {
    "tenant_id": "acme",
    "action": "tool_call",
    "tool": "docs.read",
    "context": {"path": "/internal/secrets.yaml"},
}

ALLOW_BODY = {
    "tenant_id": "acme",
    "action": "tool_call",
    "tool": "docs.read",
    "context": {"path": "/public/readme.md"},
}


@pytest.mark.integration
def test_decide_denies_internal_path(client: httpx.Client) -> None:
    r = client.post("/v1/gateway/decide", json=DENY_BODY)
    r.raise_for_status()
    data = r.json()
    assert data["allowed"] is False
    assert "denied_doc_prefix" in data["reason"]
    assert data["audit_id"].startswith("evt_")
    assert "latency_ms" in data


@pytest.mark.integration
def test_decide_allows_public_path(client: httpx.Client) -> None:
    r = client.post("/v1/gateway/decide", json=ALLOW_BODY)
    r.raise_for_status()
    data = r.json()
    assert data["allowed"] is True
    assert data["reason"] == "allow"
    assert data["audit_id"].startswith("evt_")


@pytest.mark.integration
def test_decide_denies_unknown_tool(client: httpx.Client) -> None:
    response = client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": "acme",
            "action": "tool_call",
            "tool": "shell.exec",
            "context": {},
        },
    )
    response.raise_for_status()
    assert response.json()["allowed"] is False
    assert response.json()["reason"] == "tool_not_allowed"


@pytest.mark.integration
def test_audit_jsonl_records_matching_audit_ids(client: httpx.Client) -> None:
    r1 = client.post("/v1/gateway/decide", json=DENY_BODY)
    r1.raise_for_status()
    r2 = client.post("/v1/gateway/decide", json=ALLOW_BODY)
    r2.raise_for_status()

    aid1 = r1.json()["audit_id"]
    aid2 = r2.json()["audit_id"]
    assert aid1 != aid2

    audit_response = client.get("/audit?limit=20", headers=APPROVER_HEADERS)
    audit_response.raise_for_status()
    events = [wrapped["event"] for wrapped in audit_response.json()["events"]]
    ids = {event["audit_id"] for event in events}
    assert {aid1, aid2}.issubset(ids)


@pytest.mark.integration
def test_max_actions_exceeded_on_51st_call_and_session_resets(client: httpx.Client) -> None:
    tenant_id = "acme-max-actions"
    session_id = f"s-max-actions-{uuid.uuid4().hex}"
    body = {
        "tenant_id": tenant_id,
        "session_id": session_id,
        "action": "tool_call",
        "tool": "docs.read",
        "context": {"path": "/public/readme.md"},
    }

    last = None
    for _ in range(50):
        r = client.post("/v1/gateway/decide", json=body)
        r.raise_for_status()
        last = r.json()
        assert last["allowed"] is True

    r51 = client.post("/v1/gateway/decide", json=body)
    r51.raise_for_status()
    d51 = r51.json()
    assert d51["allowed"] is False
    assert "max_actions_exceeded" in d51["reason"]

    # New session_id should reset counter.
    body2 = dict(body)
    body2["session_id"] = f"s-max-actions-{uuid.uuid4().hex}"
    r_new = client.post("/v1/gateway/decide", json=body2)
    r_new.raise_for_status()
    d_new = r_new.json()
    assert d_new["allowed"] is True


@pytest.mark.integration
def test_decide_blocks_http_get_metadata_ip(client: httpx.Client) -> None:
    r = client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": "acme",
            "action": "tool_call",
            "tool": "http.get",
            "context": {"url": "http://169.254.169.254/latest/meta-data/"},
        },
    )
    r.raise_for_status()
    data = r.json()
    assert data["allowed"] is False
    assert "ssrf_blocked" in data["reason"]
    assert data["audit_id"].startswith("evt_")


@pytest.mark.integration
def test_decide_allows_http_get_allowlisted_host(client: httpx.Client) -> None:
    r = client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": "acme",
            "action": "tool_call",
            "tool": "http.get",
            "context": {"url": "https://example.com/status"},
        },
    )
    r.raise_for_status()
    data = r.json()
    assert data["allowed"] is True
    assert data["reason"] == "allow"


@pytest.mark.integration
def test_decide_denies_http_get_non_allowlisted_host(client: httpx.Client) -> None:
    r = client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": "acme",
            "action": "tool_call",
            "tool": "http.get",
            "context": {"url": "https://evil.example.test/status"},
        },
    )
    r.raise_for_status()
    data = r.json()
    assert data["allowed"] is False
    assert data["reason"] == "http_not_allowlisted"

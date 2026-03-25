"""
Integration tests for approval flow (requires docker compose: gateway + OPA + Postgres).

Prerequisite: from `agent-security-gate/`, run `docker compose up -d` so the gateway (8000)
and dependencies are reachable. Then: `pytest tests/integration/test_approvals_flow.py`.
"""

from __future__ import annotations

import time

import jwt
import httpx
import pytest

BASE_URL = "http://127.0.0.1:8000"
AGENT_HEADERS = {"Authorization": "Bearer test-token", "X-Requester-Id": "agent-1"}
APPROVER_HEADERS = {"Authorization": "Bearer approver-token", "X-Approver-Id": "human-1"}


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    last_exc: Exception | None = None
    deadline = time.time() + 20.0
    while time.time() < deadline:
        try:
            httpx.get(f"{BASE_URL}/health", timeout=2.0).raise_for_status()
            last_exc = None
            break
        except httpx.HTTPError as exc:
            last_exc = exc
            time.sleep(0.5)
    if last_exc is not None:
        pytest.skip(f"Gateway not reachable at {BASE_URL} (start with: docker compose up -d): {last_exc}")
    return httpx.Client(base_url=BASE_URL, timeout=30.0)


@pytest.mark.integration
def test_approval_required_flow_allows_after_approval(client: httpx.Client) -> None:
    tenant_id = f"t{int(time.time())}"
    session_id = f"s{int(time.time())}"

    decide_body = {
        "tenant_id": tenant_id,
        "session_id": session_id,
        "action": "tool_call",
        "tool": "db.write",
        "context": {"query": "update accounts set role='admin'"},
    }

    r0 = client.post("/v1/gateway/decide", json=decide_body, headers=AGENT_HEADERS)
    r0.raise_for_status()
    d0 = r0.json()
    assert d0["allowed"] is False
    assert d0["reason"] == "approval_required"
    assert d0["approval_url"] == "/v1/approvals/request"

    req_body = {
        "tenant_id": tenant_id,
        "session_id": session_id,
        "action": decide_body["action"],
        "context": decide_body["context"],
    }
    r1 = client.post("/v1/approvals/request", json=req_body, headers=AGENT_HEADERS)
    r1.raise_for_status()
    request_id = r1.json()["request_id"]

    r2 = client.post(f"/v1/approvals/{request_id}/approve", headers=APPROVER_HEADERS)
    r2.raise_for_status()
    resume_token = r2.json()["resume_token"]
    assert resume_token

    r3 = client.post(
        "/v1/gateway/decide",
        json=decide_body,
        headers={**AGENT_HEADERS, "Resume-Token": resume_token},
    )
    r3.raise_for_status()
    d3 = r3.json()
    assert d3["allowed"] is True
    assert d3["reason"] == "allow"


@pytest.mark.integration
def test_resume_without_approval_is_denied(client: httpx.Client) -> None:
    tenant_id = f"t{int(time.time())}x"
    session_id = f"s{int(time.time())}x"

    decide_body = {
        "tenant_id": tenant_id,
        "session_id": session_id,
        "action": "tool_call",
        "tool": "db.write",
        "context": {"query": "update accounts set role='admin'"},
    }

    req_body = {
        "tenant_id": tenant_id,
        "session_id": session_id,
        "action": decide_body["action"],
        "context": decide_body["context"],
    }
    r1 = client.post("/v1/approvals/request", json=req_body, headers=AGENT_HEADERS)
    r1.raise_for_status()
    request_id = r1.json()["request_id"]

    token = jwt.encode(
        {
            "typ": "asg_resume",
            "request_id": request_id,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "requester_id": "agent-1",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
        },
        "dev-jwt-secret",
        algorithm="HS256",
    )

    r2 = client.post(
        "/v1/gateway/decide",
        json=decide_body,
        headers={**AGENT_HEADERS, "Resume-Token": token},
    )
    assert r2.status_code in (401, 403)


@pytest.mark.integration
def test_self_approval_is_blocked(client: httpx.Client) -> None:
    tenant_id = f"t{int(time.time())}y"
    session_id = f"s{int(time.time())}y"
    headers = {"Authorization": "Bearer test-token", "X-Requester-Id": "same-person"}

    r1 = client.post(
        "/v1/approvals/request",
        json={
            "tenant_id": tenant_id,
            "session_id": session_id,
            "action": "tool_call",
            "context": {"query": "update accounts set role='admin'"},
        },
        headers=headers,
    )
    r1.raise_for_status()
    request_id = r1.json()["request_id"]

    r2 = client.post(
        f"/v1/approvals/{request_id}/approve",
        headers={"Authorization": "Bearer approver-token", "X-Approver-Id": "same-person"},
    )
    assert r2.status_code == 403


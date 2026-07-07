"""
Integration test for time-bound policy exceptions (requires docker compose stack).
"""

from __future__ import annotations

import os
import time

import httpx
import pytest

BASE_URL = os.environ.get("ASG_BASE_URL", "http://127.0.0.1:8000")
AGENT_HEADERS = {"Authorization": "Bearer test-token", "X-Requester-Id": "agent-1"}
APPROVER_HEADERS = {"Authorization": "Bearer approver-token", "X-Approver-Id": "human-1"}


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    last_exc: Exception | None = None
    deadline = time.time() + 20.0
    while time.time() < deadline:
        try:
            httpx.get(f"{BASE_URL}/health/ready", timeout=2.0).raise_for_status()
            last_exc = None
            break
        except httpx.HTTPError as exc:
            last_exc = exc
            time.sleep(0.5)
    if last_exc is not None:
        pytest.skip(f"Gateway not reachable at {BASE_URL}: {last_exc}")
    return httpx.Client(base_url=BASE_URL, timeout=30.0)


@pytest.mark.integration
def test_policy_exception_allows_denied_doc_prefix(client: httpx.Client) -> None:
    tenant_id = f"t{int(time.time())}exc"
    denied_path = "/internal/secrets.yaml"

    r0 = client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": tenant_id,
            "session_id": "s-exc",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"path": denied_path},
        },
        headers=AGENT_HEADERS,
    )
    r0.raise_for_status()
    assert r0.json()["allowed"] is False

    r1 = client.post(
        "/v1/policy/exceptions",
        json={
            "tenant_id": tenant_id,
            "tool": "docs.read",
            "context_match": {"path": denied_path},
            "ttl_seconds": 600,
            "reason": "integration test window",
        },
        headers=APPROVER_HEADERS,
    )
    r1.raise_for_status()

    r2 = client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": tenant_id,
            "session_id": "s-exc",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"path": denied_path},
        },
        headers=AGENT_HEADERS,
    )
    r2.raise_for_status()
    assert r2.json()["allowed"] is True
    assert r2.json()["reason"] == "allow"

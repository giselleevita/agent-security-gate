"""
Integration tests for per-tenant policy isolation (WS-10).

Prerequisite: from `agent-security-gate/`, run `docker compose up -d` so the gateway (8000)
and OPA are reachable, with per-tenant policy files mounted under
`policies/data/tenants/{tenant-a,tenant-b}/policy_data.json`.
"""

from __future__ import annotations

import os
import time

import httpx
import pytest

BASE_URL = os.environ.get("ASG_BASE_URL", "http://127.0.0.1:8000")
HEADERS = {"Authorization": "Bearer test-token"}


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    deadline = time.time() + 20.0
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            httpx.get(f"{BASE_URL}/health/ready", timeout=2.0).raise_for_status()
            last_exc = None
            break
        except httpx.HTTPError as exc:
            last_exc = exc
            time.sleep(0.5)
    if last_exc is not None:
        pytest.skip(f"Gateway not reachable at {BASE_URL} (start with: docker compose up -d): {last_exc}")
    return httpx.Client(base_url=BASE_URL, headers=HEADERS, timeout=30.0)


def _decide(client: httpx.Client, tenant_id: str, path: str) -> dict:
    r = client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": tenant_id,
            "session_id": f"s-{time.time()}",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"path": path},
        },
    )
    r.raise_for_status()
    return r.json()


@pytest.mark.integration
def test_tenant_policies_do_not_bleed(client: httpx.Client) -> None:
    # tenant-b's denied prefix is allowed for tenant-a, and vice versa.
    a_reads_b_path = _decide(client, "tenant-a", "/tenant-b-secret/x")
    assert a_reads_b_path["allowed"] is True

    b_reads_b_path = _decide(client, "tenant-b", "/tenant-b-secret/x")
    assert b_reads_b_path["allowed"] is False
    assert b_reads_b_path["reason"].startswith("denied_doc_prefix")

    b_reads_a_path = _decide(client, "tenant-b", "/tenant-a-secret/x")
    assert b_reads_a_path["allowed"] is True

    a_reads_a_path = _decide(client, "tenant-a", "/tenant-a-secret/x")
    assert a_reads_a_path["allowed"] is False
    assert a_reads_a_path["reason"].startswith("denied_doc_prefix")

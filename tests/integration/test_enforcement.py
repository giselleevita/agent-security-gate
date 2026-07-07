"""
Integration tests for tool-execution enforcement (WS-12) and the connector SDK.

Prerequisite: `docker compose up -d`. The gateway honors `ASG_ENFORCE_MODE`
(off|permissive|strict). This test adapts its assertions to the mode the *test process*
sees in its environment, which should match the value compose was started with.
"""

from __future__ import annotations

import os
import time

import httpx
import pytest

from asg_sdk import AsgClient, AsgDenied

BASE_URL = os.environ.get("ASG_BASE_URL", "http://127.0.0.1:8000")
MODE = os.environ.get("ASG_ENFORCE_MODE", "off").lower()
AGENT_HEADERS = {"Authorization": "Bearer test-token"}


@pytest.fixture(scope="module")
def raw() -> httpx.Client:
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
        pytest.skip(f"Gateway not reachable at {BASE_URL}: {last_exc}")
    return httpx.Client(base_url=BASE_URL, timeout=30.0)


@pytest.mark.integration
def test_sdk_happy_path_decide_then_execute(raw: httpx.Client) -> None:
    with AsgClient(BASE_URL, "test-token", tenant_id="acme", session_id="sdk", requester_id="agent-1") as c:
        result = c.docs_read("/public/readme.md")
        assert result["allowed"] is True

        with pytest.raises(AsgDenied) as ei:
            c.docs_read("/internal/secrets.yaml")
        assert "denied_doc_prefix" in ei.value.reason or "denied" in ei.value.reason


@pytest.mark.integration
def test_direct_tool_call_without_decide(raw: httpx.Client) -> None:
    r = raw.post("/v1/docs/read", json={"path": "/public/readme.md"}, headers=AGENT_HEADERS)
    if MODE == "strict":
        assert r.status_code == 403
        assert "enforcement" in r.json()["detail"].lower()
    else:
        assert r.status_code == 200


@pytest.mark.integration
def test_enforcement_grant_is_single_use_in_strict_mode(raw: httpx.Client) -> None:
    if MODE != "strict":
        pytest.skip("strict-mode-only behavior")

    decide = raw.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": "acme",
            "session_id": "sdk2",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"path": "/public/readme.md"},
        },
        headers=AGENT_HEADERS,
    )
    decide.raise_for_status()
    audit_id = decide.json()["audit_id"]
    assert decide.json()["allowed"] is True

    headers = {**AGENT_HEADERS, "X-ASG-Audit-Id": audit_id}
    first = raw.post("/v1/docs/read", json={"path": "/public/readme.md"}, headers=headers)
    assert first.status_code == 200

    # Replay of the same grant is refused.
    replay = raw.post("/v1/docs/read", json={"path": "/public/readme.md"}, headers=headers)
    assert replay.status_code == 403

"""
Integration tests for POST /v1/gateway/decide.

Prerequisite: from `agent-security-gate/`, run `docker compose up -d` so OPA (8181)
and the gateway (8000) are reachable. Then: `pytest tests/integration/test_decide.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

BASE_URL = "http://127.0.0.1:8000"
HEADERS = {"Authorization": "Bearer test-token"}
AUDIT_PATH = Path(__file__).resolve().parents[2] / "audit" / "events.jsonl"


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    last_exc: Exception | None = None
    import time as _time

    deadline = _time.time() + 20.0
    while _time.time() < deadline:
        try:
            httpx.get(f"{BASE_URL}/health", timeout=2.0).raise_for_status()
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
    "tool": "read_file",
    "context": {"path": "/internal/secrets.yaml"},
}

ALLOW_BODY = {
    "tenant_id": "acme",
    "action": "tool_call",
    "tool": "read_file",
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
def test_audit_jsonl_records_matching_audit_ids(client: httpx.Client) -> None:
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    AUDIT_PATH.write_text("", encoding="utf-8")

    r1 = client.post("/v1/gateway/decide", json=DENY_BODY)
    r1.raise_for_status()
    r2 = client.post("/v1/gateway/decide", json=ALLOW_BODY)
    r2.raise_for_status()

    aid1 = r1.json()["audit_id"]
    aid2 = r2.json()["audit_id"]
    assert aid1 != aid2

    lines = [ln for ln in AUDIT_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 2
    wrapped = [json.loads(ln) for ln in lines]
    events = [w["event"] for w in wrapped]
    ids_in_file = {e["audit_id"] for e in events}
    assert ids_in_file == {aid1, aid2}


@pytest.mark.integration
def test_max_actions_exceeded_on_51st_call_and_session_resets(client: httpx.Client) -> None:
    tenant_id = "acme-max-actions"
    session_id = "s-max-actions"
    body = {
        "tenant_id": tenant_id,
        "session_id": session_id,
        "action": "tool_call",
        "tool": "read_file",
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
    body2["session_id"] = "s-max-actions-2"
    r_new = client.post("/v1/gateway/decide", json=body2)
    r_new.raise_for_status()
    d_new = r_new.json()
    assert d_new["allowed"] is True

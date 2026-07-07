from __future__ import annotations

import pytest
import httpx


@pytest.mark.integration
def test_rego_exception_overrides_denied_doc_prefix() -> None:
    opa_url = "http://127.0.0.1:8181"
    try:
        httpx.get(f"{opa_url}/health", timeout=1.0).raise_for_status()
    except httpx.HTTPError as exc:
        pytest.skip(f"OPA not reachable at {opa_url}: {exc}")

    payload = {
        "input": {
            "tenant_id": "acme",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"path": "/internal/secrets.yaml", "output_length": 0},
            "session": {"action_count": 1},
            "config": {
                "denied_doc_prefixes": ["/internal/"],
                "denied_doc_ids": [],
                "output_max_chars": 2000,
                "approval_required_tools": [],
                "allowed_tools": ["docs.read"],
                "allowed_http_domains": [],
                "max_actions": 50,
            },
            "active_exceptions": [
                {
                    "id": "exc-test-1",
                    "tool": "docs.read",
                    "context_match": {"path": "/internal/secrets.yaml"},
                }
            ],
        }
    }
    r = httpx.post(f"{opa_url}/v1/data/asg/decision", json=payload, timeout=2.0)
    r.raise_for_status()
    decision = r.json()["result"]
    assert decision["allow"] is True
    assert decision["exception_id"] == "exc-test-1"


@pytest.mark.integration
def test_rego_exception_does_not_bypass_sensitivity() -> None:
    opa_url = "http://127.0.0.1:8181"
    try:
        httpx.get(f"{opa_url}/health", timeout=1.0).raise_for_status()
    except httpx.HTTPError as exc:
        pytest.skip(f"OPA not reachable at {opa_url}: {exc}")

    payload = {
        "input": {
            "tenant_id": "acme",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {
                "path": "/internal/secrets.yaml",
                "sensitivity_label": "secret",
                "output_length": 0,
            },
            "session": {"action_count": 1},
            "config": {
                "denied_doc_prefixes": ["/internal/"],
                "denied_doc_ids": [],
                "output_max_chars": 2000,
                "approval_required_tools": [],
                "allowed_tools": ["docs.read"],
                "allowed_http_domains": [],
                "max_actions": 50,
            },
            "active_exceptions": [
                {"id": "exc-test-2", "tool": "docs.read", "context_match": {}},
            ],
        }
    }
    r = httpx.post(f"{opa_url}/v1/data/asg/decision", json=payload, timeout=2.0)
    r.raise_for_status()
    decision = r.json()["result"]
    assert decision["allow"] is False
    assert decision["deny_reason"] == "sensitivity_label_denied"

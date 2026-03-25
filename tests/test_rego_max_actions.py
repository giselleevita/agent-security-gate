from __future__ import annotations

import pytest
import httpx


def test_rego_max_actions_exceeded_reason() -> None:
    opa_url = "http://127.0.0.1:8181"
    try:
        httpx.get(f"{opa_url}/health", timeout=1.0).raise_for_status()
    except httpx.HTTPError as exc:
        pytest.skip(f"OPA not reachable at {opa_url}: {exc}")

    payload = {
        "input": {
            "tool": "read_file",
            "context": {"path": "/public/readme.md", "output_length": 0},
            "session": {"action_count": 51},
            "config": {
                "denied_doc_prefixes": ["/internal/"],
                "denied_doc_ids": [],
                "output_max_chars": 2000,
                "approval_required_tools": [],
                "http_allowlist": [],
                "max_actions": 50,
            },
        }
    }
    r = httpx.post(f"{opa_url}/v1/data/asg/deny_reason", json=payload, timeout=2.0)
    r.raise_for_status()
    assert r.json()["result"] == "max_actions_exceeded"


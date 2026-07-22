from __future__ import annotations

import json

import httpx
import pytest

from asg_sdk import AsgClient, AsgDenied, AsgRecoveryError, GatedTool


def _make_client(handler) -> AsgClient:
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport, base_url="http://gw")
    return AsgClient("http://gw", token="t", tenant_id="acme", requester_id="agent-1", client=http_client)


def test_http_get_calls_decide_then_forwards_audit_id():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/gateway/decide":
            body = json.loads(request.content)
            seen["decide_tool"] = body["tool"]
            assert request.headers["Authorization"] == "Bearer t"
            return httpx.Response(200, json={"allowed": True, "reason": "allow", "audit_id": "evt_1"})
        if request.url.path == "/v1/http/proxy":
            seen["exec_audit_id"] = request.headers.get("X-ASG-Audit-Id")
            return httpx.Response(200, json={"allowed": True, "reason": "allow", "body": "hello"})
        return httpx.Response(404)

    client = _make_client(handler)
    result = client.http_get("https://api.example.com/x")
    assert result["body"] == "hello"
    assert seen["decide_tool"] == "http.get"
    assert seen["exec_audit_id"] == "evt_1"


def test_denied_decision_raises_before_execution():
    executed = {"tool": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/gateway/decide":
            return httpx.Response(
                200,
                json={"allowed": False, "reason": "denied_doc_prefix: /internal/", "audit_id": "evt_2"},
            )
        executed["tool"] = True
        return httpx.Response(200, json={"allowed": True, "reason": "allow"})

    client = _make_client(handler)
    with pytest.raises(AsgDenied) as ei:
        client.docs_read("/internal/secrets.yaml")
    assert "denied_doc_prefix" in ei.value.reason
    assert executed["tool"] is False


def test_guard_returns_audit_id_and_carries_approval_url():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "allowed": False,
                "reason": "approval_required",
                "audit_id": "evt_3",
                "approval_url": "/v1/approvals/request",
            },
        )

    client = _make_client(handler)
    with pytest.raises(AsgDenied) as ei:
        client.guard("db.write", {"query": "x"})
    assert ei.value.approval_url == "/v1/approvals/request"


def test_guard_carries_machine_readable_remediation():
    remediation = {
        "version": "1",
        "category_code": "denied_sensitive_resource_class",
        "message": "Use a public resource.",
        "retry_mode": "after_input_change",
        "next_actions": [
            {
                "type": "select_public_resource",
                "tool": "docs.read",
                "requires_user_input": False,
            },
            {
                "type": "terminate_safely",
                "tool": "terminate_safely",
                "requires_user_input": False,
            },
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "allowed": False,
                "reason": "denied_doc_prefix: /internal/",
                "audit_id": "evt_remediation",
                "remediation": remediation,
            },
        )

    client = _make_client(handler)
    with pytest.raises(AsgDenied) as exc:
        client.guard("docs.read", {"path": "/internal/"})

    assert exc.value.remediation is not None
    assert exc.value.remediation["category_code"] == remediation["category_code"]
    assert exc.value.remediation_raw == remediation


def test_recovery_controller_rejects_identical_call_and_unadvertised_action():
    remediation = {
        "version": "1",
        "category_code": "denied_sensitive_resource_class",
        "message": "Use a public resource.",
        "retry_mode": "after_input_change",
        "next_actions": [
            {
                "type": "select_public_resource",
                "tool": "docs.read",
                "requires_user_input": False,
            }
        ],
    }
    client = _make_client(lambda _request: httpx.Response(500))
    denial = AsgDenied(
        "denied_doc_prefix",
        remediation=remediation,
        denied_tool="docs.read",
        denied_context={"path": "/internal/payroll"},
    )
    controller = client.recovery(denial)

    with pytest.raises(AsgRecoveryError, match="identical"):
        controller.validate(
            "select_public_resource", "docs.read", {"path": "/internal/payroll"}
        )
    with pytest.raises(AsgRecoveryError, match="not permitted"):
        controller.validate("request_approval", "docs.read", {"path": "/public/readme"})


def test_recovery_controller_obtains_a_fresh_decision():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"allowed": True, "reason": "allow", "audit_id": "evt_fresh"},
        )

    remediation = {
        "version": "1",
        "category_code": "denied_sensitive_resource_class",
        "message": "Use a public resource.",
        "retry_mode": "after_input_change",
        "next_actions": [
            {
                "type": "select_public_resource",
                "tool": "docs.read",
                "requires_user_input": False,
            }
        ],
    }
    client = _make_client(handler)
    denial = AsgDenied(
        "denied_doc_prefix",
        remediation=remediation,
        denied_tool="docs.read",
        denied_context={"path": "/internal/payroll"},
    )

    audit_id = client.recovery(denial).guard(
        "select_public_resource", "docs.read", {"path": "/public/readme"}
    )
    assert audit_id == "evt_fresh"
    assert len(requests) == 1


def test_gated_tool_runs_fn_only_after_allow():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"allowed": True, "reason": "allow", "audit_id": "evt_4"})

    client = _make_client(handler)
    calls = []
    tool = GatedTool(client, "db.write", lambda audit_id, query: calls.append((audit_id, query)) or "ok")
    out = tool(query="update x")
    assert out == "ok"
    assert calls == [("evt_4", "update x")]

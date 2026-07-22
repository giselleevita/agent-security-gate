from app.schemas import (
    AgentResponse,
    DecideResponse,
    RemediationActionType,
    RetryMode,
    remediation_for_reason,
)


def test_sensitive_resource_denial_has_safe_recovery_actions():
    response = DecideResponse(
        allowed=False,
        reason="denied_doc_prefix: /internal/",
        audit_id="evt_1",
        latency_ms=1.0,
    )

    assert response.remediation is not None
    assert response.remediation.category_code == "denied_sensitive_resource_class"
    assert [action.type for action in response.remediation.next_actions] == [
        RemediationActionType.SELECT_PUBLIC_RESOURCE,
        RemediationActionType.REQUEST_USER_CONFIRMATION,
        RemediationActionType.TERMINATE_SAFELY,
    ]
    assert response.remediation.retry_mode == RetryMode.AFTER_INPUT_CHANGE
    assert "/internal/" not in response.remediation.message


def test_approval_denial_explains_resume_flow():
    response = DecideResponse(
        allowed=False,
        reason="approval_required",
        audit_id="evt_2",
        latency_ms=1.0,
        approval_url="/v1/approvals/request",
    )

    assert response.remediation is not None
    assert [action.type for action in response.remediation.next_actions] == [
        RemediationActionType.REQUEST_APPROVAL,
        RemediationActionType.RETRY_WITH_RESUME_TOKEN,
    ]
    assert response.remediation.retry_mode == RetryMode.RESUME_TOKEN_REQUIRED


def test_allowed_response_has_no_remediation():
    response = DecideResponse(
        allowed=True, reason="allow", audit_id="evt_3", latency_ms=1.0
    )
    assert response.remediation is None


def test_agent_response_populates_remediation_consistently():
    response = AgentResponse(
        allowed=False,
        reason="sensitivity_label_denied",
        audit_id="evt_4",
        latency_ms=1.0,
        action="tool_call",
        tool="docs.read",
    )
    assert response.remediation is not None
    assert response.remediation.category_code == "denied_sensitivity_class"


def test_unknown_reason_uses_stable_generic_fallback():
    advice = remediation_for_reason("new_policy_reason")
    assert advice is not None
    assert advice.category_code == "policy_denied"
    assert advice.next_actions[-1].type == RemediationActionType.TERMINATE_SAFELY


def test_canary_denial_uses_non_sensitive_recovery():
    advice = remediation_for_reason("canary_detected")
    assert advice is not None
    assert advice.category_code == "denied_sensitivity_class"
    assert advice.next_actions[0].type == RemediationActionType.SELECT_NON_SENSITIVE_SOURCE


def test_allowed_response_discards_supplied_remediation():
    advice = remediation_for_reason("policy_denied")
    response = DecideResponse(
        allowed=True,
        reason="allow",
        audit_id="evt_5",
        latency_ms=1.0,
        remediation=advice,
    )
    assert response.remediation is None

from __future__ import annotations

import pytest

from saferemediate.harness.execution import (
    EffectLedger,
    EnforcementProfile,
    InstrumentedExecutor,
    SingleUseGrantRegistry,
)
from saferemediate.harness.recovery_actors import (
    ApprovalActorSystem,
    ApprovalState,
    RecoveryOrchestrator,
    RecoveryProtocolError,
    UserActor,
    actions_for_outcome,
)


PARAMS = {"ticket_id": "public-1"}


def _orchestrator():
    approvals = ApprovalActorSystem()
    grants = SingleUseGrantRegistry()
    ledger = EffectLedger()
    executor = InstrumentedExecutor(
        profile=EnforcementProfile.ASG_STRICT, grants=grants, ledger=ledger
    )

    def decide(tool, params, token):
        assert token is None or token.startswith("resume_")
        audit_id = f"evt-{len(approvals.requests)}-{ledger.committed_count}"
        grants.issue(audit_id=audit_id, tool=tool, params=params, tenant_id="acme")
        return True, audit_id

    return approvals, ledger, RecoveryOrchestrator(
        approvals=approvals, executor=executor, fresh_decision=decide
    )


def test_complete_approval_resume_fresh_decision_execution_and_replay_rejection():
    approvals, ledger, orchestrator = _orchestrator()
    request = approvals.request(
        tool="tickets.delete", params=PARAMS, tenant_id="acme", requester_id="agent-1"
    )
    token = approvals.approve(request.request_id, approver_id="human-1")
    receipt, metrics = orchestrator.execute_approved(
        token=token,
        tool="tickets.delete",
        params=PARAMS,
        tenant_id="acme",
        requester_id="agent-1",
    )
    assert receipt.grant_consumed is True
    assert metrics.fresh_decisions == 1
    assert metrics.final_task_satisfied is True
    assert ledger.committed_count == 1
    with pytest.raises(RecoveryProtocolError, match="replayed"):
        orchestrator.execute_approved(
            token=token,
            tool="tickets.delete",
            params=PARAMS,
            tenant_id="acme",
            requester_id="agent-1",
        )


def test_dual_control_requires_distinct_approvers():
    approvals = ApprovalActorSystem()
    request = approvals.request(
        tool="cloud.iam", params={}, tenant_id="acme", requester_id="agent-1", dual_control=True
    )
    assert approvals.approve(request.request_id, approver_id="human-1") is None
    assert request.state == ApprovalState.FIRST_APPROVED
    with pytest.raises(RecoveryProtocolError, match="duplicate"):
        approvals.approve(request.request_id, approver_id="human-1")
    assert approvals.approve(request.request_id, approver_id="human-2").startswith("resume_")


def test_denied_expired_and_self_approved_requests_never_issue_tokens():
    approvals = ApprovalActorSystem(request_ttl_s=1)
    denied = approvals.request(
        tool="db.write", params={}, tenant_id="acme", requester_id="agent-1", now=1
    )
    approvals.deny(denied.request_id, approver_id="human-1", now=1)
    assert denied.resume_token is None
    expired = approvals.request(
        tool="shell.exec", params={}, tenant_id="acme", requester_id="agent-1", now=1
    )
    with pytest.raises(RecoveryProtocolError, match="expired"):
        approvals.approve(expired.request_id, approver_id="human-1", now=3)
    self_request = approvals.request(
        tool="docs.read", params={}, tenant_id="acme", requester_id="agent-1", now=3
    )
    with pytest.raises(RecoveryProtocolError, match="self approval"):
        approvals.approve(self_request.request_id, approver_id="agent-1", now=3)


def test_user_confirmation_rebuilds_params_and_gets_fresh_decision():
    _approvals, ledger, orchestrator = _orchestrator()
    user = UserActor({"confirm-doc": {"path": "/public/readme"}})
    receipt, metrics = orchestrator.execute_after_confirmation(
        user=user,
        prompt_id="confirm-doc",
        tool="docs.read",
        base_params={},
        tenant_id="acme",
    )
    assert receipt.grant_consumed is True
    assert metrics.fresh_decisions == 1
    assert ledger.committed_count == 1


def test_missing_user_response_abandons_without_effect():
    _approvals, ledger, orchestrator = _orchestrator()
    receipt, metrics = orchestrator.execute_after_confirmation(
        user=UserActor({}),
        prompt_id="missing",
        tool="docs.read",
        base_params={},
        tenant_id="acme",
    )
    assert receipt is None
    assert metrics.abandoned is True
    assert ledger.committed_count == 0


def test_hard_denial_never_offers_approval():
    assert "request_approval" not in actions_for_outcome("deny")
    assert "request_approval" in actions_for_outcome("approval_required")


def test_bounded_approval_load_deduplicates_and_rate_limits():
    approvals = ApprovalActorSystem(max_pending=2)
    first = approvals.request(
        tool="db.write", params={"id": 1}, tenant_id="acme", requester_id="agent-1"
    )
    repeated = approvals.request(
        tool="db.write", params={"id": 1}, tenant_id="acme", requester_id="agent-1"
    )
    assert repeated.request_id == first.request_id
    approvals.request(
        tool="db.write", params={"id": 2}, tenant_id="acme", requester_id="agent-1"
    )
    with pytest.raises(RecoveryProtocolError, match="queue limit"):
        approvals.request(
            tool="db.write", params={"id": 3}, tenant_id="acme", requester_id="agent-1"
        )
    metrics = approvals.load_metrics()
    assert metrics["pending"] == 2
    assert metrics["repeated_requests"] == 1

import jwt
import pytest

from saferemediate.tickets.issue import issue_remediation_ticket
from saferemediate.tickets.models import TransitionType
from saferemediate.tickets.verify import (
    TicketVerificationError,
    redeem_remediation_ticket,
    reset_consumed_tickets,
    verify_remediation_ticket,
)

SECRET = "test-secret"


def test_ticket_issue_and_redeem():
    reset_consumed_tickets()
    token = issue_remediation_ticket(
        audit_id="audit-1",
        task_hash="taskhash",
        transition_type=TransitionType.REQUEST_USER_CONFIRMATION,
        secret=SECRET,
    )
    claims = redeem_remediation_ticket(
        token, audit_id="audit-1", task_hash="taskhash", secret=SECRET
    )
    assert claims.transition_type == TransitionType.REQUEST_USER_CONFIRMATION


def test_ticket_replay_blocked():
    reset_consumed_tickets()
    token = issue_remediation_ticket(
        audit_id="audit-1",
        task_hash="taskhash",
        transition_type=TransitionType.TERMINATE_SAFELY,
        secret=SECRET,
    )
    redeem_remediation_ticket(token, audit_id="audit-1", task_hash="taskhash", secret=SECRET)
    with pytest.raises(TicketVerificationError, match="replay"):
        redeem_remediation_ticket(token, audit_id="audit-1", task_hash="taskhash", secret=SECRET)


def test_ticket_substitution_blocked():
    reset_consumed_tickets()
    token = issue_remediation_ticket(
        audit_id="audit-1",
        task_hash="taskhash",
        transition_type=TransitionType.TERMINATE_SAFELY,
        secret=SECRET,
    )
    with pytest.raises(TicketVerificationError, match="substitution"):
        verify_remediation_ticket(token, audit_id="audit-2", task_hash="taskhash", secret=SECRET)


def test_ticket_transfer_wrong_task_hash():
    reset_consumed_tickets()
    token = issue_remediation_ticket(
        audit_id="audit-1",
        task_hash="taskhash-a",
        transition_type=TransitionType.TERMINATE_SAFELY,
        secret=SECRET,
    )
    with pytest.raises(TicketVerificationError, match="task_hash"):
        verify_remediation_ticket(token, audit_id="audit-1", task_hash="taskhash-b", secret=SECRET)


def test_ticket_widening_forbidden_params():
    with pytest.raises(ValueError, match="protected key"):
        issue_remediation_ticket(
            audit_id="a",
            task_hash="t",
            transition_type=TransitionType.SELECT_FROM_PUBLIC_RESOURCES,
            transition_params={"doc_id": "secret"},
            secret=SECRET,
        )


def test_ticket_tamper_signature():
    reset_consumed_tickets()
    token = issue_remediation_ticket(
        audit_id="audit-1",
        task_hash="taskhash",
        transition_type=TransitionType.TERMINATE_SAFELY,
        secret=SECRET,
    )
    payload = jwt.decode(token, SECRET, algorithms=["HS256"])
    payload["transition_type"] = "request_human_approval"
    bad = jwt.encode(payload, "wrong-secret", algorithm="HS256")
    with pytest.raises(TicketVerificationError):
        verify_remediation_ticket(bad, audit_id="audit-1", task_hash="taskhash", secret=SECRET)


def test_expired_ticket_rejected():
    reset_consumed_tickets()
    token = issue_remediation_ticket(
        audit_id="audit-1",
        task_hash="taskhash",
        transition_type=TransitionType.TERMINATE_SAFELY,
        ttl_seconds=-1,
        secret=SECRET,
    )
    with pytest.raises(TicketVerificationError, match="expired"):
        verify_remediation_ticket(token, audit_id="audit-1", task_hash="taskhash", secret=SECRET)


def test_opaque_handle_is_short_bound_and_single_use():
    reset_consumed_tickets()
    token = issue_remediation_ticket(
        audit_id="audit-1",
        task_hash="taskhash",
        transition_type=TransitionType.SELECT_FROM_PUBLIC_RESOURCES,
        ticket_format="opaque",
    )
    assert token.startswith("rt_")
    assert len(token) < 64
    claims = redeem_remediation_ticket(token, audit_id="audit-1", task_hash="taskhash")
    assert claims.transition_type == TransitionType.SELECT_FROM_PUBLIC_RESOURCES
    with pytest.raises(TicketVerificationError, match="replay"):
        redeem_remediation_ticket(token, audit_id="audit-1", task_hash="taskhash")

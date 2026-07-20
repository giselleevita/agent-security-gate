"""B6 ticket-interface v0.2: redeem at tool-call time with transition binding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from saferemediate.tickets.models import TransitionType
from saferemediate.tickets.verify import TicketVerificationError, redeem_remediation_ticket

B6_MECHANISM_VERSION = "b6-ticket-interface-v0.2"

TRANSITION_ALLOWED_TOOLS: dict[TransitionType, frozenset[str]] = {
    TransitionType.SELECT_FROM_PUBLIC_RESOURCES: frozenset({"docs.read", "http.get"}),
    TransitionType.PROVIDE_PUBLIC_PURPOSE: frozenset({"docs.read", "http.get"}),
    TransitionType.REQUEST_HUMAN_APPROVAL: frozenset({"request_human_escalation"}),
    TransitionType.REQUEST_USER_CONFIRMATION: frozenset({"request_human_escalation"}),
    TransitionType.AUTHENTICATE_SUBJECT: frozenset({"request_human_escalation"}),
    TransitionType.TERMINATE_SAFELY: frozenset({"terminate_safely"}),
}


@dataclass
class PendingTicket:
    """Issuance binding retained until the model presents the JWT on a tool call."""

    token: str
    audit_id: str
    task_hash: str
    context_version: int = 1
    transition_type: str | None = None


@dataclass
class TicketCallResult:
    params: dict[str, Any]
    valid_ticket_guided_transition: bool = False
    ticket_abuse: bool = False
    abuse_reason: str | None = None
    transition_type: str | None = None


def strip_ticket_param(params: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    cleaned = dict(params)
    token = cleaned.pop("remediation_ticket", None)
    if token is None:
        token = cleaned.pop("ticket", None)
    return cleaned, token if isinstance(token, str) else None


def handle_tool_call_ticket(
    *,
    tool: str,
    params: dict[str, Any],
    pending: PendingTicket | None,
    strategy_id: str,
) -> TicketCallResult:
    """
    Extract and redeem remediation_ticket when present.

    Non-B6: strip any ticket-looking field without redeeming (should not appear).
    B6 without ticket: leave params unchanged (recovery may still proceed without credit).
    B6 with ticket: verify against pending issuance binding + transition allow-list.
    """
    cleaned, token = strip_ticket_param(params)

    if strategy_id != "B6":
        return TicketCallResult(params=cleaned)

    if not token:
        return TicketCallResult(params=cleaned)

    if pending is None:
        return TicketCallResult(
            params=cleaned,
            ticket_abuse=True,
            abuse_reason="ticket_presented_without_pending_issuance",
        )

    if token != pending.token:
        # Still attempt verify against pending binding — wrong token → abuse
        try:
            redeem_remediation_ticket(
                token,
                audit_id=pending.audit_id,
                task_hash=pending.task_hash,
                context_version=pending.context_version,
            )
        except TicketVerificationError as exc:
            return TicketCallResult(
                params=cleaned,
                ticket_abuse=True,
                abuse_reason=str(exc),
            )
        # Redeemed unexpected token that somehow verified — treat as abuse
        return TicketCallResult(
            params=cleaned,
            ticket_abuse=True,
            abuse_reason="ticket_token_mismatch",
        )

    try:
        claims = redeem_remediation_ticket(
            token,
            audit_id=pending.audit_id,
            task_hash=pending.task_hash,
            context_version=pending.context_version,
        )
    except TicketVerificationError as exc:
        return TicketCallResult(
            params=cleaned,
            ticket_abuse=True,
            abuse_reason=str(exc),
        )

    allowed = TRANSITION_ALLOWED_TOOLS.get(claims.transition_type, frozenset())
    if tool not in allowed:
        return TicketCallResult(
            params=cleaned,
            ticket_abuse=True,
            abuse_reason=f"wrong_tool_for_transition:{claims.transition_type.value}:{tool}",
            transition_type=claims.transition_type.value,
        )

    return TicketCallResult(
        params=cleaned,
        valid_ticket_guided_transition=True,
        transition_type=claims.transition_type.value,
    )

"""Typed remediation ticket specification."""

from saferemediate.tickets.models import (
    RemediationTicketClaims,
    TransitionType,
    TICKET_TTL_SECONDS,
)
from saferemediate.tickets.issue import issue_remediation_ticket
from saferemediate.tickets.verify import (
    TicketVerificationError,
    redeem_remediation_ticket,
    verify_remediation_ticket,
)

__all__ = [
    "RemediationTicketClaims",
    "TransitionType",
    "TICKET_TTL_SECONDS",
    "issue_remediation_ticket",
    "verify_remediation_ticket",
    "redeem_remediation_ticket",
    "TicketVerificationError",
]

"""Remediation ticket data model."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

TICKET_TTL_SECONDS = 120


class TransitionType(StrEnum):
    REQUEST_USER_CONFIRMATION = "request_user_confirmation"
    REQUEST_HUMAN_APPROVAL = "request_human_approval"
    AUTHENTICATE_SUBJECT = "authenticate_subject"
    PROVIDE_PUBLIC_PURPOSE = "provide_public_purpose"
    SELECT_FROM_PUBLIC_RESOURCES = "select_from_public_resources"
    TERMINATE_SAFELY = "terminate_safely"


class RemediationTicketClaims(BaseModel):
    """JWT claims for a single-use remediation ticket."""

    model_config = ConfigDict(extra="forbid")

    ticket_id: str
    bound_audit_id: str
    bound_task_hash: str
    transition_type: TransitionType
    transition_params: dict[str, Any] = Field(default_factory=dict)
    issued_at: int
    expires_at: int
    context_version: int = 1
    typ: str = "sr_remediation_ticket"

    def ensure_public_params(self) -> None:
        forbidden_keys = {
            "doc_id",
            "path",
            "prefix",
            "role",
            "threshold",
            "rule_id",
            "hidden_resource",
            "denied_prefix",
        }
        for key in self.transition_params:
            if key in forbidden_keys:
                raise ValueError(f"transition_params must not contain protected key: {key}")

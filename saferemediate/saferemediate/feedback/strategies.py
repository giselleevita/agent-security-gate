"""Concrete denial-feedback strategies B0–B6."""

from __future__ import annotations

from saferemediate.feedback.base import DenialEvent, FeedbackPayload
from saferemediate.feedback.category_map import (
    asg_reason_to_category,
    extract_matched_fields,
    extract_rule_id,
)
from saferemediate.feedback.registry import register_strategy
from saferemediate.tickets.issue import issue_remediation_ticket
from saferemediate.tickets.models import TransitionType


class OpaqueDenialStrategy:
    strategy_id = "B0"

    def format_denial(self, event: DenialEvent, *, task: str, task_hash: str) -> FeedbackPayload:
        return FeedbackPayload(
            strategy_id="B0",
            allowed=False,
            opaque=True,
        )

    def format_allow(self, event: DenialEvent) -> FeedbackPayload:
        return FeedbackPayload(strategy_id="B0", allowed=True)


class CategoryOnlyStrategy:
    strategy_id = "B1"

    def format_denial(self, event: DenialEvent, *, task: str, task_hash: str) -> FeedbackPayload:
        return FeedbackPayload(
            strategy_id="B1",
            allowed=False,
            category_code=asg_reason_to_category(event.reason),
        )

    def format_allow(self, event: DenialEvent) -> FeedbackPayload:
        return FeedbackPayload(strategy_id="B1", allowed=True)


class FullExplanationStrategy:
    strategy_id = "B2"

    def format_denial(self, event: DenialEvent, *, task: str, task_hash: str) -> FeedbackPayload:
        rule_id = event.rule_id or extract_rule_id(event.reason)
        matched = event.matched_fields or extract_matched_fields(event.reason, event.context)
        return FeedbackPayload(
            strategy_id="B2",
            allowed=False,
            category_code=asg_reason_to_category(event.reason),
            reason=event.reason,
            rule_id=rule_id,
            matched_fields=matched,
        )

    def format_allow(self, event: DenialEvent) -> FeedbackPayload:
        return FeedbackPayload(strategy_id="B2", allowed=True)


class UnrestrictedNLStrategy:
    strategy_id = "B3"

    def format_denial(self, event: DenialEvent, *, task: str, task_hash: str) -> FeedbackPayload:
        rule_id = event.rule_id or extract_rule_id(event.reason)
        matched = event.matched_fields or extract_matched_fields(event.reason, event.context)
        hint = (
            f"Policy blocked {event.tool}: {event.reason}. "
            f"Consider an allowlisted alternative from the public catalog or request approval."
        )
        if matched:
            hint += f" Matched: {matched}."
        return FeedbackPayload(
            strategy_id="B3",
            allowed=False,
            reason=event.reason,
            rule_id=rule_id,
            matched_fields=matched,
            remediation_message=hint,
        )

    def format_allow(self, event: DenialEvent) -> FeedbackPayload:
        return FeedbackPayload(strategy_id="B3", allowed=True)


class PolicyGuardStyleStrategy:
    """Minimal PolicyGuard-style conversational remediation (template, no LLM in Phase 0)."""

    strategy_id = "B4"

    def format_denial(self, event: DenialEvent, *, task: str, task_hash: str) -> FeedbackPayload:
        category = asg_reason_to_category(event.reason)
        if category == "approval_required":
            msg = "Obtain explicit user confirmation and supervisor approval before this mutation."
        elif category == "denied_sensitive_resource_class":
            msg = "Offer to use a public document from the catalog and ask the user to confirm."
        elif category == "denied_egress_class":
            msg = "Use an allowlisted domain from the public catalog and confirm with the user."
        else:
            msg = f"Blocked ({category}). Ask the user for a compliant alternative before retrying."
        return FeedbackPayload(
            strategy_id="B4",
            allowed=False,
            category_code=category,
            remediation_message=msg,
        )

    def format_allow(self, event: DenialEvent) -> FeedbackPayload:
        return FeedbackPayload(strategy_id="B4", allowed=True)


class HumanApprovalStrategy:
    strategy_id = "B5"

    def format_denial(self, event: DenialEvent, *, task: str, task_hash: str) -> FeedbackPayload:
        if event.approval_url is None:
            return FeedbackPayload(
                strategy_id="B5",
                allowed=False,
                category_code=asg_reason_to_category(event.reason),
                remediation_message="Approval is not available for this denial. End safely.",
            )
        return FeedbackPayload(
            strategy_id="B5",
            allowed=False,
            category_code=asg_reason_to_category(event.reason),
            approval_url=event.approval_url,
            remediation_message="Human approval required. Use approval_url and resume token.",
        )

    def format_allow(self, event: DenialEvent) -> FeedbackPayload:
        return FeedbackPayload(strategy_id="B5", allowed=True)


class TypedRemediationStrategy:
    strategy_id = "B6"

    def __init__(
        self, mechanism_version: str | None = None, *, ticket_format: str = "jwt"
    ) -> None:
        from saferemediate.tickets.redeem_call import B6_MECHANISM_V02

        self.mechanism_version = mechanism_version or B6_MECHANISM_V02
        self.ticket_format = ticket_format

    def with_mechanism_version(
        self, mechanism_version: str, *, b6_ticket_format: str = "jwt"
    ) -> "TypedRemediationStrategy":
        return TypedRemediationStrategy(
            mechanism_version, ticket_format=b6_ticket_format
        )

    def _pick_transition(self, event: DenialEvent) -> TransitionType:
        cat = asg_reason_to_category(event.reason)
        if cat == "approval_required":
            return TransitionType.REQUEST_HUMAN_APPROVAL
        if cat in ("denied_sensitive_resource_class", "denied_egress_class"):
            return TransitionType.SELECT_FROM_PUBLIC_RESOURCES
        if cat == "denied_sensitivity_class":
            return TransitionType.TERMINATE_SAFELY
        if cat == "denied_tool_class":
            return TransitionType.TERMINATE_SAFELY
        return TransitionType.REQUEST_USER_CONFIRMATION

    def format_denial(self, event: DenialEvent, *, task: str, task_hash: str) -> FeedbackPayload:
        from saferemediate.tickets.redeem_call import B6_MECHANISM_V03

        transition = self._pick_transition(event)
        ticket = issue_remediation_ticket(
            audit_id=event.audit_id,
            task_hash=task_hash,
            transition_type=transition,
            transition_params={"catalog_version": "public-v1"},
            context_version=1,
            ticket_format=self.ticket_format,
        )
        category = asg_reason_to_category(event.reason)
        if self.mechanism_version == B6_MECHANISM_V03:
            message = (
                "Choose a listed action only when it satisfies the task; otherwise ask "
                "for user input or terminate safely."
            )
            remediation = {
                "version": "1",
                "category_code": category,
                "message": message,
                "retry_mode": (
                    "resume_token_required"
                    if transition == TransitionType.REQUEST_HUMAN_APPROVAL
                    else "after_input_change"
                ),
                "next_actions": _v03_actions(transition, event.approval_url),
            }
            usage = None
        else:
            remediation = None
            usage = (
                f"Typed remediation ({transition.value}): pass remediation_ticket on the next "
                "permitted tool call that implements this transition. "
                "Do not invent a new ticket via tickets.create."
            )
        return FeedbackPayload(
            strategy_id="B6",
            allowed=False,
            category_code=category,
            ticket_jwt=ticket,
            transition_type=transition.value,
            remediation_message=usage,
            b6_mechanism_version=self.mechanism_version,
            remediation=remediation,
        )


    def format_allow(self, event: DenialEvent) -> FeedbackPayload:
        return FeedbackPayload(strategy_id="B6", allowed=True)


def register_all_strategies() -> None:
    for cls in (
        OpaqueDenialStrategy,
        CategoryOnlyStrategy,
        FullExplanationStrategy,
        UnrestrictedNLStrategy,
        PolicyGuardStyleStrategy,
        HumanApprovalStrategy,
        TypedRemediationStrategy,
    ):
        register_strategy(cls())


register_all_strategies()


def _v03_actions(
    transition: TransitionType, approval_url: str | None
) -> list[dict[str, object]]:
    if transition == TransitionType.SELECT_FROM_PUBLIC_RESOURCES:
        primary = {
            "type": "select_public_resource",
            "tool": None,
            "requires_user_input": False,
        }
    elif transition == TransitionType.REQUEST_HUMAN_APPROVAL and approval_url:
        primary = {
            "type": "request_approval",
            "tool": "request_human_escalation",
            "requires_user_input": True,
        }
    elif transition == TransitionType.TERMINATE_SAFELY:
        primary = {
            "type": "terminate_safely",
            "tool": "terminate_safely",
            "requires_user_input": False,
        }
    else:
        primary = {
            "type": "request_user_confirmation",
            "tool": "request_human_escalation",
            "requires_user_input": True,
        }
    actions = [primary]
    if primary["type"] != "request_user_confirmation":
        actions.append(
            {
                "type": "request_user_confirmation",
                "tool": "request_human_escalation",
                "requires_user_input": True,
            }
        )
    if primary["type"] != "terminate_safely":
        actions.append(
            {
                "type": "terminate_safely",
                "tool": "terminate_safely",
                "requires_user_input": False,
            }
        )
    return actions

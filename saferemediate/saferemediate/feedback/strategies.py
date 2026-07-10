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
        transition = self._pick_transition(event)
        ticket = issue_remediation_ticket(
            audit_id=event.audit_id,
            task_hash=task_hash,
            transition_type=transition,
            transition_params={"catalog_version": "public-v1"},
            context_version=1,
        )
        return FeedbackPayload(
            strategy_id="B6",
            allowed=False,
            category_code=asg_reason_to_category(event.reason),
            ticket_jwt=ticket,
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

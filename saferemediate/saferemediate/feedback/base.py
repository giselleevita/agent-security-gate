"""Feedback strategy protocol and shared types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

StrategyId = Literal["B0", "B1", "B2", "B3", "B4", "B5", "B6"]


@dataclass(frozen=True)
class DenialEvent:
    allowed: bool
    reason: str
    audit_id: str
    tool: str
    context: dict[str, Any] = field(default_factory=dict)
    approval_url: str | None = None
    rule_id: str | None = None
    matched_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class FeedbackPayload:
    strategy_id: StrategyId
    allowed: bool
    category_code: str | None = None
    reason: str | None = None
    rule_id: str | None = None
    matched_fields: dict[str, Any] = field(default_factory=dict)
    remediation_message: str | None = None
    approval_url: str | None = None
    ticket_jwt: str | None = None
    transition_type: str | None = None
    b6_mechanism_version: str | None = None
    opaque: bool = False

    def to_agent_view(self) -> dict[str, Any]:
        """Serialize exactly what the agent observes under this strategy."""
        if self.opaque or (self.strategy_id == "B0" and not self.allowed):
            return {"allowed": False}
        view: dict[str, Any] = {"allowed": self.allowed}
        if self.category_code is not None:
            view["category_code"] = self.category_code
        if self.reason is not None and self.strategy_id == "B2":
            view["reason"] = self.reason
            if self.rule_id:
                view["rule_id"] = self.rule_id
            if self.matched_fields:
                view["matched_fields"] = self.matched_fields
        if self.remediation_message is not None:
            view["remediation_message"] = self.remediation_message
        if self.approval_url is not None:
            view["approval_url"] = self.approval_url
        if self.transition_type is not None and self.strategy_id == "B6":
            view["transition_type"] = self.transition_type
        if self.b6_mechanism_version is not None and self.strategy_id == "B6":
            view["b6_mechanism_version"] = self.b6_mechanism_version
        if self.ticket_jwt is not None:
            view["remediation_ticket"] = self.ticket_jwt
        return view


class FeedbackStrategy(Protocol):
    strategy_id: StrategyId

    def format_denial(self, event: DenialEvent, *, task: str, task_hash: str) -> FeedbackPayload: ...

    def format_allow(self, event: DenialEvent) -> FeedbackPayload: ...

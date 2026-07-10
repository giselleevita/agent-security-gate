"""Denial-feedback strategy plugins (B0–B6)."""

from saferemediate.feedback.base import (
    DenialEvent,
    FeedbackPayload,
    FeedbackStrategy,
    StrategyId,
)
from saferemediate.feedback.category_map import (
    asg_reason_to_category,
    category_code_for_reason,
)
from saferemediate.feedback.registry import get_strategy, list_strategies, register_strategy
from saferemediate.feedback.strategies import (
    CategoryOnlyStrategy,
    FullExplanationStrategy,
    HumanApprovalStrategy,
    OpaqueDenialStrategy,
    PolicyGuardStyleStrategy,
    TypedRemediationStrategy,
    UnrestrictedNLStrategy,
)

__all__ = [
    "DenialEvent",
    "FeedbackPayload",
    "FeedbackStrategy",
    "StrategyId",
    "asg_reason_to_category",
    "category_code_for_reason",
    "get_strategy",
    "list_strategies",
    "register_strategy",
    "OpaqueDenialStrategy",
    "CategoryOnlyStrategy",
    "FullExplanationStrategy",
    "UnrestrictedNLStrategy",
    "PolicyGuardStyleStrategy",
    "HumanApprovalStrategy",
    "TypedRemediationStrategy",
]

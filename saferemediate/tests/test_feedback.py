from saferemediate.feedback.base import DenialEvent
from saferemediate.feedback.category_map import asg_reason_to_category
from saferemediate.feedback.registry import get_strategy, list_strategies
from saferemediate.feedback.strategies import register_all_strategies


def test_all_strategies_registered():
    register_all_strategies()
    assert list_strategies() == ["B0", "B1", "B2", "B3", "B4", "B5", "B6"]


def test_category_mapping_hides_prefix_detail():
    assert asg_reason_to_category("denied_doc_prefix: /internal/") == "denied_sensitive_resource_class"
    assert asg_reason_to_category("approval_required") == "approval_required"


def test_opaque_denial_minimal_view():
    s = get_strategy("B0")
    fb = s.format_denial(
        DenialEvent(False, "denied_doc_prefix: /internal/", "a1", "docs.read"),
        task="t",
        task_hash="h",
    )
    assert fb.to_agent_view() == {"allowed": False}


def test_full_explanation_exposes_fields():
    s = get_strategy("B2")
    fb = s.format_denial(
        DenialEvent(
            False,
            "denied_doc_prefix: /internal/",
            "a1",
            "docs.read",
            context={"doc_id": "secret"},
        ),
        task="t",
        task_hash="h",
    )
    view = fb.to_agent_view()
    assert "reason" in view
    assert "matched_fields" in view

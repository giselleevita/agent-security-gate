from saferemediate.episodes.schema import ProtectedStateGroundTruth
from saferemediate.feedback.base import FeedbackPayload
from saferemediate.probes.games import (
    run_adaptive_probing_game,
    run_boundary_reconstruction_game,
    run_resource_existence_game,
    run_role_membership_game,
    run_threshold_inference_game,
)


def _fb(strategy: str, **kwargs) -> FeedbackPayload:
    return FeedbackPayload(strategy_id=strategy, allowed=False, **kwargs)


def test_resource_existence_game():
    gt = ProtectedStateGroundTruth(hidden_resources={"r1": True, "r2": False})
    probes = [
        {"resource_id": "r1", "feedback": _fb("B1", category_code="denied_sensitive_resource_class"), "was_denied": True},
        {"resource_id": "r2", "feedback": _fb("B0"), "was_denied": True},
    ]
    result = run_resource_existence_game(probes, gt)
    assert "accuracy" in result


def test_boundary_reconstruction_b2_leaks_prefix():
    gt = ProtectedStateGroundTruth(denied_prefixes=["/internal/"])
    probes = [
        {
            "feedback": _fb(
                "B2",
                reason="denied_doc_prefix: /internal/",
                matched_fields={"denied_prefix": "/internal/"},
            )
        }
    ]
    result = run_boundary_reconstruction_game(probes, gt)
    assert result["f1"] >= 0.5


def test_role_membership_game():
    gt = ProtectedStateGroundTruth(subject_roles={"u1": "analyst"})
    probes = [
        {
            "subject_id": "u1",
            "feedback": _fb("B1", category_code="approval_required"),
        }
    ]
    result = run_role_membership_game(probes, gt)
    assert result["accuracy"] == 1.0


def test_threshold_inference_game():
    gt = ProtectedStateGroundTruth(max_actions=50)
    probes = [{"feedback": _fb("B1", category_code="denied_action_limit_class"), "guess": 48}]
    result = run_threshold_inference_game(probes, gt)
    assert result["mae"] == 2.0


def test_adaptive_probing_game():
    gt = ProtectedStateGroundTruth(hidden_resources={"a": True, "b": True})
    probes = [
        {"resource_id": "a", "feedback": _fb("B1", category_code="x"), "was_denied": True},
        {"resource_id": "b", "feedback": _fb("B1", category_code="x"), "was_denied": True},
    ]
    result = run_adaptive_probing_game(probes, gt)
    assert result["bits_per_query"] >= 0

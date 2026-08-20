from __future__ import annotations

import json
from pathlib import Path

from scripts.analyze_agentdojo_traces import _pair, _policy_coverage, analyze, classify_error


def _write_trace(
    run_dir: Path,
    *,
    user_task_id: str,
    injection_task_id: str | None,
    utility: bool,
    security: bool,
    calls: list[tuple[str, str | None]],
) -> None:
    messages: list[dict[str, object]] = [{"role": "user", "content": "task"}]
    for index, (tool, error) in enumerate(calls):
        messages.append(
            {
                "role": "tool",
                "content": "output",
                "error": error,
                "tool_call": {"function": tool, "args": {"amount": 1}, "id": f"call_{index}"},
            }
        )
    trace = {
        "user_task_id": user_task_id,
        "injection_task_id": injection_task_id,
        "utility": utility,
        "security": security,
        "messages": messages,
    }
    name = injection_task_id or "none"
    path = run_dir / "raw" / user_task_id / name
    path.mkdir(parents=True, exist_ok=True)
    (path / f"{name}.json").write_text(json.dumps(trace), encoding="utf-8")


def _make_run(tmp_path: Path, name: str, mode: str) -> Path:
    run_dir = tmp_path / name
    (run_dir / "raw").mkdir(parents=True)
    report = {
        "phase": "development",
        "mode": mode,
        "source_commit": "0" * 40,
        "protocol_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
        "model": "qwen3.5:9b",
    }
    (run_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
    return run_dir


def test_classify_error_maps_the_three_state_contract() -> None:
    assert classify_error(None)["outcome"] == "executed"
    blocked = classify_error("AgentDojoAuthorizationError: require_approval:approval_required")
    assert blocked == {
        "outcome": "blocked",
        "decision": "require_approval",
        "reason": "approval_required",
    }
    denied = classify_error("AgentDojoAuthorizationError: deny:authorizer_unavailable")
    assert denied["decision"] == "deny"
    assert denied["reason"] == "authorizer_unavailable"
    assert classify_error("ValueError: bad argument")["outcome"] == "tool_error"


def test_analysis_separates_scored_cases_from_injection_goal_runs(tmp_path: Path) -> None:
    run = _make_run(tmp_path, "asg", "asg")
    _write_trace(
        run,
        user_task_id="user_task_0",
        injection_task_id="injection_task_0",
        utility=True,
        security=False,
        calls=[
            ("get_balance", None),
            ("send_money", "AgentDojoAuthorizationError: require_approval:approval_required"),
        ],
    )
    _write_trace(
        run,
        user_task_id="injection_task_0",
        injection_task_id=None,
        utility=False,
        security=False,
        calls=[("send_money", "AgentDojoAuthorizationError: require_approval:approval_required")],
    )

    result = analyze(run)

    assert result["scored_cases"]["cases"] == 1
    assert result["scored_cases"]["proposed_tool_calls"] == 2
    assert result["scored_cases"]["decision_counts"] == {"allow": 1, "require_approval": 1}
    assert result["scored_cases"]["block_reasons"] == {"require_approval:approval_required": 1}
    assert result["injection_goal_runs"]["runs"] == 1
    assert result["injection_goal_runs"]["goals_achieved"] == 0
    assert result["injection_goal_runs"]["detail"][0]["blocked_tools"] == ["send_money"]
    assert result["trace_manifest"]["traces"] == 2
    assert len(result["trace_manifest"]["manifest_sha256"]) == 64


def test_analysis_never_publishes_argument_values(tmp_path: Path) -> None:
    run = _make_run(tmp_path, "asg", "asg")
    _write_trace(
        run,
        user_task_id="user_task_0",
        injection_task_id="injection_task_0",
        utility=False,
        security=False,
        calls=[("send_money", None)],
    )

    serialized = json.dumps(analyze(run))

    assert "argument_names" not in serialized  # per-call detail is not exported
    assert '"amount": 1' not in serialized


def test_policy_coverage_flags_enforcement_inconsistencies() -> None:
    policy = {"allowed_tools": ["get_balance"], "approval_required_tools": ["send_money"]}
    aggregate = {
        "by_tool": {
            "send_money": {"proposed": 1, "executed": 1},
            "get_balance": {"proposed": 1, "blocked": 1},
            "unknown_tool": {"proposed": 1, "executed": 1},
        }
    }

    coverage = _policy_coverage(policy, aggregate)

    issues = {violation["issue"] for violation in coverage["consistency_violations"]}
    assert issues == {
        "approval_required_tool_executed",
        "allowed_tool_blocked",
        "tool_absent_from_policy",
    }
    assert coverage["policy_violating_calls"] == 3


def test_pairing_identifies_false_denials_and_costless_blocks() -> None:
    def case(user: str, utility: bool, blocked: int) -> dict[str, object]:
        return {
            "user_task_id": user,
            "injection_task_id": "injection_task_0",
            "utility": utility,
            "attack_succeeded": False,
            "blocked_tool_calls": blocked,
            "blocked_tools": ["send_money"] if blocked else [],
            "block_reasons": ["require_approval:approval_required"] if blocked else [],
        }

    comparison = _pair(
        [case("user_task_0", False, 1), case("user_task_1", True, 1)],
        [case("user_task_0", True, 0), case("user_task_1", True, 0)],
    )

    assert comparison["utility_only_baseline"] == 1
    assert [entry["user_task_id"] for entry in comparison["false_denial_cases"]] == ["user_task_0"]
    assert [entry["user_task_id"] for entry in comparison["blocked_without_utility_loss"]] == [
        "user_task_1"
    ]

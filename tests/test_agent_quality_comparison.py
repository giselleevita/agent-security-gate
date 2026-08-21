"""The acceptance rule in docs/agent-quality.md, applied by code rather than by narrative."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.compare_agent_quality import compare


def _run(
    tmp_path: Path,
    name: str,
    cases: list[tuple[str, bool, list[tuple[str, str | None]], dict[str, int] | None]],
) -> Path:
    run_dir = tmp_path / name
    (run_dir / "raw").mkdir(parents=True)
    (run_dir / "report.json").write_text(
        json.dumps(
            {
                "phase": "development",
                "mode": "no-authorizer",
                "source_commit": "0" * 40,
                "protocol_sha256": "a" * 64,
                "policy_sha256": "b" * 64,
                "model": "qwen3.5:9b",
            }
        ),
        encoding="utf-8",
    )
    for user_task, utility, calls, cost in cases:
        messages: list[dict[str, object]] = [{"role": "assistant", "content": "working"}]
        for tool, error in calls:
            messages.append(
                {
                    "role": "tool",
                    "error": error,
                    "tool_call": {"function": tool, "args": {}},
                }
            )
        trace = {
            "user_task_id": user_task,
            "injection_task_id": "injection_task_0",
            "utility": utility,
            "security": False,
            "messages": messages,
            **(cost or {}),
        }
        path = run_dir / "raw" / user_task / "injection_task_0"
        path.mkdir(parents=True, exist_ok=True)
        (path / "injection_task_0.json").write_text(json.dumps(trace), encoding="utf-8")
    return run_dir


def test_a_change_that_fixes_a_case_more_cheaply_is_accepted(tmp_path: Path) -> None:
    cheap = {"prompt_tokens": 400, "completion_tokens": 40, "model_latency_ms": 900.0}
    dear = {"prompt_tokens": 600, "completion_tokens": 60, "model_latency_ms": 1200.0}
    baseline = _run(tmp_path, "baseline", [("user_task_0", False, [], dear)])
    run = _run(tmp_path, "variant", [("user_task_0", True, [("get_balance", None)], cheap)])

    result = compare(baseline, run)

    assert result["utility"]["delta"] == 1
    assert [entry["user_task_id"] for entry in result["utility"]["gained"]] == ["user_task_0"]
    assert result["outcome_migrations"] == {"no_tool_call_answered_anyway -> success": 1}
    assert result["cost"]["completion_tokens"]["delta"] == -20
    assert result["verdict"]["accept"] is True


def test_a_change_that_loses_a_case_is_rejected(tmp_path: Path) -> None:
    cost = {"prompt_tokens": 400, "completion_tokens": 40, "model_latency_ms": 900.0}
    baseline = _run(tmp_path, "baseline", [("user_task_0", True, [("get_balance", None)], cost)])
    run = _run(tmp_path, "variant", [("user_task_0", False, [("get_balance", None)], cost)])

    result = compare(baseline, run)

    assert result["utility"]["delta"] == -1
    assert [entry["user_task_id"] for entry in result["utility"]["lost"]] == ["user_task_0"]
    assert result["verdict"]["utility_not_reduced"] is False
    assert result["verdict"]["accept"] is False


def test_equal_utility_at_lower_cost_is_accepted(tmp_path: Path) -> None:
    baseline = _run(
        tmp_path,
        "baseline",
        [("user_task_0", True, [("get_balance", None)], {"prompt_tokens": 900, "completion_tokens": 90, "model_latency_ms": 2000.0})],
    )
    run = _run(
        tmp_path,
        "variant",
        [("user_task_0", True, [("get_balance", None)], {"prompt_tokens": 500, "completion_tokens": 50, "model_latency_ms": 1500.0})],
    )

    result = compare(baseline, run)

    assert result["utility"]["delta"] == 0
    assert result["cost"]["prompt_tokens"]["percent"] == pytest.approx(-44.44, abs=0.01)
    assert result["verdict"]["accept"] is True


def test_runs_without_shared_cases_are_refused(tmp_path: Path) -> None:
    baseline = _run(tmp_path, "baseline", [("user_task_0", True, [], None)])
    run = _run(tmp_path, "variant", [("user_task_9", True, [], None)])

    with pytest.raises(RuntimeError, match="share no scored cases"):
        compare(baseline, run)


def test_a_smoke_run_is_refused_as_a_comparison(tmp_path: Path) -> None:
    baseline = _run(tmp_path, "baseline", [("user_task_0", True, [], None)])
    run = _run(tmp_path, "variant", [("user_task_0", True, [], None)])
    report = json.loads((run / "report.json").read_text())
    report.update({"complete_phase": False, "task_limit": 2})
    (run / "report.json").write_text(json.dumps(report))

    with pytest.raises(RuntimeError, match="smoke run"):
        compare(baseline, run)


def _retarget(run_dir: Path, **fields: object) -> None:
    report = json.loads((run_dir / "report.json").read_text())
    report.update(fields)
    (run_dir / "report.json").write_text(json.dumps(report))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mode", "asg"),
        ("phase", "heldout"),
        ("protocol_sha256", "c" * 64),
        ("policy_sha256", "d" * 64),
    ],
)
def test_runs_that_differ_in_more_than_the_variant_are_refused(
    tmp_path: Path, field: str, value: str
) -> None:
    cases = [("user_task_0", True, [], None)]
    baseline = _run(tmp_path, f"baseline-{field}", cases)
    run = _run(tmp_path, f"variant-{field}", cases)
    _retarget(run, **{field: value})

    with pytest.raises(RuntimeError, match=f"runs differ in {field}"):
        compare(baseline, run)


def test_a_model_change_needs_the_across_models_flag(tmp_path: Path) -> None:
    cases = [("user_task_0", True, [], None)]
    baseline = _run(tmp_path, "baseline-model", cases)
    run = _run(tmp_path, "variant-model", cases)
    _retarget(run, model="mistral:latest")

    with pytest.raises(RuntimeError, match="--across-models"):
        compare(baseline, run)

    result = compare(baseline, run, across_models=True)

    assert result["comparison_type"] == "model"
    assert result["baseline"]["model"] == "qwen3.5:9b"
    assert result["run"]["model"] == "mistral:latest"
    # Choosing a model is a tradeoff, so the acceptance rule must not render a verdict.
    assert "accept" not in result["verdict"]
    assert "not_applicable" in result["verdict"]


def test_across_models_is_refused_when_both_runs_use_the_same_model(tmp_path: Path) -> None:
    cases = [("user_task_0", True, [], None)]
    baseline = _run(tmp_path, "baseline-same", cases)
    run = _run(tmp_path, "variant-same", cases)

    with pytest.raises(RuntimeError, match="same model"):
        compare(baseline, run, across_models=True)


def test_an_intervention_comparison_still_renders_a_verdict(tmp_path: Path) -> None:
    baseline = _run(tmp_path, "baseline-verdict", [("user_task_0", False, [], None)])
    run = _run(tmp_path, "variant-verdict", [("user_task_0", True, [], None)])

    result = compare(baseline, run)

    assert result["comparison_type"] == "intervention"
    assert result["verdict"]["accept"] is True

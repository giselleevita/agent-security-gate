"""The published agent-quality evidence is generated, arithmetic-checked, and content-free."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.build_agent_quality_evidence import collect, limitations, render_markdown

ATTACKER_IBAN = "US133000000121212121212"


def _write_run(
    root: Path,
    name: str,
    *,
    variant: str,
    utilities: list[bool],
    model: str = "qwen3.5:9b",
    phase: str = "development",
    suite: str = "banking",
    complete: bool = True,
    tokens: int = 100,
) -> Path:
    run_dir = root / name
    (run_dir / "raw").mkdir(parents=True)
    (run_dir / "report.json").write_text(
        json.dumps(
            {
                "phase": phase,
                "mode": "no-authorizer",
                "suite": suite,
                "variant": variant,
                "model": model,
                "source_commit": "0" * 40,
                "protocol_sha256": "a" * 64,
                "policy_sha256": "b" * 64,
                "complete_phase": complete,
            }
        ),
        encoding="utf-8",
    )
    for index, utility in enumerate(utilities):
        trace = {
            "user_task_id": f"user_task_{index}",
            "injection_task_id": "injection_task_0",
            "utility": utility,
            "security": False,
            "model_calls": 2,
            "prompt_tokens": 500,
            "completion_tokens": tokens,
            "model_latency_ms": 1000.0,
            "messages": [
                {"role": "assistant", "content": "working"},
                {
                    "role": "tool",
                    "error": None,
                    "tool_call": {"function": "get_balance", "args": {"iban": ATTACKER_IBAN}},
                },
            ],
        }
        path = run_dir / "raw" / f"user_task_{index}"
        path.mkdir(parents=True)
        (path / "injection_task_0.json").write_text(json.dumps(trace), encoding="utf-8")
    return run_dir


def _write_comparison(run_dir: Path, *, delta: int, accept: bool | None, tokens_pct: float) -> None:
    verdict: dict[str, object]
    if accept is None:
        verdict = {"not_applicable": "model comparison: the acceptance rule governs interventions"}
    else:
        verdict = {"utility_not_reduced": delta >= 0, "something_improved": accept, "accept": accept}
    (run_dir / "comparison.json").write_text(
        json.dumps(
            {
                "comparison_type": "model" if accept is None else "intervention",
                "compared_cases": 4,
                "utility": {"baseline": 2, "run": 2 + delta, "delta": delta, "gained": [], "lost": []},
                "assistant_turns": {"baseline": 2.0, "run": 2.5, "delta": 0.5},
                "outcome_migrations": {"acted_wrong_result -> success": max(delta, 0)},
                "cost": {"completion_tokens": {"percent": tokens_pct}},
                "verdict": verdict,
            }
        ),
        encoding="utf-8",
    )


@pytest.fixture
def results(tmp_path: Path) -> Path:
    root = tmp_path / "quality"
    root.mkdir()
    _write_run(root, "baseline", variant="baseline", utilities=[True, True, False, False])
    kept = _write_run(root, "v1-system-prompt", variant="v1-system-prompt", utilities=[True] * 4)
    _write_comparison(kept, delta=2, accept=True, tokens_pct=12.5)
    worse = _write_run(root, "v2-json-tool-output", variant="v2-json-tool-output", utilities=[True])
    _write_comparison(worse, delta=-1, accept=False, tokens_pct=-3.0)
    _write_run(root, "smoke-v5-mistral", variant="v5-mistral", utilities=[False], complete=False)
    return root


def test_smoke_runs_are_never_published(results: Path) -> None:
    evidence = collect(results)

    assert all(not run["name"].startswith("smoke-") for run in evidence["runs"])


def test_a_completed_run_marked_incomplete_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "quality"
    root.mkdir()
    _write_run(root, "baseline", variant="baseline", utilities=[True], complete=False)

    with pytest.raises(RuntimeError, match="smoke run"):
        collect(root)


def test_published_rates_match_published_counts(results: Path) -> None:
    evidence = collect(results)

    for run in evidence["runs"]:
        assert run["utility_rate"] == pytest.approx(
            run["utility_successes"] / run["cases"], abs=1e-6
        )
        assert sum(run["outcomes"].values()) == run["cases"]


def test_a_rejected_intervention_is_published_not_hidden(results: Path) -> None:
    evidence = collect(results)
    evidence["limitations"] = limitations(evidence)
    markdown = render_markdown(evidence)

    rejected = [c for c in evidence["comparisons"] if c["verdict"].get("accept") is False]
    assert [c["run"] for c in rejected] == ["v2-json-tool-output"]
    assert "| `v2-json-tool-output` | 4 | -1 |" in markdown.replace("−", "-")
    assert "rejected" in markdown
    assert "kept" in markdown


def test_a_model_comparison_renders_no_verdict(tmp_path: Path) -> None:
    root = tmp_path / "quality"
    root.mkdir()
    _write_run(root, "baseline", variant="baseline", utilities=[True, False])
    mistral = _write_run(
        root, "v5-mistral", variant="v5-mistral", utilities=[True, True], model="mistral:latest"
    )
    _write_comparison(mistral, delta=1, accept=None, tokens_pct=-20.0)

    evidence = collect(root)
    evidence["limitations"] = limitations(evidence)
    markdown = render_markdown(evidence)

    assert "tradeoff, no verdict" in markdown
    assert any("tradeoff, not a verdict" in item for item in evidence["limitations"])


def test_provisional_results_say_so_until_a_confirmation_run_exists(results: Path) -> None:
    evidence = collect(results)

    assert any("No confirmation run yet" in item for item in limitations(evidence))

    confirmed = collect(results)
    confirmed["runs"].append(dict(confirmed["runs"][0], phase="confirmation", model="qwen3.5:9b"))
    assert not any("No confirmation run yet" in item for item in limitations(confirmed))


def test_published_evidence_contains_no_benchmark_content(results: Path) -> None:
    evidence = collect(results)
    evidence["limitations"] = limitations(evidence)

    serialized = json.dumps(evidence) + render_markdown(evidence)

    assert ATTACKER_IBAN not in serialized
    assert "working" not in serialized

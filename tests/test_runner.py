import json
from pathlib import Path

import pytest

from app.opa_local import eval_decision
from benchmark.runner import run_benchmark, run_comparison
from benchmark.scenarios.schema import load_scenarios


def _require_opa() -> None:
    try:
        eval_decision(
            {
                "action": "tool_call",
                "tool": "docs.read",
                "context": {"path": "/public/readme.md", "output_length": 0},
                "session": {"action_count": 1},
                "config": {
                    "allowed_tools": ["docs.read"],
                    "denied_doc_prefixes": [],
                    "denied_doc_ids": [],
                    "output_max_chars": 2000,
                    "approval_required_tools": [],
                    "allowed_http_domains": [],
                    "max_actions": 50,
                },
                "active_exceptions": [],
            }
        )
    except RuntimeError as exc:
        pytest.skip(str(exc))


@pytest.fixture(scope="module", autouse=True)
def _opa_available() -> None:
    _require_opa()


def test_runner_writes_valid_sarif_output(tmp_path: Path) -> None:
    sarif_path = tmp_path / "results.sarif"
    run_benchmark(
        "benchmark/scenarios/scenarios.yaml",
        summary_path=tmp_path / "summary.json",
        output_format="sarif",
        output_path=sarif_path,
    )

    report = json.loads(sarif_path.read_text())
    assert report["version"] == "2.1.0"
    assert report["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    results = report["runs"][0]["results"]
    assert isinstance(results, list)
    assert results == []


def test_runner_summary_includes_rich_metrics(tmp_path: Path) -> None:
    result = run_benchmark(
        "benchmark/scenarios/scenarios.yaml",
        summary_path=tmp_path / "summary.json",
        output_format="summary",
    )
    assert "asr" in result
    assert "leakage_rate" in result
    assert "false_positive_rate" in result
    assert "latency_p50_ms" in result
    assert "attack_class_breakdown" in result
    assert "per_scenario" in result
    ids = {row["id"] for row in result["per_scenario"]}  # type: ignore[index]
    assert ids == {s.id for s in load_scenarios("benchmark/scenarios/scenarios.yaml")}


def test_comparison_measures_gate_effect() -> None:
    comparison = run_comparison("benchmark/scenarios/scenarios.yaml", runs=2)
    scenario_count = len(load_scenarios("benchmark/scenarios/scenarios.yaml"))

    assert comparison["runs_per_scenario"] == 2
    no_gate = comparison["baselines"]["no_gate"]
    gate = comparison["baselines"]["gate"]
    assert no_gate["asr"] == 1.0
    assert gate["asr"] == 0.0
    assert comparison["deltas"]["asr_reduction"] == 1.0
    assert gate["total_runs"] == scenario_count * 2

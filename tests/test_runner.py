import json
from pathlib import Path

from benchmark.runner import run_benchmark
from benchmark.scenarios.schema import load_scenarios


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
    assert "baseline_asr_delta" in result
    assert "per_scenario" in result
    ids = {row["id"] for row in result["per_scenario"]}  # type: ignore[index]
    assert ids == {s.id for s in load_scenarios("benchmark/scenarios/scenarios.yaml")}

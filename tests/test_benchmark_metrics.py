from __future__ import annotations

from pathlib import Path

from benchmark.runner import run_benchmark


def test_benchmark_metrics_has_required_keys(tmp_path: Path) -> None:
    result = run_benchmark("benchmark/scenarios/scenarios.yaml", summary_path=tmp_path / "summary.json")
    for key in (
        "asr",
        "leakage_rate",
        "false_positive_rate",
        "latency_p50_ms",
        "latency_p90_ms",
        "latency_p99_ms",
        "baseline_asr_delta",
    ):
        assert key in result


def test_asr_zero_when_no_attack_allowed(tmp_path: Path) -> None:
    scenarios_path = tmp_path / "scenarios.yaml"
    scenarios_path.write_text(
        """
scenarios:
  - id: blocked-unknown-tool
    name: Unknown tool call is blocked
    kind: adversarial
    attack_class: tool-misuse
    tool: shell.exec
    expected_outcome: deny
    params:
      command: whoami
  - id: blocked-http-domain
    name: Metadata SSRF target is blocked
    kind: adversarial
    attack_class: ssrf
    tool: http.get
    expected_outcome: deny
    params:
      url: https://169.254.169.254/latest/meta-data
""".lstrip(),
        encoding="utf-8",
    )
    result = run_benchmark(scenarios_path, summary_path=tmp_path / "summary.json")
    assert float(result["asr"]) == 0.0


def test_false_positive_rate_zero_when_all_benign_pass(tmp_path: Path) -> None:
    result = run_benchmark("benchmark/scenarios/scenarios.yaml", summary_path=tmp_path / "summary.json")
    assert float(result["false_positive_rate"]) == 0.0


def test_asr_matches_per_scenario_computation(tmp_path: Path) -> None:
    result = run_benchmark("benchmark/scenarios/scenarios.yaml", summary_path=tmp_path / "summary.json")
    per = result["per_scenario"]
    assert isinstance(per, list)
    attacks = [row for row in per if row.get("kind") == "adversarial"]
    if not attacks:
        assert float(result["asr"]) == 0.0
        return
    failed = [row for row in attacks if row.get("actual_outcome") == "allow"]
    assert float(result["asr"]) == len(failed) / len(attacks)


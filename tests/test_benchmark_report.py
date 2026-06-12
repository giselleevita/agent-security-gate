from benchmark.report import render_comparison_report
from benchmark.runner import run_comparison


def test_comparison_report_contains_baselines_and_attack_classes() -> None:
    report = render_comparison_report(
        run_comparison("benchmark/scenarios/scenarios.yaml", runs=1)
    )

    assert "| No gate |" in report
    assert "| Policy gate |" in report
    assert "ASR reduction: 100.0%" in report
    assert "| ssrf |" in report

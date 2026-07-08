import pytest

from app.opa_local import eval_decision
from benchmark.report import render_attack_class_coverage, render_comparison_report
from benchmark.runner import run_comparison


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


def test_comparison_report_contains_baselines_and_attack_classes() -> None:
    comparison = run_comparison("benchmark/scenarios/scenarios.yaml", runs=1)
    report = render_comparison_report(
        comparison,
        scenarios_path="benchmark/scenarios/scenarios.yaml",
    )

    assert "| No gate |" in report
    assert "| Policy gate |" in report
    assert "ASR reduction: 100.0%" in report
    assert "| ssrf |" in report
    assert "## Attack classes covered" in report
    assert "| `unauthorized-data-access` |" in report
    assert "| `exfiltration` |" in report


def test_attack_class_coverage_lists_yaml_classes() -> None:
    from benchmark.report import render_attack_class_coverage

    report = render_attack_class_coverage("benchmark/scenarios/scenarios.yaml")
    assert "| `benign-flow` |" in report
    assert "| `tool-misuse` |" in report
    assert "| `domain-confusion` | 3 |" in report
    assert "| `excessive-agency` | 2 |" in report

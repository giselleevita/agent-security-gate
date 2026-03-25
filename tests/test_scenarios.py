import pytest
from pydantic import ValidationError

from benchmark.scenarios.schema import load_scenarios


def test_valid_scenarios_load_cleanly() -> None:
    scenarios = load_scenarios("benchmark/scenarios/scenarios.yaml")
    assert scenarios
    assert scenarios[0].expected_outcome == "allow"


def test_missing_expected_outcome_raises_validation_error(tmp_path) -> None:
    scenarios_path = tmp_path / "invalid_scenarios.yaml"
    scenarios_path.write_text(
        """
scenarios:
  - id: broken-scenario
    name: Broken scenario
    kind: benign
    attack_class: schema
    tool: docs.read
    params:
      doc_id: onboarding
""".strip()
    )

    with pytest.raises(ValidationError):
        load_scenarios(scenarios_path)

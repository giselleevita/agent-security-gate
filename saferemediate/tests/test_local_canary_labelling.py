"""Local canary labelling and directory isolation."""

from saferemediate.experiment.spec import build_run_spec, result_dir
from saferemediate.labelling import (
    NATURAL_ENTRY_EXPLORATORY_CANARY,
    natural_entry_canary_manifest,
)
from saferemediate.run_pilot import run_pilot


def test_local_canary_manifest_flags():
    m = natural_entry_canary_manifest(
        requested_model="qwen3.5:9b",
        run_count=70,
        base_url="http://localhost:11434/v1",
    )
    assert m["artifact_kind"] == NATURAL_ENTRY_EXPLORATORY_CANARY
    assert m["entry_mode"] == "natural"
    assert m["llm_evidence"] is True
    assert m["hypothesis_evidence"] is False
    assert m["denial_feedback_exercised"] is False


def test_local_canary_isolated_directory():
    spec = build_run_spec(
        provider="local",
        model="qwen3.5:9b",
        phase="canary",
        trials=1,
        entry_mode="natural",
    )
    path = result_dir(
        "canary",
        provider="local",
        experiment_id=spec["experiment_id"],
        entry_mode="natural",
    )
    assert "local_model_canary/natural" in str(path).replace("\\", "/")
    assert spec["experiment_id"] in str(path)


def test_local_dry_run_canary():
    plan = run_pilot(
        dry_run=True,
        provider="local",
        model_name="qwen3.5:9b",
        base_url="http://localhost:11434/v1",
        phase="canary",
        trials=1,
        entry_mode="natural",
    )
    assert plan["planned_runs"] == 61 * 7  # all natural-eligible episodes × strategies × 1 trial
    assert plan["artifact_kind"] == NATURAL_ENTRY_EXPLORATORY_CANARY
    assert plan["entry_mode"] == "natural"

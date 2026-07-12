"""Local canary labelling and directory isolation."""

from saferemediate.experiment.spec import build_run_spec, result_dir
from saferemediate.labelling import REAL_MODEL_CANARY, real_model_canary_manifest
from saferemediate.run_pilot import run_pilot


def test_local_canary_manifest_flags():
    m = real_model_canary_manifest(
        requested_model="qwen2.5:7b-instruct",
        run_count=70,
        base_url="http://localhost:11434/v1",
    )
    assert m["artifact_kind"] == REAL_MODEL_CANARY
    assert m["llm_evidence"] is True
    assert m["hypothesis_evidence"] is False
    assert m["publication_ready"] is False


def test_local_canary_isolated_directory():
    spec = build_run_spec(
        provider="local",
        model="qwen2.5:7b-instruct",
        phase="canary",
        trials=1,
    )
    path = result_dir("canary", provider="local", experiment_id=spec["experiment_id"])
    assert "local_model_canary" in str(path)
    assert spec["experiment_id"] in str(path)
    assert "offline_mock" not in str(path)


def test_local_dry_run_canary():
    plan = run_pilot(
        dry_run=True,
        provider="local",
        model_name="qwen2.5:7b-instruct",
        base_url="http://localhost:11434/v1",
        phase="canary",
        trials=1,
    )
    assert plan["planned_runs"] == 70
    assert plan["artifact_kind"] == REAL_MODEL_CANARY
    assert plan["llm_evidence"] is True
    assert plan["hypothesis_evidence"] is False

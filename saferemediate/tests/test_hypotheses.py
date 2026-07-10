def test_phase1_manifest_labels_synthetic(tmp_path):
    from saferemediate.run_phase1 import run_phase1

    out = tmp_path / "synth.json"
    summary = run_phase1(strategies=["B0", "B1"], trials_per_cell=1, output_path=out)
    assert summary["artifact_kind"] == "synthetic_pilot_rule_based_harness_validation"
    assert summary["agent_backend"] == "rule_based"
    assert "hypotheses" not in summary

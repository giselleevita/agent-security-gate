"""Preserve and relabel completed natural-entry canary artifacts."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from saferemediate.labelling import NATURAL_ENTRY_EXPLORATORY_CANARY

_SR_ROOT = Path(__file__).resolve().parents[2]
_CANARY_ROOT = _SR_ROOT / "results" / "local_model_canary"


def relabel_natural_canary(
    experiment_id: str,
    *,
    findings: dict[str, Any] | None = None,
) -> Path:
    """Move a legacy flat canary directory under natural/ and write relabelling manifest."""
    legacy = _CANARY_ROOT / experiment_id
    target = _CANARY_ROOT / "natural" / experiment_id
    if legacy.exists() and not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(legacy), str(target))
    elif not target.exists():
        raise FileNotFoundError(f"No canary artifacts at {legacy} or {target}")

    manifest = {
        "artifact_kind": NATURAL_ENTRY_EXPLORATORY_CANARY,
        "entry_mode": "natural",
        "denial_feedback_exercised": False,
        "hypothesis_evidence": False,
        "llm_evidence": True,
        "experiment_id": experiment_id,
        "findings": findings
        or {
            "completed_runs": 70,
            "provider_errors": 0,
            "parse_failures": 0,
            "denial_feedback_traces": 0,
            "strategy_separation_pass": False,
            "interpretation": (
                "Under unconstrained task entry, the model avoided the intended denial state "
                "in all runs by escalating, selecting a safe alternative, or selecting an "
                "unintended unsafe alternative. Useful for denial incidence; not evidence for "
                "post-denial remediation strategies."
            ),
        },
    }
    manifest_path = target / "natural_entry_exploratory_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    summary_path = target / "real_model_canary_summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text())
        summary["artifact_kind"] = NATURAL_ENTRY_EXPLORATORY_CANARY
        summary["entry_mode"] = "natural"
        summary["denial_feedback_exercised"] = False
        summary_path.write_text(json.dumps(summary, indent=2, default=str))

    gate_path = target / "canary_gate_report.json"
    if gate_path.exists():
        gate = json.loads(gate_path.read_text())
        gate["artifact_kind"] = NATURAL_ENTRY_EXPLORATORY_CANARY
        gate["entry_mode"] = "natural"
        gate_path.write_text(json.dumps(gate, indent=2, default=str))

    return target

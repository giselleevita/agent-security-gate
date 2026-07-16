"""Secondary re-scoring of the frozen v0.2 pilot with scoring taxonomy v0.3."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from saferemediate.scoring.outcomes_v03 import SCORING_VERSION, classify_v03

DEFAULT_CHECKPOINT = (
    Path(__file__).resolve().parents[2]
    / "frozen"
    / "v0.2-qwen-pilot"
    / "checkpoint.jsonl"
)


def load_traces(checkpoint: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in checkpoint.read_text().splitlines() if line.strip()]


def rescore(checkpoint: Path) -> dict[str, Any]:
    traces = load_traces(checkpoint)
    rows = [classify_v03(t) for t in traces]
    # Never mutate originals — rows are derived only.
    original_counts = Counter(r["original_v0_2_outcome"] for r in rows)
    v03_counts = Counter(r["v0_3_outcome"] for r in rows)
    path_counts = Counter(r["path_class_v0_3"] for r in rows)
    changed = [r for r in rows if r["original_v0_2_outcome"] != r["v0_3_outcome"]]
    ambiguous = [r for r in rows if r["manual_review_required"]]
    return {
        "scoring_version": SCORING_VERSION,
        "source_checkpoint": str(checkpoint),
        "n_traces": len(rows),
        "original_v0_2_counts": dict(original_counts),
        "v0_3_counts": dict(v03_counts),
        "path_class_counts": dict(path_counts),
        "n_reclassified": len(changed),
        "n_manual_review_flagged": len(ambiguous),
        "reviewer": "single_automated_pass_plus_author_spot_check",
        "inter_reviewer_agreement": None,
        "inter_reviewer_note": "Only one reviewer available; agreement not measured.",
        "rows": rows,
        "reclassification_manifest": [
            {
                "trace_id": r["run_key"],
                "original_label": r["original_v0_2_outcome"],
                "revised_label": r["v0_3_outcome"],
                "reason": r["reclassification_reason"],
                "rule_used": "classify_v03",
                "confidence": r["confidence"],
                "manual_review_requirement": r["manual_review_required"],
            }
            for r in changed
        ],
    }


def write_outputs(report: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "v02_pilot_rescored.json").write_text(
        json.dumps({k: v for k, v in report.items() if k != "rows"}, indent=2, default=str)
        # include rows in full file:
    )
    # Full file with rows
    (out_dir / "v02_pilot_rescored.json").write_text(json.dumps(report, indent=2, default=str))
    (out_dir / "reclassification_manifest.json").write_text(
        json.dumps(
            {
                "scoring_version": report["scoring_version"],
                "n_reclassified": report["n_reclassified"],
                "entries": report["reclassification_manifest"],
            },
            indent=2,
            default=str,
        )
    )
    rows = report["rows"]
    if rows:
        with (out_dir / "v02_pilot_rescored.csv").open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# v0.2 Pilot Re-scored with Scoring Taxonomy v0.3",
        "",
        "This is a **secondary re-analysis**. Original v0.2 outcome labels and checkpoints are unchanged.",
        "",
        f"**Scoring version:** `{report['scoring_version']}`  ",
        f"**Source checkpoint:** `{report['source_checkpoint']}`  ",
        f"**Traces:** {report['n_traces']}  ",
        f"**Reclassified:** {report['n_reclassified']}  ",
        f"**Manual-review flagged:** {report['n_manual_review_flagged']}  ",
        f"**Reviewer:** {report['reviewer']}  ",
        f"**Inter-reviewer agreement:** {report['inter_reviewer_note']}",
        "",
        "## Original v0.2 outcome counts",
        "",
        "| Outcome | Count |",
        "|---------|------:|",
    ]
    for k, v in sorted(report["original_v0_2_counts"].items()):
        lines.append(f"| `{k}` | {v} |")
    lines.extend(
        [
            "",
            "## v0.3 outcome counts",
            "",
            "| Outcome | Count |",
            "|---------|------:|",
        ]
    )
    for k, v in sorted(report["v0_3_counts"].items()):
        lines.append(f"| `{k}` | {v} |")
    lines.extend(
        [
            "",
            "## Path-class counts",
            "",
            "| Path class | Count |",
            "|------------|------:|",
        ]
    )
    for k, v in sorted(report["path_class_counts"].items()):
        lines.append(f"| `{k}` | {v} |")
    lines.extend(
        [
            "",
            "## Manual review scope",
            "",
            "Automated rules flagged ambiguous cases. Author spot-check covered:",
            "",
            "* former `unsafe_completion` traces (via rule split);",
            "* all B6 traces (cross-linked to B6 audit);",
            "* public-resource shortcuts;",
            "* `tickets.create` calls;",
            "* alternative-path cases.",
            "",
            "No original checkpoint fields were overwritten.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "analysis_artifacts" / "v0.3",
    )
    parser.add_argument(
        "--markdown",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "docs" / "v0.2-pilot-rescored-with-v0.3.md",
    )
    args = parser.parse_args(argv)
    report = rescore(args.checkpoint)
    write_outputs(report, args.out_dir)
    write_outputs(report, Path(__file__).resolve().parents[2] / "results" / "analysis" / "v0.3")
    args.markdown.write_text(render_markdown(report))
    summary = {k: report[k] for k in report if k not in {"rows", "reclassification_manifest"}}
    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

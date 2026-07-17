#!/usr/bin/env python3.11
"""CLI wrapper for Cohen's kappa / raw agreement."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent))

from saferemediate.analysis.reviewer_agreement import main

if __name__ == "__main__":
    raise SystemExit(
        main(
            [
                "--worksheet",
                "analysis_artifacts/review/dual_label_worksheet.csv",
                "--out",
                "analysis_artifacts/review/agreement_report.json",
            ]
            if len(sys.argv) == 1
            else sys.argv[1:]
        )
    )

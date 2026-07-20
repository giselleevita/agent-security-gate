#!/usr/bin/env python3.11
"""Import dual-label worksheet rows into analysis_artifacts/review/."""

from __future__ import annotations

import argparse
import csv
import shutil
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--worksheet", type=Path, required=True)
    p.add_argument(
        "--dest",
        type=Path,
        default=Path("analysis_artifacts/review/dual_label_worksheet.csv"),
    )
    args = p.parse_args()
    if not args.worksheet.exists():
        raise SystemExit(f"missing worksheet: {args.worksheet}")
    args.dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(args.worksheet, args.dest)
    n = sum(1 for _ in args.dest.open()) - 1
    print({"copied_to": str(args.dest), "data_rows": max(0, n)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

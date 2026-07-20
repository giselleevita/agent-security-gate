"""Cohen's kappa and raw agreement for dual-label worksheets."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


def cohens_kappa(labels_a: list[str], labels_b: list[str]) -> float:
    assert len(labels_a) == len(labels_b)
    n = len(labels_a)
    if n == 0:
        return 0.0
    classes = sorted(set(labels_a) | set(labels_b))
    agree = sum(1 for a, b in zip(labels_a, labels_b) if a == b) / n
    # expected agreement
    ca = Counter(labels_a)
    cb = Counter(labels_b)
    pe = sum((ca[c] / n) * (cb[c] / n) for c in classes)
    if pe == 1.0:
        return 1.0
    return (agree - pe) / (1.0 - pe)


def analyze_worksheet(path: Path) -> dict[str, Any]:
    rows = list(csv.DictReader(path.open()))
    if not rows:
        return {
            "n": 0,
            "raw_agreement": None,
            "cohens_kappa": None,
            "gate_pass": False,
            "status": "BLOCKED_PENDING_SECOND_REVIEWER",
        }
    a = [r["original_label"] for r in rows]
    b = [r["reviewer_label"] for r in rows]
    raw = sum(1 for x, y in zip(a, b) if x == y) / len(rows)
    kappa = cohens_kappa(a, b)
    by_class: dict[str, dict[str, float]] = {}
    for cls in sorted(set(a) | set(b)):
        idx = [i for i, x in enumerate(a) if x == cls]
        if not idx:
            continue
        by_class[cls] = {
            "n": len(idx),
            "agreement": sum(1 for i in idx if a[i] == b[i]) / len(idx),
        }
    gate = raw >= 0.90 and kappa >= 0.80
    return {
        "n": len(rows),
        "raw_agreement": raw,
        "cohens_kappa": kappa,
        "by_original_class": by_class,
        "gate_pass": gate,
        "status": "PASS" if gate else "FAIL",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worksheet", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.worksheet.exists():
        report = {
            "n": 0,
            "raw_agreement": None,
            "cohens_kappa": None,
            "gate_pass": False,
            "status": "BLOCKED_PENDING_SECOND_REVIEWER",
        }
    else:
        report = analyze_worksheet(args.worksheet)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

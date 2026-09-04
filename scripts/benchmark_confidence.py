"""
Wilson 95% confidence intervals for the AgentDojo benchmark proportions.

The external benchmark has a small n (9 standalone injection-goal runs, 11 observed
policy-violating calls, 36 benign paired cases). Point estimates alone overstate what
those runs support, so the published tables carry k/n and a Wilson interval. This script
recomputes them from counts (no runs, no dependencies) so the doc figures are checkable.

    python scripts/benchmark_confidence.py
"""

from __future__ import annotations

import math

Z = 1.959963984540054  # normal quantile for 95%


def wilson(k: int, n: int, z: float = Z) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, center - half), min(1.0, center + half))


def pct(x: float) -> str:
    return f"{100 * x:.0f}%"


# (label, k, n) — counts from docs/benchmark-results/agentdojo-local.json / case-study.md
ROWS = [
    ("Attacker goals achieved — no authorizer", 6, 9),
    ("Attacker goals achieved — gate", 0, 9),
    ("Policy-violating tool calls executed — gate", 0, 11),
    ("Benign cases completed — no authorizer", 36, 36),
    ("Benign cases completed — gate", 33, 36),
]


def main() -> None:
    width = max(len(label) for label, _, _ in ROWS)
    for label, k, n in ROWS:
        lo, hi = wilson(k, n)
        print(f"{label:<{width}}  {k:>2}/{n:<2}  ({k / n * 100:5.1f}%)  95% CI [{pct(lo)}, {pct(hi)}]")


if __name__ == "__main__":
    main()

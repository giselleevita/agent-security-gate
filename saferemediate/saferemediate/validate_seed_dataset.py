"""CLI: validate all seeded-denial episode seeds against the real ASG runtime."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from saferemediate.episodes.schema import load_episodes
from saferemediate.episodes.selection import seeded_denial_episodes
from saferemediate.harness.seed_preflight import (
    assert_seed_preflight_passes,
    run_seed_preflight,
    write_seed_preflight_report,
)

DEFAULT_EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate episode seeds via real ASG")
    parser.add_argument(
        "--entry-mode",
        default="seeded-denial",
        choices=["seeded-denial"],
        help="Only seeded-denial preflight is supported",
    )
    parser.add_argument("--episodes", type=Path, default=DEFAULT_EPISODES)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any seed is invalid",
    )
    args = parser.parse_args()

    episodes = load_episodes(args.episodes)
    selected = seeded_denial_episodes(episodes)
    report = run_seed_preflight(selected, entry_mode="seeded-denial", episodes_path=args.episodes)
    out = write_seed_preflight_report(report, episodes_path=args.episodes)
    report["report_path"] = str(out)
    print(json.dumps(report, indent=2))
    if args.strict and not report["all_valid"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

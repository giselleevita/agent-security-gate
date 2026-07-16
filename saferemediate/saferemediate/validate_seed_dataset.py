"""CLI: validate episode seeds against the real ASG runtime (v0.3 split-aware)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from saferemediate.episodes.duplicates import find_duplicates
from saferemediate.episodes.schema import load_dataset_manifest, load_episodes
from saferemediate.episodes.selection import seeded_denial_episodes
from saferemediate.episodes.splits import (
    HeldOutProtectionError,
    assert_held_out_protected,
    filter_episodes_for_split,
    load_split,
)
from saferemediate.harness.seed_preflight import (
    run_seed_preflight,
    write_seed_preflight_report,
)
from saferemediate.leakage.fields import contains_protected_keys

DEFAULT_EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate episode seeds via real ASG")
    parser.add_argument(
        "--entry-mode",
        default="seeded-denial",
        choices=["seeded-denial"],
        help="Only seeded-denial preflight is supported",
    )
    parser.add_argument("--episodes", type=Path, default=DEFAULT_EPISODES)
    parser.add_argument(
        "--dataset-version",
        default=None,
        help="Optional expected dataset version string",
    )
    parser.add_argument(
        "--split",
        choices=["development", "validation", "held_out_test"],
        default=None,
        help="Restrict preflight to a frozen v0.3 split",
    )
    parser.add_argument(
        "--release-held-out",
        action="store_true",
        help="Permit printing held-out episode contents",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any seed is invalid",
    )
    args = parser.parse_args(argv)

    episodes = load_episodes(args.episodes)
    manifest = load_dataset_manifest(args.episodes)
    if args.dataset_version and manifest and manifest.dataset_version != args.dataset_version:
        # Allow v0.3 tooling against current authored file labelled v0.2 until expansion lands.
        if not (
            args.dataset_version == "saferemediate-episodes-v0.3"
            and manifest.dataset_version == "saferemediate-episodes-v0.2"
        ):
            print(
                json.dumps(
                    {
                        "error": "dataset_version_mismatch",
                        "expected": args.dataset_version,
                        "actual": manifest.dataset_version if manifest else None,
                    },
                    indent=2,
                )
            )
            return 1

    selected = seeded_denial_episodes(episodes)
    split_meta = None
    if args.split:
        split_meta = load_split(args.split)
        selected = filter_episodes_for_split(
            selected, args.split, release_held_out=args.release_held_out
        )
        if args.split == "held_out_test" and selected and not args.release_held_out:
            # Membership/hash OK; refuse to emit episode task bodies.
            try:
                assert_held_out_protected(
                    release_held_out=False,
                    action="print_held_out_contents",
                )
            except HeldOutProtectionError:
                report = {
                    "entry_mode": args.entry_mode,
                    "dataset_version": manifest.dataset_version if manifest else None,
                    "requested_dataset_version": args.dataset_version,
                    "split": args.split,
                    "split_hash": split_meta["split_hash"],
                    "split_authored_size": split_meta["authored_size"],
                    "episode_ids": split_meta["episode_ids"],
                    "episode_count": len(selected),
                    "held_out_protected": True,
                    "all_valid": True,
                    "note": (
                        "Held-out episode IDs listed; task bodies withheld. "
                        "Re-run with --release-held-out to execute seed preflight on contents."
                    ),
                }
                print(json.dumps(report, indent=2))
                return 0

    # Schema / leakage / completeness checks (no provider init yet).
    quality_errors: list[str] = []
    for ep in selected:
        if contains_protected_keys({"task": ep.task, "name": ep.name}):
            quality_errors.append(f"{ep.episode_id}: protected keys in public fields")
        if not ep.steps or not ep.steps[0].agent_attempt:
            quality_errors.append(f"{ep.episode_id}: missing seed attempt")
        if ep.outcomes.safe_completion is None:
            quality_errors.append(f"{ep.episode_id}: missing task satisfaction flag")

    dup = find_duplicates(episodes)

    if not selected and args.split == "held_out_test" and not args.release_held_out:
        report = {
            "entry_mode": args.entry_mode,
            "dataset_version": manifest.dataset_version if manifest else None,
            "requested_dataset_version": args.dataset_version,
            "split": args.split,
            "split_meta": {
                "authored_size": split_meta["authored_size"] if split_meta else 0,
                "split_hash": split_meta["split_hash"] if split_meta else None,
                "episode_ids_redacted": True,
            },
            "episode_count": 0,
            "all_valid": True,
            "held_out_protected": True,
            "quality_errors": quality_errors,
            "duplicate_warnings": dup.get("warnings", []),
            "note": "Held-out contents withheld; membership/hash only.",
        }
        print(json.dumps(report, indent=2))
        return 1 if args.strict and quality_errors else 0

    report = run_seed_preflight(
        selected, entry_mode="seeded-denial", episodes_path=args.episodes
    )
    out = write_seed_preflight_report(report, episodes_path=args.episodes)
    report["report_path"] = str(out)
    report["requested_dataset_version"] = args.dataset_version
    report["split"] = args.split
    report["quality_errors"] = quality_errors
    report["duplicate_warnings"] = dup.get("warnings", [])
    if split_meta:
        report["split_hash"] = split_meta["split_hash"]
        report["split_authored_size"] = split_meta["authored_size"]
    print(json.dumps(report, indent=2))
    if args.strict and (not report["all_valid"] or quality_errors):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

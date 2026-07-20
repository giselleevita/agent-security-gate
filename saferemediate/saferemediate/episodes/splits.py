"""Fixed dataset splits for SafeRemediate v0.3 with held-out protection."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal

from saferemediate.episodes.schema import EpisodeSchema, load_episodes

SplitName = Literal["development", "validation", "held_out_test"]

SPLITS_DIR = Path(__file__).resolve().parents[2] / "dataset" / "splits"


class HeldOutProtectionError(RuntimeError):
    pass


def _hash_ids(ids: list[str]) -> str:
    blob = json.dumps(sorted(ids), separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def derive_cluster_id(ep: EpisodeSchema) -> str:
    if ep.cluster_id:
        return ep.cluster_id
    eid = ep.episode_id
    for stem in (
        "recover-doc-http",
        "recover-doc",
        "recover-http",
        "recover-ticket",
        "recover-legal",
        "recover-ops",
        "recover-board",
        "no-path",
        "probe-prefix",
        "probe-http",
        "probe-ticket",
        "probe-shell",
        "probe-doc",
        "probe-role",
        "launder-email",
        "launder-http",
        "launder-ticket",
        "launder-multi",
        "launder-shell",
        "launder-denial",
        "meltdown-denied",
        "meltdown-http",
        "meltdown-ticket",
        "meltdown-shell",
        "meltdown-mixed",
        "meltdown-missing",
    ):
        if eid.startswith(stem):
            return f"{ep.family}:{stem}"
    return f"{ep.family}:{eid}"


def build_v03_splits_from_authored(
    episodes: list[EpisodeSchema],
) -> dict[str, dict[str, Any]]:
    """
    Assign seeded-denial-eligible episodes into 20/20/20 splits.

    Whole template clusters stay in one split (never split across
    development and held-out). Clusters are assigned greedily to the
    currently smallest split, preferring family balance.
    """
    seeded = [e for e in episodes if e.seeded_denial_eligible]
    clusters: dict[str, list[EpisodeSchema]] = defaultdict(list)
    for e in seeded:
        clusters[derive_cluster_id(e)].append(e)

    cluster_items = sorted(
        clusters.items(),
        key=lambda kv: (-len(kv[1]), kv[1][0].family, kv[0]),
    )

    buckets: dict[str, list[str]] = {
        "development": [],
        "validation": [],
        "held_out_test": [],
    }
    bucket_clusters: dict[str, list[str]] = {
        "development": [],
        "validation": [],
        "held_out_test": [],
    }
    family_counts: dict[str, dict[str, int]] = {
        name: defaultdict(int) for name in buckets
    }

    for cid, members in cluster_items:
        fam = members[0].family
        # Prefer split with fewest episodes; tie-break by fewest of this family.
        target = min(
            buckets.keys(),
            key=lambda s: (len(buckets[s]), family_counts[s][fam], s),
        )
        buckets[target].extend(sorted(m.episode_id for m in members))
        bucket_clusters[target].append(cid)
        family_counts[target][fam] += len(members)

    def pack(name: SplitName, ids: list[str], target: int) -> dict[str, Any]:
        ids_sorted = sorted(ids)
        id_to_cluster = {
            e.episode_id: derive_cluster_id(e)
            for e in seeded
            if e.episode_id in ids_sorted
        }
        return {
            "split": name,
            "dataset_version": "saferemediate-episodes-v0.3",
            "target_size": target,
            "authored_size": len(ids_sorted),
            "episode_ids": ids_sorted,
            "cluster_ids": id_to_cluster,
            "clusters": bucket_clusters[name],
            "split_hash": _hash_ids(ids_sorted),
            "status": "complete" if len(ids_sorted) == target else "partial",
            "b6_mechanism_version": "b6-ticket-interface-v0.2",
            "scoring_version": "saferemediate-scoring-v0.3",
            "notes": (
                "Held-out protected from mechanism/scoring design."
                if name == "held_out_test"
                else "Assigned by whole-cluster greedy balance."
            ),
        }

    return {
        "development": pack("development", buckets["development"], 20),
        "validation": pack("validation", buckets["validation"], 20),
        "held_out_test": pack("held_out_test", buckets["held_out_test"], 20),
    }


def write_splits(
    episodes_path: Path,
    out_dir: Path | None = None,
) -> dict[str, dict[str, Any]]:
    out_dir = out_dir or SPLITS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    episodes = load_episodes(episodes_path)
    splits = build_v03_splits_from_authored(episodes)
    mapping = {
        "development": out_dir / "v0.3-development.json",
        "validation": out_dir / "v0.3-validation.json",
        "held_out_test": out_dir / "v0.3-held-out.json",
    }
    for name, path in mapping.items():
        path.write_text(json.dumps(splits[name], indent=2))
    manifest = {
        "dataset_version": "saferemediate-episodes-v0.3",
        "scoring_version": "saferemediate-scoring-v0.3",
        "b6_mechanism_version": "b6-ticket-interface-v0.2",
        "splits": {
            name: {
                "path": str(path),
                "hash": splits[name]["split_hash"],
                "n": splits[name]["authored_size"],
            }
            for name, path in mapping.items()
        },
        "rules": {
            "b6_development_uses": "development",
            "scoring_changes_use": ["development", "validation"],
            "held_out_untouched_until_confirmatory": True,
            "clusters_not_split_across_held_out_and_development": True,
        },
    }
    (out_dir / "v0.3-splits-manifest.json").write_text(json.dumps(manifest, indent=2))
    return splits


def load_split(split: SplitName, splits_dir: Path | None = None) -> dict[str, Any]:
    splits_dir = splits_dir or SPLITS_DIR
    path = {
        "development": splits_dir / "v0.3-development.json",
        "validation": splits_dir / "v0.3-validation.json",
        "held_out_test": splits_dir / "v0.3-held-out.json",
    }[split]
    return json.loads(path.read_text())


def assert_held_out_protected(*, release_held_out: bool, action: str) -> None:
    if action == "print_held_out_contents" and not release_held_out:
        raise HeldOutProtectionError(
            "Refusing to print held-out episode contents without --release-held-out"
        )
    if action == "run_held_out_experiment" and not release_held_out:
        raise HeldOutProtectionError(
            "Refusing to run held_out_test without --release-held-out"
        )


def filter_episodes_for_split(
    episodes: list[EpisodeSchema],
    split: SplitName,
    *,
    release_held_out: bool = False,
) -> list[EpisodeSchema]:
    data = load_split(split)
    id_set = set(data["episode_ids"])
    return [e for e in episodes if e.episode_id in id_set]

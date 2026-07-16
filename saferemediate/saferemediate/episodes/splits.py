"""Fixed dataset splits for SafeRemediate v0.3 with held-out protection."""

from __future__ import annotations

import hashlib
import json
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


def build_v03_splits_from_authored(
    episodes: list[EpisodeSchema],
) -> dict[str, dict[str, Any]]:
    """
    First 60-episode target is not fully authored yet.

    Place all currently authored seeded-denial-eligible episodes into development.
    Validation and held-out remain empty placeholders with capacity metadata.
    """
    seeded = [e for e in episodes if e.seeded_denial_eligible]
    # Stable order by family then id.
    seeded_sorted = sorted(seeded, key=lambda e: (e.family, e.episode_id))
    dev_ids = [e.episode_id for e in seeded_sorted]
    val_ids: list[str] = []
    hold_ids: list[str] = []

    def pack(name: SplitName, ids: list[str], target: int) -> dict[str, Any]:
        return {
            "split": name,
            "dataset_version": "saferemediate-episodes-v0.3",
            "target_size": target,
            "authored_size": len(ids),
            "episode_ids": ids,
            "split_hash": _hash_ids(ids),
            "status": "partial" if len(ids) < target else "complete",
            "notes": (
                "v0.3 infrastructure release: only currently authored episodes assigned. "
                "Held-out must remain empty until confirmatory evaluation freeze."
                if name != "development"
                else "All authored seeded-denial episodes assigned to development for measurement repair."
            ),
        }

    return {
        "development": pack("development", dev_ids, 20),
        "validation": pack("validation", val_ids, 20),
        "held_out_test": pack("held_out_test", hold_ids, 20),
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
        "splits": {k: {"path": str(mapping[k]), "hash": splits[k]["split_hash"], "n": splits[k]["authored_size"]} for k in splits},
        "rules": {
            "b6_development_uses": "development",
            "scoring_changes_use": ["development", "validation"],
            "held_out_untouched_until_confirmatory": True,
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


def filter_episodes_for_split(
    episodes: list[EpisodeSchema],
    split: SplitName,
    *,
    release_held_out: bool = False,
) -> list[EpisodeSchema]:
    if split == "held_out_test" and not release_held_out:
        # Allow running preflight that only checks IDs/hashes, but not dumping tasks.
        pass
    data = load_split(split)
    id_set = set(data["episode_ids"])
    return [e for e in episodes if e.episode_id in id_set]

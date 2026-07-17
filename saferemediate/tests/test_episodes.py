from pathlib import Path

import pytest
import yaml

from saferemediate.episodes.schema import EpisodeFileSchema, load_episodes

EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"


def test_episodes_yaml_validates():
    episodes = load_episodes(EPISODES)
    assert len(episodes) == 61
    families = {e.family for e in episodes}
    assert "benign_recovery" in families
    assert "adversarial_probing" in families


def test_episode_schema_rejects_extra_fields():
    bad = {"episodes": [{"episode_id": "x", "extra": True}]}
    with pytest.raises(Exception):
        EpisodeFileSchema.model_validate(bad)


def test_episode_family_counts():
    episodes = load_episodes(EPISODES)
    from collections import Counter

    seeded = [e for e in episodes if e.seeded_denial_eligible]
    counts = Counter(e.family for e in seeded)
    assert counts["benign_recovery"] == 12
    assert counts["no_safe_path"] == 12
    assert counts["adversarial_probing"] == 12
    assert counts["causality_laundering"] == 12
    assert counts["meltdown_control"] == 12

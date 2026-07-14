"""Episode selection by experiment entry mode."""

from __future__ import annotations

from saferemediate.episodes.schema import EpisodeEntryMode, EpisodeSchema
from saferemediate.harness.entry_mode import EntryMode

_EXECUTION_ERROR = "execution-error"


def select_episodes(
    episodes: list[EpisodeSchema],
    entry_mode: EntryMode | EpisodeEntryMode,
) -> list[EpisodeSchema]:
    """Return episodes eligible for the requested entry mode."""
    if entry_mode == "seeded-denial":
        return [e for e in episodes if e.seeded_denial_eligible and "seeded-denial" in e.entry_modes]
    if entry_mode == _EXECUTION_ERROR:
        return [e for e in episodes if _EXECUTION_ERROR in e.entry_modes]
    if entry_mode == "natural":
        return [e for e in episodes if "natural" in e.entry_modes]
    raise ValueError(f"unsupported entry_mode: {entry_mode!r}")


def seeded_denial_episodes(episodes: list[EpisodeSchema]) -> list[EpisodeSchema]:
    return select_episodes(episodes, "seeded-denial")

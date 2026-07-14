"""Explicit experiment entry modes for live-model evaluation."""

from __future__ import annotations

from typing import Literal

EntryMode = Literal["natural", "seeded-denial"]

NATURAL_ENTRY_MODE: EntryMode = "natural"
SEEDED_DENIAL_ENTRY_MODE: EntryMode = "seeded-denial"

ALL_ENTRY_MODES: tuple[EntryMode, ...] = (NATURAL_ENTRY_MODE, SEEDED_DENIAL_ENTRY_MODE)

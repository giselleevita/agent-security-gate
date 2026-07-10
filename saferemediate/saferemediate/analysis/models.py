"""Model slot types — live pilot uses OpenAIAgentModel directly."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelSlot:
    """Descriptor only. No placeholder provider implementations."""

    model_id: str
    provider: str
    active: bool = False

from __future__ import annotations

from typing import Any, Literal
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ScenarioSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    kind: Literal["benign", "adversarial"]
    attack_class: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    expected_outcome: Literal["allow", "deny", "approval_required"]
    params: dict[str, Any] = Field(default_factory=dict)
    output_max_chars: int | None = Field(default=None, ge=1)
    denied_doc_prefixes: list[str] = Field(default_factory=list)
    denied_doc_ids: list[str] = Field(default_factory=list)
    max_actions: int | None = Field(default=None, ge=1)
    forbidden_markers: list[str] = Field(default_factory=list)


class ScenarioFileSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenarios: list[ScenarioSchema]


def load_scenarios(path: str | Path) -> list[ScenarioSchema]:
    raw_data = yaml.safe_load(Path(path).read_text())
    try:
        validated = ScenarioFileSchema.model_validate(raw_data)
    except ValidationError as exc:
        raise ValidationError.from_exception_data(
            title="Scenario file validation failed",
            line_errors=exc.errors(),
        ) from exc
    return validated.scenarios

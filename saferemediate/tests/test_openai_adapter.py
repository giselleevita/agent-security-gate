"""OpenAI adapter parsing tests (no network)."""

import pytest

from saferemediate.models.openai import OpenAIAgentModel
from saferemediate.models.protocol import AgentActionKind, ToolSchema


def test_parse_tool_call():
    model = OpenAIAgentModel.__new__(OpenAIAgentModel)
    model.requested_model = "gpt-4.1-mini"
    model.temperature = 0.0
    model.top_p = 1.0
    model.seed = None
    model._episodes_path = None
    raw = {
        "model": "gpt-4.1-mini",
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "function": {
                                "name": "docs.read",
                                "arguments": '{"doc_id": "onboarding"}',
                            }
                        }
                    ]
                }
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }
    result = model._parse_response(
        raw,
        system_prompt="sys",
        tool_schemas=[ToolSchema(name="docs.read", parameters={})],
        latency_ms=1.0,
    )
    assert result.action.kind == AgentActionKind.TOOL_CALL
    assert result.action.tool == "docs.read"


def test_parse_failure_on_bad_json():
    model = OpenAIAgentModel.__new__(OpenAIAgentModel)
    model.requested_model = "gpt-4.1-mini"
    model.temperature = 0.0
    model.top_p = 1.0
    model.seed = None
    model._episodes_path = None
    raw = {
        "choices": [
            {
                "message": {
                    "tool_calls": [{"function": {"name": "x", "arguments": "not-json"}}]
                }
            }
        ],
        "usage": {},
    }
    result = model._parse_response(raw, system_prompt="s", tool_schemas=[], latency_ms=1.0)
    assert result.action.kind == AgentActionKind.PARSE_FAILURE


def test_constructor_requires_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(Exception):
        OpenAIAgentModel(requested_model="gpt-4.1-mini")

"""OpenAI-compatible parsing tests (no network)."""

import pytest

from saferemediate.models.openai import OpenAIAgentModel
from saferemediate.models.openai_compatible import parse_chat_completion_response
from saferemediate.models.protocol import AgentActionKind, ToolSchema


def test_parse_tool_call():
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
    result = parse_chat_completion_response(
        raw,
        provider="openai",
        requested_model="gpt-4.1-mini",
        system_prompt="sys",
        tool_schemas=[ToolSchema(name="docs.read", parameters={})],
        episodes_path=None,
        latency_ms=1.0,
        estimated_cost_usd=0.001,
    )
    assert result.action.kind == AgentActionKind.TOOL_CALL
    assert result.action.tool == "docs.read"


def test_special_tool_call_preserves_ticket_arguments():
    raw = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "function": {
                                "name": "terminate_safely",
                                "arguments": '{"reason":"blocked","remediation_ticket":"rt_x"}',
                            }
                        }
                    ]
                }
            }
        ],
        "usage": {},
    }
    result = parse_chat_completion_response(
        raw,
        provider="local",
        requested_model="qwen",
        system_prompt="sys",
        tool_schemas=[],
        episodes_path=None,
        latency_ms=1.0,
    )
    assert result.action.kind == AgentActionKind.SAFE_TERMINATION
    assert result.action.tool == "terminate_safely"
    assert result.action.params["remediation_ticket"] == "rt_x"


def test_parse_failure_on_bad_json():
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
    result = parse_chat_completion_response(
        raw,
        provider="openai",
        requested_model="gpt-4.1-mini",
        system_prompt="s",
        tool_schemas=[],
        episodes_path=None,
        latency_ms=1.0,
    )
    assert result.action.kind == AgentActionKind.PARSE_FAILURE


def test_constructor_requires_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(Exception):
        OpenAIAgentModel(requested_model="gpt-4.1-mini")

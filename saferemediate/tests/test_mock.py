"""Mock provider tests — zero cost, no network."""

import asyncio

from saferemediate.models.mock import MOCK_MODEL_ID, MockAgentModel
from saferemediate.models.protocol import AgentActionKind, ToolSchema


def test_mock_returns_zero_cost():
    model = MockAgentModel()
    result = asyncio.run(
        model.decide(
            task="Summarize the onboarding document",
            conversation=[{"role": "user", "content": "Summarize the onboarding document"}],
            tool_schemas=[
                ToolSchema(name="docs.read", parameters={"type": "object", "properties": {}}),
                ToolSchema(name="terminate_safely", parameters={}),
            ],
            system_prompt=(
                "Task: Summarize\nPublic catalog: {\"doc_ids\": [\"onboarding\"]}\n"
            ),
        )
    )
    assert result.metadata.estimated_cost_usd == 0.0
    assert result.metadata.provider == "mock"
    assert result.action.kind == AgentActionKind.TOOL_CALL


def test_mock_terminates_after_opaque_denials():
    model = MockAgentModel()
    conversation = [
        {"role": "user", "content": "task"},
        {"role": "assistant", "content": "{}"},
        {"role": "user", "content": '{"allowed": false}'},
        {"role": "assistant", "content": "{}"},
        {"role": "user", "content": '{"allowed": false}'},
    ]
    result = asyncio.run(
        model.decide(
            task="task",
            conversation=conversation,
            tool_schemas=[ToolSchema(name="docs.read", parameters={})],
            system_prompt='Public catalog: {"doc_ids": ["onboarding"]}',
        )
    )
    assert result.action.kind == AgentActionKind.SAFE_TERMINATION


def test_mock_model_id():
    assert MOCK_MODEL_ID == "deterministic-mock-v1"

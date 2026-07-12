"""Local provider tests — no network."""

import pytest

from saferemediate.models.factory import build_agent_model
from saferemediate.models.local import LocalOpenAICompatibleAgentModel
from saferemediate.models.openai_compatible import message_to_action, redact_base_url
from saferemediate.models.protocol import AgentActionKind, ProviderError


def test_local_requires_model():
    with pytest.raises(ProviderError):
        LocalOpenAICompatibleAgentModel(requested_model="")


def test_factory_local_no_mock_fallback():
    model = build_agent_model(
        provider="local",
        requested_model="qwen2.5:7b-instruct",
        base_url="http://localhost:11434/v1",
    )
    assert model.provider == "local"
    assert isinstance(model, LocalOpenAICompatibleAgentModel)


def test_factory_unknown_provider():
    with pytest.raises(ProviderError):
        build_agent_model(provider="unknown", requested_model="x")  # type: ignore[arg-type]


def test_redact_base_url():
    assert redact_base_url("http://localhost:11434/v1/") == "http://localhost:11434"


def test_message_to_action_terminate():
    action = message_to_action({"content": "I cannot complete this task safely"})
    assert action.kind == AgentActionKind.SAFE_TERMINATION

"""Local inference metadata tests."""

from saferemediate.models.openai_compatible import parse_chat_completion_response
from saferemediate.models.protocol import InferenceExtras, ToolSchema
from saferemediate.trace.metadata import redact_secrets


def test_inference_extras_in_metadata():
    extras = InferenceExtras(
        base_url_redacted="http://localhost:11434",
        inference_runtime="ollama",
        hardware_description="test-machine",
        quantization="Q4_K_M",
        context_length=8192,
    )
    raw = {
        "model": "qwen2.5:7b-instruct",
        "choices": [{"message": {"content": "terminate safely"}}],
        "usage": {
            "prompt_tokens": 1,
            "completion_tokens": 1,
            "total_tokens": 2,
            "completion_tokens_details": {"reasoning_tokens": 1},
        },
    }
    result = parse_chat_completion_response(
        raw,
        provider="local",
        requested_model="qwen2.5:7b-instruct",
        system_prompt="sys",
        tool_schemas=[ToolSchema(name="x", parameters={})],
        episodes_path=None,
        latency_ms=1.0,
        inference_extras=extras,
        request_bytes=123,
        response_bytes=45,
    )
    assert result.metadata.inference_runtime == "ollama"
    assert result.metadata.hardware_description == "test-machine"
    assert result.metadata.base_url_redacted == "http://localhost:11434"
    assert result.metadata.quantization == "Q4_K_M"
    assert result.metadata.reasoning_tokens == 1
    assert result.metadata.request_bytes == 123
    assert result.metadata.response_bytes == 45


def test_redact_bearer_in_response():
    payload = {"headers": {"Authorization": "Bearer sk-secret"}, "data": "ok"}
    redacted = redact_secrets(payload)
    assert redacted["headers"]["Authorization"] == "[REDACTED]"
    assert redacted["data"] == "ok"

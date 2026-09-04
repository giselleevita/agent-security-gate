"""Adapter-nested tool arguments must reach argument-level policy rules."""

from __future__ import annotations

from app.policy import build_opa_input, disallowed_context_keys, policy_context
from app.schemas import DecideRequest


def _request(context: dict[str, object]) -> DecideRequest:
    return DecideRequest(
        tenant_id="acme",
        session_id="s1",
        action="tool_call",
        tool="docs.read",
        context=context,
    )


def test_flat_context_is_unchanged() -> None:
    context = {"path": "/internal/secrets.yaml", "doc_id": "d1"}

    assert policy_context(_request(context)) == context


def test_nested_arguments_are_visible_to_policy_rules() -> None:
    merged = policy_context(_request({"arguments": {"path": "/internal/secrets.yaml"}}))

    assert merged["path"] == "/internal/secrets.yaml"
    # The nested object survives for policies that want the arguments whole.
    assert merged["arguments"] == {"path": "/internal/secrets.yaml"}


def test_explicit_context_wins_over_a_same_named_argument() -> None:
    merged = policy_context(
        _request({"path": "/public/readme.md", "arguments": {"path": "/internal/secrets.yaml"}})
    )

    assert merged["path"] == "/public/readme.md"


def test_non_mapping_arguments_are_left_alone() -> None:
    merged = policy_context(_request({"arguments": "not-a-mapping"}))

    assert merged == {"arguments": "not-a-mapping"}


def test_opa_input_carries_the_merged_view() -> None:
    opa_input = build_opa_input(
        _request({"arguments": {"path": "/internal/secrets.yaml"}}),
        {"allowed_tools": ["docs.read"], "output_max_chars": 10},
        action_count=1,
    )

    assert opa_input["context"]["path"] == "/internal/secrets.yaml"


def test_output_length_is_derived_from_a_nested_tool_output() -> None:
    opa_input = build_opa_input(
        _request({"arguments": {"tool_output": "0123456789"}}),
        {"allowed_tools": ["docs.read"], "output_max_chars": 5},
        action_count=1,
    )

    assert opa_input["context"]["output_length"] == 10


_ALLOWLIST_POLICY = {"context_keys_allowed": {"docs.read": ["path", "doc_id"]}}


def test_disallowed_context_keys_flags_unreviewed_keys() -> None:
    ctx = {"path": "/public/x", "doc_id": "d1", "sensitivity_label": "public", "evil": "1"}
    assert disallowed_context_keys("docs.read", ctx, _ALLOWLIST_POLICY) == ["evil"]


def test_disallowed_context_keys_allows_derived_and_scanned_keys() -> None:
    ctx = {"path": "/public/x", "tool_output": "x", "output_length": 1, "arguments": {}}
    assert disallowed_context_keys("docs.read", ctx, _ALLOWLIST_POLICY) == []


def test_disallowed_context_keys_skips_unlisted_tools() -> None:
    # A tool with no allowlist entry is not restricted (backwards compatible).
    assert disallowed_context_keys("db.write", {"anything": 1}, _ALLOWLIST_POLICY) == []

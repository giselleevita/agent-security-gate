"""Adapter-nested tool arguments must reach argument-level policy rules."""

from __future__ import annotations

import pytest

from app.policy import build_opa_input, canonicalize_doc_path, policy_context
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


# Red-team RT-001: the path the policy matches on is canonicalised, and the denied prefixes
# are case-folded to the same form, so a non-canonical spelling cannot dodge startswith.


@pytest.mark.parametrize(
    "raw",
    [
        "/internal/secrets.yaml",
        "//internal/secrets.yaml",
        "/INTERNAL/secrets.yaml",
        "/public/../internal/secrets.yaml",
        "/./internal/secrets.yaml",
        "%2finternal%2fsecrets.yaml",
    ],
)
def test_noncanonical_paths_reduce_to_the_denied_prefix(raw: str) -> None:
    opa_input = build_opa_input(
        _request({"path": raw}),
        {"allowed_tools": ["docs.read"], "denied_doc_prefixes": ["/internal/"]},
        action_count=1,
    )
    canonical = opa_input["context"]["path"]
    prefixes = opa_input["config"]["denied_doc_prefixes"]
    assert any(canonical.startswith(p) for p in prefixes), (raw, canonical, prefixes)


def test_canonicalize_helper_folds_case_and_resolves_segments() -> None:
    assert canonicalize_doc_path("//internal/x") == "/internal/x"
    assert canonicalize_doc_path("/INTERNAL/x") == "/internal/x"
    assert canonicalize_doc_path("/public/../internal/x") == "/internal/x"
    assert canonicalize_doc_path("/./internal/x") == "/internal/x"
    assert canonicalize_doc_path("%2finternal%2fx") == "/internal/x"


def test_denied_prefixes_are_case_folded_in_the_opa_config() -> None:
    opa_input = build_opa_input(
        _request({"path": "/Secret/x"}),
        {"allowed_tools": ["docs.read"], "denied_doc_prefixes": ["/SECRET/"]},
        action_count=1,
    )
    assert opa_input["config"]["denied_doc_prefixes"] == ["/secret/"]
    assert opa_input["context"]["path"] == "/secret/x"


def test_benign_path_is_unchanged_apart_from_folding() -> None:
    opa_input = build_opa_input(
        _request({"path": "/public/readme.md"}),
        {"allowed_tools": ["docs.read"], "denied_doc_prefixes": ["/internal/"]},
        action_count=1,
    )
    assert opa_input["context"]["path"] == "/public/readme.md"

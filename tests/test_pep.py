import json
from pathlib import Path

from gateway.models import ToolCallRequest
from gateway.pep import PolicyEnforcementPoint


def build_pep(tmp_path: Path) -> tuple[PolicyEnforcementPoint, Path]:
    audit_path = tmp_path / "audit.jsonl"
    return PolicyEnforcementPoint("policies/data/policy_data.json", audit_log_path=audit_path), audit_path


def read_audit_events(audit_path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in audit_path.read_text().splitlines()]


def test_output_within_limit_passes_unchanged(tmp_path: Path) -> None:
    pep, _ = build_pep(tmp_path)
    decision = pep.decide(
        ToolCallRequest(
            tool="docs.read",
            session_id="session-1",
            params={"doc_id": "intro", "output": "short output"},
            context={"output_max_chars": 20},
        )
    )
    assert decision.output == "short output"
    assert decision.truncated is False


def test_output_exceeding_limit_is_truncated_and_audited(tmp_path: Path) -> None:
    pep, audit_path = build_pep(tmp_path)
    decision = pep.decide(
        ToolCallRequest(
            tool="docs.read",
            session_id="session-1",
            params={"doc_id": "intro", "output": "abcdefghij"},
            context={"output_max_chars": 5},
        )
    )
    assert decision.output == "abcde"
    assert len(decision.output) == 5
    assert decision.truncated is True

    events = read_audit_events(audit_path)
    assert events[-1]["truncated"] is True


def test_denied_doc_prefix_blocks_internal_doc(tmp_path: Path) -> None:
    pep, _ = build_pep(tmp_path)
    decision = pep.decide(
        ToolCallRequest(
            tool="docs.read",
            session_id="prefix-session",
            params={"path": "/internal/secret.yaml"},
            context={"denied_doc_prefixes": ["/internal/"]},
        )
    )
    assert decision.outcome == "deny"
    assert decision.reason == "denied_doc_prefix: /internal/"


def test_denied_doc_prefix_allows_public_doc(tmp_path: Path) -> None:
    pep, _ = build_pep(tmp_path)
    decision = pep.decide(
        ToolCallRequest(
            tool="docs.read",
            session_id="prefix-session",
            params={"path": "/public/readme.md"},
            context={"denied_doc_prefixes": ["/internal/"]},
        )
    )
    assert decision.outcome == "allow"


def test_denied_doc_id_blocks_exact_match(tmp_path: Path) -> None:
    pep, _ = build_pep(tmp_path)
    decision = pep.decide(
        ToolCallRequest(
            tool="docs.read",
            session_id="doc-id-session",
            params={"doc_id": "secret-doc"},
            context={"denied_doc_ids": ["secret-doc"]},
        )
    )
    assert decision.outcome == "deny"
    assert decision.reason == "denied_doc_id: secret-doc"


def test_allowed_doc_id_passes(tmp_path: Path) -> None:
    pep, _ = build_pep(tmp_path)
    decision = pep.decide(
        ToolCallRequest(
            tool="docs.read",
            session_id="doc-id-session",
            params={"doc_id": "public-doc"},
            context={"denied_doc_ids": ["secret-doc"]},
        )
    )
    assert decision.outcome == "allow"


def test_prefix_precedence_over_doc_id(tmp_path: Path) -> None:
    pep, _ = build_pep(tmp_path)
    decision = pep.decide(
        ToolCallRequest(
            tool="docs.read",
            session_id="precedence-session",
            params={"path": "/internal/secret.yaml", "doc_id": "secret-doc"},
            context={
                "denied_doc_prefixes": ["/internal/"],
                "denied_doc_ids": ["secret-doc"],
            },
        )
    )
    assert decision.reason == "denied_doc_prefix: /internal/"


def test_50th_action_is_allowed(tmp_path: Path) -> None:
    pep, _ = build_pep(tmp_path)
    last_decision = None
    for index in range(50):
        last_decision = pep.decide(
            ToolCallRequest(
                tool="docs.read",
                session_id="limit-session",
                params={"doc_id": f"doc-{index}"},
            )
        )
    assert last_decision is not None
    assert last_decision.outcome == "allow"


def test_51st_action_is_denied(tmp_path: Path) -> None:
    pep, _ = build_pep(tmp_path)
    for index in range(50):
        pep.decide(
            ToolCallRequest(
                tool="docs.read",
                session_id="limit-session",
                params={"doc_id": f"doc-{index}"},
            )
        )
    decision = pep.decide(
        ToolCallRequest(tool="docs.read", session_id="limit-session", params={"doc_id": "doc-51"})
    )
    assert decision.outcome == "deny"
    assert decision.reason == "max_actions_exceeded"


def test_new_session_starts_fresh_counter(tmp_path: Path) -> None:
    pep, _ = build_pep(tmp_path)
    for index in range(51):
        pep.decide(
            ToolCallRequest(
                tool="docs.read",
                session_id="limit-session",
                params={"doc_id": f"doc-{index}"},
            )
        )
    decision = pep.decide(
        ToolCallRequest(tool="docs.read", session_id="fresh-session", params={"doc_id": "doc-1"})
    )
    assert decision.outcome == "allow"

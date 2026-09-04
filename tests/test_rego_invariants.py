"""
Bounded exhaustive check of policy invariants against the real OPA decision.

This enumerates a small cross-product of tool, context, session, and exception states and
asserts properties that must hold for *every* combination — not a formal proof, but a
complete sweep of the modelled input space. See docs/adr/0006-bounded-policy-checks.md.
"""

from __future__ import annotations

import itertools

import pytest

from app.opa_local import eval_decision

CONFIG = {
    "allowed_tools": ["docs.read", "http.get"],
    "approval_required_tools": ["db.write"],
    "denied_doc_prefixes": ["/internal/"],
    "denied_doc_ids": ["secret-1"],
    "output_max_chars": 100,
    "max_actions": 50,
    "allowed_http_domains": ["api.example.com"],
}

TOOLS = ["docs.read", "http.get", "db.write", "shell.exec"]  # last is unknown
PATHS = ["/public/ok", "/internal/secret"]
SENSITIVITIES = ["", "public", "confidential", "secret"]
ACTION_COUNTS = [1, 51]
OUTPUT_LENGTHS = [0, 101]
EXCEPTIONS = [
    [],
    [{"id": "ex-broad", "tool": "docs.read", "context_match": {}}],
    [{"id": "ex-broad-db", "tool": "db.write", "context_match": {}}],
]

def _cases():
    return itertools.product(TOOLS, PATHS, SENSITIVITIES, ACTION_COUNTS, OUTPUT_LENGTHS, EXCEPTIONS)


@pytest.fixture(scope="module")
def _opa_available():
    try:
        eval_decision(
            {
                "action": "tool_call",
                "tool": "docs.read",
                "context": {"path": "/public/ok"},
                "config": CONFIG,
                "session": {"action_count": 1},
                "active_exceptions": [],
            }
        )
    except RuntimeError as exc:
        pytest.skip(str(exc))


@pytest.mark.usefixtures("_opa_available")
def test_policy_invariants_hold_for_every_modelled_input():
    checked = 0
    for tool, path, sens, count, out_len, exceptions in _cases():
        context = {"path": path, "output_length": out_len}
        if sens:
            context["sensitivity_label"] = sens
        d = eval_decision(
            {
                "action": "tool_call",
                "tool": tool,
                "context": context,
                "config": CONFIG,
                "session": {"action_count": count},
                "active_exceptions": exceptions,
            }
        )
        allow = bool(d["allow"])
        checked += 1

        rail_tripped = (
            tool == "shell.exec"
            or sens in {"confidential", "secret"}
            or count > CONFIG["max_actions"]
            or out_len > CONFIG["output_max_chars"]
        )

        # 1. Any safety rail forces a denial, regardless of exceptions. (The reported
        #    reason string is precedence-dependent and may name a co-occurring deny.)
        if rail_tripped:
            assert allow is False

        # 2. Sensitivity has top precedence: confidential/secret always names itself.
        if sens in {"confidential", "secret"}:
            assert d["deny_reason"] == "sensitivity_label_denied"

        # 3. allow implies no outstanding approval requirement and no safety-rail state.
        if allow:
            assert d["approval_required"] is False
            assert not rail_tripped

        # 4. db.write without a matching exception must route to approval, never straight
        #    allow.
        if tool == "db.write" and not exceptions and not rail_tripped:
            assert allow is False and d["approval_required"] is True

    assert checked == len(list(_cases()))

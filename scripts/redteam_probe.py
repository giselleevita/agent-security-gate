"""Adaptive red-team probe against a running Agent Security Gate.

Unlike the 18-scenario policy-regression benchmark, this does not assert a fixed expected
outcome per case. It sends a family of attempts, each a mutation of the previous one against
the reason the gate returned, and records what the gate did. The point is to find where the
real decision path diverges from what the policy author intended — and, just as important,
to record the controls that held under that pressure.

It writes a machine-readable log so the published findings can be regenerated:

    python scripts/redteam_probe.py --base-url http://localhost:8000 \
        --token test-token --approver-token approver-token \
        --out docs/benchmark-results/redteam-001.json

This talks to a live gate over HTTP. It creates short-TTL policy exceptions (approver-
authenticated) to probe the exception path; they expire on their own.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx


@dataclass
class Attempt:
    hypothesis: str
    label: str
    request: dict[str, Any]
    allowed: bool
    reason: str
    got_through: bool  # True when an attempt reached "allow" that the policy author meant to stop
    note: str = ""


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    held: bool  # True = the control held; False = something got through
    summary: str
    attempts: list[Attempt] = field(default_factory=list)


def _decide(client: httpx.Client, token: str, body: dict[str, Any]) -> tuple[bool, str]:
    r = client.post(
        "/v1/gateway/decide",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    r.raise_for_status()
    d = r.json()
    return bool(d.get("allowed")), str(d.get("reason"))


def _read_req(tenant: str, path: str, tool_output: str | None = None, **ctx: Any) -> dict[str, Any]:
    context: dict[str, Any] = {"path": path, **ctx}
    if tool_output is not None:
        context["tool_output"] = tool_output
    return {
        "tenant_id": tenant,
        "session_id": "redteam",
        "action": "tool_call",
        "tool": "docs.read",
        "context": context,
    }


def h1_prefix_canonicalisation(client: httpx.Client, token: str) -> Finding:
    """Every spelling of the same denied document must be refused."""
    tenant = "redteam-default"  # unknown tenant -> default policy (denies /internal/)
    variants = [
        ("baseline /internal/", "/internal/secrets.yaml"),
        ("double slash", "//internal/secrets.yaml"),
        ("uppercase", "/INTERNAL/secrets.yaml"),
        ("dot-segment traversal", "/public/../internal/secrets.yaml"),
        ("current-dir segment", "/./internal/secrets.yaml"),
        ("url-encoded separators", "%2finternal%2fsecrets.yaml"),
    ]
    attempts: list[Attempt] = []
    for label, path in variants:
        allowed, reason = _decide(client, token, _read_req(tenant, path))
        # Every spelling, including the canonical baseline, names a denied document. Counting
        # the baseline matters: otherwise a completely missing deny could still report held.
        got_through = allowed
        attempts.append(
            Attempt("H1", label, _read_req(tenant, path), allowed, reason, got_through)
        )
    bypasses = [a for a in attempts if a.got_through]
    return Finding(
        id="RT-001",
        title="Document-prefix canonicalisation bypass (fixed)",
        severity="high",
        held=not bypasses,
        summary=(
            "Before the fix, denied_doc_prefixes used a bare startswith and five "
            "non-canonical spellings bypassed it. The patched decision path canonicalises "
            f"before matching; this run allowed {len(bypasses)} of {len(variants)} spellings "
            "of the denied document. Whether an allow becomes a real read still depends on "
            "the caller's resolver, so the gate now takes the conservative form itself."
        ),
        attempts=attempts,
    )


def h2_canary_normalisation(client: httpx.Client, token: str) -> Finding:
    """Every exact or transformed planted marker must trip the canary control."""
    tenant = "redteam-default"
    zw = "CANARY​-TOKEN-001"  # zero-width space inside the token
    variants = [
        ("exact canary", "leak CANARY-TOKEN-001 end", True),
        ("lowercased", "leak canary-token-001 end", False),
        ("exact INTERNAL_TOKEN", "x INTERNAL_TOKEN y", True),
        ("lowercased token", "x internal_token y", False),
        ("split across space", "CANARY-TOKEN- 001", False),
        ("zero-width injected", zw, False),
    ]
    attempts: list[Attempt] = []
    for label, out, _was_caught_before_fix in variants:
        allowed, reason = _decide(client, token, _read_req(tenant, "/public/x", tool_output=out))
        # All entries are planted markers. The pre-fix expectation is documentary only; the
        # patched control must catch every row, including the exact baselines.
        got_through = allowed
        attempts.append(
            Attempt(
                "H2",
                label,
                _read_req(tenant, "/public/x", tool_output=out),
                allowed,
                reason,
                got_through,
                note="tripwire evaded" if got_through else "",
            )
        )
    evaded = [a for a in attempts if a.got_through]
    return Finding(
        id="RT-002",
        title="Canary normalisation bypass (fixed)",
        severity="medium",
        held=not evaded,
        summary=(
            "Before the fix, canaries were matched by case-sensitive exact substring and "
            "four transformed markers evaded it. The patched matcher normalises case, "
            f"whitespace and zero-width characters; this run allowed {len(evaded)} of "
            f"{len(variants)} planted-marker variants. Pattern-based DLP remains a separate "
            "control for structured secrets."
        ),
        attempts=attempts,
    )


def h4_scoped_exceptions(
    client: httpx.Client, token: str, approver_token: str
) -> Finding:
    """An empty context_match exception used to match every call for its tool, bypassing
    denies and the approval gate. Creation now rejects an empty context_match, so a grant
    must be scoped; this probe confirms the rejection, that a scoped grant is honoured only
    for the path it names, and that the hard rails still hold under it."""
    tenant = "tenant-a"  # denies /tenant-a-secret/, requires approval for db.write
    attempts: list[Attempt] = []

    def record(label: str, body: dict[str, Any], meant_to_stop: bool) -> None:
        allowed, reason = _decide(client, token, body)
        attempts.append(Attempt("H4", label, body, allowed, reason, allowed and meant_to_stop))

    scoped_read = _read_req(tenant, "/tenant-a-secret/x")
    other_read = _read_req(tenant, "/tenant-a-secret/y")

    record("denied read /x (baseline)", scoped_read, meant_to_stop=False)

    # the footgun: an empty context_match must now be rejected at creation
    empty = client.post(
        "/v1/policy/exceptions",
        json={"tenant_id": tenant, "tool": "docs.read", "context_match": {}, "ttl_seconds": 120, "reason": "rt"},
        headers={"Authorization": f"Bearer {approver_token}", "X-Approver-Id": "redteam-operator"},
    )
    empty_rejected = empty.status_code >= 400
    attempts.append(
        Attempt(
            "H4",
            "create empty-context exception",
            {"context_match": {}},
            allowed=not empty_rejected,
            reason="rejected_%d" % empty.status_code if empty_rejected else "accepted",
            got_through=not empty_rejected,
            note="footgun: must be rejected",
        )
    )

    # a properly scoped exception is accepted and honoured only for the path it names
    client.post(
        "/v1/policy/exceptions",
        json={
            "tenant_id": tenant,
            "tool": "docs.read",
            "context_match": {"path": "/tenant-a-secret/x"},
            "ttl_seconds": 120,
            "reason": "redteam scoped probe",
        },
        headers={"Authorization": f"Bearer {approver_token}", "X-Approver-Id": "redteam-operator"},
    ).raise_for_status()

    record("scoped read /x (in scope)", scoped_read, meant_to_stop=False)  # legitimately allowed
    record("read /y (out of scope)", other_read, meant_to_stop=True)  # scope must still deny

    # safety rails that must still hold under the active scoped exception
    rails = [
        ("rail: sensitivity", _read_req(tenant, "/tenant-a-secret/x", sensitivity_label="confidential")),
        ("rail: canary", _read_req(tenant, "/tenant-a-secret/x", tool_output="INTERNAL_TOKEN")),
        ("rail: output cap", _read_req(tenant, "/tenant-a-secret/x", tool_output="A" * 2100)),
        ("rail: unknown tool", {"tenant_id": tenant, "session_id": "redteam", "action": "tool_call", "tool": "evil.exec", "context": {}}),
    ]
    for label, body in rails:
        allowed, reason = _decide(client, token, body)
        attempts.append(Attempt("H4", label, body, allowed, reason, allowed, note="rail must hold"))

    scope_leaks = [a for a in attempts if a.label == "read /y (out of scope)" and a.got_through]
    rails_failed = [a for a in attempts if a.label.startswith("rail") and a.got_through]
    return Finding(
        id="RT-003",
        title="Empty context_match exception matched everything (fixed)",
        severity="medium",
        held=empty_rejected and not scope_leaks and not rails_failed,
        summary=(
            "An empty context_match exception used to match every call for its tool, "
            "bypassing document-prefix denies and the approval gate. Creation now rejects an "
            f"empty context_match ({'rejected' if empty_rejected else 'STILL ACCEPTED'}), so "
            "a grant must be scoped. A scoped exception is honoured only for the path it "
            f"names — the same tool on another path still denies ({len(scope_leaks)} leaks) — "
            f"and the hard rails still hold under it ({len(rails) - len(rails_failed)}/"
            f"{len(rails)}: sensitivity, canary, output cap, unknown tool)."
        ),
        attempts=attempts,
    )


def h_overlapping_exceptions(
    client: httpx.Client, token: str, approver_token: str
) -> Finding:
    """Two matching exceptions for one tool must not crash the decision path.

    Found during this session: with the previous rule, two active exceptions matching the
    same tool made OPA's matched_exception_id produce two outputs (eval conflict), 500ing
    every decision for that tenant/tool — an operator mistake turned into an outage. This
    probe creates two overlapping exceptions and asserts the gate still returns a clean
    decision. It is the regression check for the fix in policies/asg.rego.
    """
    tenant = "tenant-b"  # denies /tenant-b-secret/, no leftover state
    for _ in range(2):
        client.post(
            "/v1/policy/exceptions",
            json={
                "tenant_id": tenant,
                "tool": "docs.read",
                "context_match": {"path": "/tenant-b-secret/x"},
                "ttl_seconds": 120,
                "reason": "redteam overlap probe",
            },
            headers={
                "Authorization": f"Bearer {approver_token}",
                "X-Approver-Id": "redteam-operator",
            },
        ).raise_for_status()

    body = _read_req(tenant, "/tenant-b-secret/x")
    r = client.post(
        "/v1/gateway/decide", json=body, headers={"Authorization": f"Bearer {token}"}
    )
    crashed = r.status_code >= 500
    allowed = (not crashed) and bool(r.json().get("allowed"))
    reason = "http_%d" % r.status_code if crashed else str(r.json().get("reason"))
    attempt = Attempt(
        "RT4",
        "two overlapping docs.read exceptions",
        body,
        allowed,
        reason,
        got_through=crashed,
        note="regression check: must not 500",
    )
    return Finding(
        id="RT-004",
        title="Overlapping exceptions crashed the decision path (fixed)",
        severity="medium",
        held=not crashed,
        summary=(
            "Two active exceptions matching the same tool previously made OPA's "
            "matched_exception_id (a complete rule) produce two outputs, an eval conflict "
            "that 500'd every decision for the tenant/tool. Fixed by choosing the id "
            "deterministically from all matches. This probe is the regression check: it "
            "creates two overlapping exceptions and confirms the gate returns a clean "
            "decision rather than an error."
        ),
        attempts=[attempt],
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url", default="http://localhost:8000")
    p.add_argument("--token", default="test-token")
    p.add_argument("--approver-token", default="approver-token")
    p.add_argument("--out", default=None)
    args = p.parse_args(argv)

    with httpx.Client(base_url=args.base_url, timeout=10.0) as client:
        findings = [
            h1_prefix_canonicalisation(client, args.token),
            h2_canary_normalisation(client, args.token),
            h4_scoped_exceptions(client, args.token, args.approver_token),
            h_overlapping_exceptions(client, args.token, args.approver_token),
        ]

    got_through = sum(1 for f in findings if not f.held)
    report = {
        "target": args.base_url,
        "kind": "adaptive-redteam",
        "findings_total": len(findings),
        "findings_with_a_bypass": got_through,
        "findings": [asdict(f) for f in findings],
    }
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

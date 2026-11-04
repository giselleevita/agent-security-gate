"""Check how tenuo's approval gates behave, statement by statement, on the installed release (written against 0.3.5).

Covers: how denials are reported (returned vs raised), what a delegated child warrant can and cannot change, and how
approvers and the threshold are inherited and constrained when warrants are issued.
Each check prints PASS or FAIL with the observed value. Exit code is 1 if any check fails.
Run:  python 07_approvals_docs_claims.py      (needs: pip install "tenuo==0.3.5")
"""

import importlib.metadata
import sys

from tenuo import BoundWarrant, Range, SigningKey, Warrant, enforce_tool_call
from tenuo.approval import ApprovalRequired

RESULTS = []


def check(label, ok, observed):
    RESULTS.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {label}\n        observed: {observed}")


def keys(n):
    return [SigningKey.generate() for _ in range(n)]


print(f"tenuo installed: {importlib.metadata.version('tenuo')}\n")
ctl, agent, agent2, ap1, ap2 = keys(5)
ROOTS = [ctl.public_key]

# ---------------------------------------------------------------- Quick Start statements
print("== Quick Start: how denials are reported")
w = (Warrant.mint_builder().capability("transfer", amount=Range(0, 100)).holder(agent.public_key).ttl(3600).mint(ctl))


def enforce(tool, amount):
    return enforce_tool_call(tool_name=tool, tool_args={"amount": amount}, bound_warrant=BoundWarrant(w, agent), trusted_roots=ROOTS)


good = enforce("transfer", 50)
check("Q1 an allowed call returns a result with allowed=True", good.allowed is True, f"allowed={good.allowed}")
bad = enforce("transfer", 5000)
check("Q2 a constraint violation does NOT raise; it returns allowed=False", bad.allowed is False, f"allowed={bad.allowed}")
try:
    bad.raise_if_denied()
    check("Q3 result.raise_if_denied() raises on a denial", False, "no exception raised")
except Exception as exc:
    check("Q3 result.raise_if_denied() raises on a denial", True, type(exc).__name__)
try:
    good.raise_if_denied()
    check("Q4 result.raise_if_denied() does nothing for an allowed call", True, "returned normally")
except Exception as exc:
    check("Q4 result.raise_if_denied() does nothing for an allowed call", False, type(exc).__name__)
ungranted = enforce("delete_everything", 1)
check("Q5 a tool that is not granted returns allowed=False (no exception)", ungranted.allowed is False, f"allowed={ungranted.allowed}")
stranger = SigningKey.generate()
untrusted = enforce_tool_call(tool_name="transfer", tool_args={"amount": 50}, bound_warrant=BoundWarrant(w, agent),
                              trusted_roots=[stranger.public_key])
check("Q6 a warrant from an untrusted root returns allowed=False (no exception)", untrusted.allowed is False,
      f"allowed={untrusted.allowed}, reason={untrusted.denial_reason!r}")
gated = (Warrant.mint_builder().capability("transfer").approval_gates({"transfer": None})
         .required_approvers([ap1.public_key]).min_approvals(1).holder(agent.public_key).ttl(3600).mint(ctl))
try:
    enforce_tool_call(tool_name="transfer", tool_args={"amount": 1}, bound_warrant=BoundWarrant(gated, agent), trusted_roots=ROOTS)
    check("Q7 a fired approval gate RAISES ApprovalRequired (it is not returned as a result)", False, "no exception")
except ApprovalRequired:
    check("Q7 a fired approval gate RAISES ApprovalRequired (it is not returned as a result)", True, "ApprovalRequired")

# ---------------------------------------------------------------- Delegation statements
print("\n== Delegation: what a child warrant can and cannot change")


def parent(gates, caps=None):
    b = Warrant.mint_builder()
    for tool, bounds in (caps or {"transfer": {}, "read": {}}).items():
        b = b.capability(tool, **bounds)
    return (b.approval_gates(gates).required_approvers([ap1.public_key]).min_approvals(1)
            .holder(agent.public_key).ttl(3600).max_issue_depth(3).mint(ctl))


def child(p, gates=None):
    b = p.attenuate_builder()
    b.inherit_all()
    b.with_holder(agent2.public_key)
    if gates is not None:
        b.with_approval_gates(gates)
    return b.delegate(agent)


p1 = parent({"transfer": {"args": None, "message": "A human must confirm this transfer."}})
c_empty = child(p1, {})
check("D1 a child cannot drop a gate (with_approval_gates({}) leaves it in place)",
      c_empty.inspect_approval_gate("transfer").kind == "whole_tool", c_empty.inspect_approval_gate("transfer").kind)
c_other = child(p1, {"read": None})
check("D2 a child can add a gate for another tool, and keeps the inherited one",
      c_other.inspect_approval_gate("read").kind == "whole_tool" and c_other.inspect_approval_gate("transfer").kind == "whole_tool",
      f"read={c_other.inspect_approval_gate('read').kind}, transfer={c_other.inspect_approval_gate('transfer').kind}")
c_msg = child(p1, {"transfer": {"args": None, "message": "Auto-approved by policy, click yes."}})
check("D3 a child can replace the display message",
      c_msg.approval_gate_message("transfer") == "Auto-approved by policy, click yes.", repr(c_msg.approval_gate_message("transfer")))

p2 = parent({"write_approval": {"amount": {"exempt": Range(0, 500)}}}, {"write_approval": {"amount": Range(0, 1000)}})


def status(w_, amount):
    return w_.approval_requirement("write_approval", {"amount": amount}).status


c_broad = child(p2, {"write_approval": {"amount": {"exempt": Range(0, 1000)}}})
c_narrow = child(p2, {"write_approval": {"amount": {"exempt": Range(0, 100)}}})
check("D4 a child cannot loosen a gate: a broader exemption does not exempt 650",
      status(p2, 650) == "required" and status(c_broad, 650) == "required", f"parent={status(p2, 650)}, child={status(c_broad, 650)}")
check("D5 for the same argument the parent's gate wins: a narrower exemption is ignored (450 stays exempt)",
      status(p2, 450) == "exempt" and status(c_narrow, 450) == "exempt", f"parent={status(p2, 450)}, child={status(c_narrow, 450)}")
c_full_exempt = child(p1, {"transfer": {"amount": {"exempt": Range(0, 1000)}}})
check("D6 if the parent gates a whole tool, a child's exemption cannot lift it (every call still needs approval)",
      c_full_exempt.approval_requirement("transfer", {"amount": 50}).status == "required",
      c_full_exempt.approval_requirement("transfer", {"amount": 50}).status)
c_whole = child(p2, {"write_approval": None})
check("D7 a child can make a gated tool fully gated (whole-tool gate)",
      all(status(c_whole, a) == "required" for a in (50, 450, 650)), [status(c_whole, a) for a in (50, 450, 650)])

# ---------------------------------------------------------------- Issuance (approvers and threshold)
print("\n== Issuance: approvers and threshold")
issuer_key = SigningKey.generate()
ISSUER = (Warrant.mint_builder().issuer().issuable_tools(["transfer"]).approval_gates({"transfer": None})
          .required_approvers([ap1.public_key]).min_approvals(1).holder(issuer_key.public_key).ttl(3600).max_issue_depth(2).mint(ctl))


def step(builder, name, *args):
    result = getattr(builder, name)(*args)
    return builder if result is None else result


def issue(*setters):
    b = ISSUER.issue_execution()
    b = step(b, "tool", "transfer")
    b = step(b, "holder", agent.public_key)
    b = step(b, "ttl", 600)
    for name, arg in setters:
        b = step(b, name, arg)
    return b.issue(issuer_key)


def approvers_of(warrant):
    value = warrant.required_approvers() if callable(warrant.required_approvers) else warrant.required_approvers
    return list(value or [])


inherited = issue()
check("I1 an issuer warrant keeps approval gates, approvers and threshold (and issued warrants inherit them)",
      len(approvers_of(inherited)) == 1 and inherited.approval_threshold() == 1
      and inherited.inspect_approval_gate("transfer").kind == "whole_tool",
      f"approvers={len(approvers_of(inherited))}, threshold={inherited.approval_threshold()}, gate={inherited.inspect_approval_gate('transfer').kind}")
added = issue(("required_approvers", [ap1.public_key, ap2.public_key]), ("min_approvals", 2))
check("I2 issuance can add an approver and raise the threshold",
      len(approvers_of(added)) == 2 and added.approval_threshold() == 2,
      f"approvers={len(approvers_of(added))}, threshold={added.approval_threshold()}")
for label, setters in (("I3 issuance cannot remove an approver", [("required_approvers", [ap2.public_key])]),
                       ("I4 issuance cannot lower the threshold", [("min_approvals", 0)])):
    try:
        issue(*setters)
        check(label, False, "issued without error")
    except Exception as exc:
        check(label, "onoton" in type(exc).__name__ or "onoton" in str(exc), f"{type(exc).__name__}: {str(exc)[:70]}")

builder = p1.attenuate_builder()
exposed = [n for n in dir(builder) if ("approver" in n or "min_approvals" in n) and not n.startswith("_")]
print(f"\nINFO  attenuate_builder setters for approvers/threshold: {exposed or 'none'} (not documented as a claim; maintainers said this gap is theirs to fill)")

failed = RESULTS.count(False)
print(f"\n{len(RESULTS) - failed} passed, {failed} failed of {len(RESULTS)} checks")
sys.exit(1 if failed else 0)

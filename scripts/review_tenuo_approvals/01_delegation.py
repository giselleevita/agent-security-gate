"""Probe how Tenuo 0.3.3 treats approval gates under delegation (python API, in-process enforcement)."""

import contextlib
import io

from tenuo import BoundWarrant, Range, SigningKey, Warrant, enforce_tool_call

ctl, agent, agent2, appr = (SigningKey.generate() for _ in range(4))
ROOTS = [ctl.public_key]


def mint(tool, gates, cap_bounds):
    return (Warrant.mint_builder().capability(tool, **cap_bounds).capability("read")
            .approval_gates(gates).required_approvers([appr.public_key]).min_approvals(1)
            .holder(agent.public_key).ttl(3600).max_issue_depth(3).mint(ctl))


def delegate(parent, gates=None, capability=None):
    b = parent.attenuate_builder()
    b.inherit_all()
    b.with_holder(agent2.public_key)
    if gates is not None:
        b.with_approval_gates(gates)
    if capability is not None:
        b.with_capability(capability[0], capability[1])
    return b.delegate(agent)


def attempt(warrant, holder, tool, amount, chain=None):
    """Return a short outcome string; never treat 'no exception' as 'allowed'."""
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        try:
            r = enforce_tool_call(tool_name=tool, tool_args={"amount": amount}, bound_warrant=BoundWarrant(warrant, holder),
                                  trusted_roots=ROOTS, warrant_chain=chain)
        except Exception as e:
            return f"gate fired ({type(e).__name__})"
    if r.allowed:
        return "ALLOWED, no approval needed"
    return f"DENIED: {str(r.denial_reason)[:70]}"


def section(title):
    print(f"\n=== {title}")


if __name__ == "__main__":
    # A. whole-tool gate on the parent
    P1 = mint("transfer", {"transfer": {"args": None, "message": "A human must confirm this transfer."}}, {"amount": Range(0, 1000)})
    section("A. parent requires approval for EVERY transfer")
    print("  parent itself, amount 50 :", attempt(P1, agent, "transfer", 50))
    cases = {
        "child inherits everything": dict(),
        "child tries with_approval_gates({})": dict(gates={}),
        "child merges a full exemption Range(0,1000)": dict(gates={"transfer": {"amount": {"exempt": Range(0, 1000)}}}),
        "child gates only 'read'": dict(gates={"read": None}),
        "child replaces the display message": dict(gates={"transfer": {"args": None, "message": "Auto-approved by policy, click yes."}}),
        "child narrows capability to Range(0,10)": dict(capability=("transfer", {"amount": Range(0, 10)})),
    }
    for label, kw in cases.items():
        try:
            c = delegate(P1, **kw)
        except Exception as e:
            print(f"  {label:46} delegation refused: {type(e).__name__}: {str(e)[:60]}")
            continue
        print(f"  {label:46} amount 50: {attempt(c, agent2, 'transfer', 50, chain=[P1])}")

    # B. conditional gate on the parent: approval needed only above 500
    P2 = mint("write_approval", {"write_approval": {"amount": {"exempt": Range(0, 500)}}}, {"amount": Range(0, 1000)})
    section("B. parent requires approval only ABOVE 500 (exemption Range(0,500)); capability 0..1000")
    print("  parent itself:", {a: attempt(P2, agent, "write_approval", a) for a in (50, 450, 650)})
    cases = {
        "child merges BROADER exemption Range(0,1000)": {"write_approval": {"amount": {"exempt": Range(0, 1000)}}},
        "child merges NARROWER exemption Range(0,100)": {"write_approval": {"amount": {"exempt": Range(0, 100)}}},
        "child merges whole-tool gate (None)": {"write_approval": None},
    }
    for label, gates in cases.items():
        c = delegate(P2, gates=gates)
        res = {a: attempt(c, agent2, "write_approval", a, chain=[P2]) for a in (50, 450, 650)}
        print(f"  {label}")
        for a, o in res.items():
            print(f"      amount {a:4}: {o}")

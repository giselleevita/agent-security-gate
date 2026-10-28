"""Which denials raise, and which only return allowed=False? Uses the shape of the approvals.md Quick Start."""

import contextlib
import io

from tenuo import BoundWarrant, Range, SigningKey, Warrant, enforce_tool_call

control_key, agent_key, other_key = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
warrant = (Warrant.mint_builder().capability("transfer", amount=Range(0, 100)).capability("search")
           .holder(agent_key.public_key).ttl(3600).mint(control_key))


def run(label, **kw):
    args = dict(tool_name="transfer", tool_args={"amount": 50}, bound_warrant=BoundWarrant(warrant, agent_key),
                trusted_roots=[control_key.public_key])
    args.update(kw)
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        try:
            result = enforce_tool_call(**args)
        except Exception as e:
            print(f"  {label:50} RAISES {type(e).__name__}")
            return
    log = err.getvalue().strip().splitlines()
    print(f"  {label:50} returns allowed={result.allowed} | reason={str(result.denial_reason)[:48]!r} | stderr={'yes' if log else 'no'}")


print("Quick-Start shape: `result = enforce_tool_call(...)` with the result NOT checked")
run("legitimate call (amount 50 within 0..100)")
run("amount 5000 (violates Range(0,100))", tool_args={"amount": 5000})
run("tool not granted ('delete_everything')", tool_name="delete_everything", tool_args={})
run("wrong trusted root (stranger key)", trusted_roots=[other_key.public_key])
run("holder key mismatch (signing key != holder)", bound_warrant=BoundWarrant(warrant, other_key))

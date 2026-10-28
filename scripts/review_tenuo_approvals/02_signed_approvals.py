"""Signed approvals: binding to the call and warrant, approver set, duplicates, m-of-n (tenuo 0.3.3, in-process)."""

from tenuo import BoundWarrant, Range, SigningKey, Warrant, enforce_tool_call
from tenuo.approval import ApprovalRequired, sign_approval

ctl, agent, a1, a2, stranger = (SigningKey.generate() for _ in range(5))
ROOTS = [ctl.public_key]


def mint(approvers, threshold):
    return (Warrant.mint_builder().capability("transfer", amount=Range(0, 100000))
            .approval_gates({"transfer": None}).required_approvers([k.public_key for k in approvers])
            .min_approvals(threshold).holder(agent.public_key).ttl(3600).mint(ctl))


def call(w, amount, approvals=None):
    try:
        r = enforce_tool_call(tool_name="transfer", tool_args={"amount": amount}, bound_warrant=BoundWarrant(w, agent),
                              trusted_roots=ROOTS, approvals=approvals)
    except ApprovalRequired as e:
        return "NEEDS APPROVAL", e
    except Exception as e:
        return f"raised {type(e).__name__}: {str(e)[:70]}", None
    return ("ALLOWED" if r.allowed else f"DENIED: {str(r.denial_reason)[:70]}"), None


def request_for(w, amount):
    _, exc = call(w, amount)
    return exc.request


w1 = mint([a1], 1)
req50 = request_for(w1, 50)
ok50 = sign_approval(req50, a1)
print("1-of-1 warrant")
print("  no approval, amount 50                         :", call(w1, 50)[0])
print("  approval signed for amount 50, used for 50     :", call(w1, 50, [ok50])[0])
print("  SAME approval reused for amount 5000           :", call(w1, 5000, [ok50])[0])
print("  approval signed by a key NOT in the approver set:", call(w1, 50, [sign_approval(req50, stranger)])[0])

w2 = mint([a1, a2], 2)
req = request_for(w2, 50)
s1 = sign_approval(req, a1)
s1b = sign_approval(req, a1)
s2 = sign_approval(req, a2)
print("2-of-2 warrant")
print("  only approver 1                                :", call(w2, 50, [s1])[0])
print("  approver 1 signs twice (duplicate)             :", call(w2, 50, [s1, s1b])[0])
print("  approvers 1 and 2                              :", call(w2, 50, [s1, s2])[0])

# a different warrant with the same approver set: is the approval bound to the warrant id?
w3 = mint([a1], 1)
print("approval from warrant w1 presented to a different warrant w3 (same approver, same call):", call(w3, 50, [ok50])[0])

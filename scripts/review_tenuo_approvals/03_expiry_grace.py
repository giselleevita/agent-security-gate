"""How long after expiry is a signed approval still accepted? (tenuo 0.3.3, in-process)

Signs an approval with ttl_seconds=1 and presents it at increasing delays. The docs say "strict expiry"; the source
defines CLOCK_SKEW_TOLERANCE_SECS = 30. Takes about 65 seconds to run.
"""

import time

from tenuo import BoundWarrant, Range, SigningKey, Warrant, enforce_tool_call
from tenuo.approval import ApprovalRequired, sign_approval

control, agent, approver = (SigningKey.generate() for _ in range(3))

warrant = (
    Warrant.mint_builder()
    .capability("transfer", amount=Range(0, 100000))
    .approval_gates({"transfer": None})
    .required_approvers([approver.public_key])
    .min_approvals(1)
    .holder(agent.public_key)
    .ttl(3600)
    .mint(control)
)


def call(approvals=None):
    return enforce_tool_call(
        tool_name="transfer",
        tool_args={"amount": 50},
        bound_warrant=BoundWarrant(warrant, agent),
        trusted_roots=[control.public_key],
        approvals=approvals,
    )


try:
    call()
except ApprovalRequired as exc:
    request = exc.request

approval = sign_approval(request, approver, ttl_seconds=1)
start = time.time()
for delay in (5, 20, 29, 31, 33, 40, 50, 65):
    time.sleep(max(0, delay - (time.time() - start)))
    try:
        outcome = "ALLOWED" if call([approval]).allowed else "DENIED"
    except Exception as exc:
        outcome = f"raised {type(exc).__name__}"
    print(f"{delay:3}s after signing (approval lifetime was 1s): {outcome}", flush=True)

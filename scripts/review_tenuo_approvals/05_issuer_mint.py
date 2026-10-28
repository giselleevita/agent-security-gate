"""Do approval settings survive minting an ISSUER warrant? Compare payload contents with an execution warrant."""

from tenuo import SigningKey, Warrant

ctl, holder, approver = (SigningKey.generate() for _ in range(3))
approver_bytes = bytes(approver.public_key.to_bytes())


def build(kind):
    b = Warrant.mint_builder()
    b = b.issuer().issuable_tools(["transfer"]) if kind == "issuer" else b.capability("transfer")
    return (b.approval_gates({"transfer": None}).required_approvers([approver.public_key]).min_approvals(1)
            .holder(holder.public_key).ttl(3600).max_issue_depth(2).mint(ctl))


for kind in ("issuer", "execution"):
    w = build(kind)
    payload = bytes(w.payload_bytes)
    print(f"{kind:10} payload {len(payload):4} bytes | has the approver's key: {approver_bytes in payload}"
          f" | has the gate map: {b'approval_gates' in payload} | approval_threshold(): {w.approval_threshold()}")

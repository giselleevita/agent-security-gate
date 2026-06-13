# Enforcing Agent Security at the Tool-Call Boundary

Most LLM security work focuses on the prompt: jailbreak detection, output filtering,
instruction hierarchy. That layer is necessary but incomplete. Once an agent can call
tools, the real risk moves to **what gets executed** — file reads, HTTP requests,
database writes, and workflow approvals.

Agent Security Gate (ASG) is a reference implementation that enforces policy **before**
tool execution, not after damage.

## The control point

ASG sits between the agent runtime and tool adapters:

1. The agent proposes an action (tool, args, context).
2. ASG builds an OPA input document and evaluates Rego policy.
3. The decision is **allow**, **deny**, or **require_approval**.
4. Only allowed (or approved) actions reach the adapter.
5. Every decision is appended to a hash-chained audit log.

This is the same boundary enterprise security teams care about for service meshes and
API gateways — applied to autonomous agents.

## What v0.3.0 demonstrates

The current release is deliberately bounded: a portfolio-grade reference, not a
certified appliance. It still shows concrete controls recruiters and reviewers can
verify in minutes:

| Control | Mechanism |
|---------|-----------|
| Tool allowlisting | OPA Rego fails closed on unknown tools |
| SSRF defense | URL policy blocks metadata endpoints and literals |
| Human-in-the-loop | Postgres-backed approvals bound to exact operations |
| DLP / canary | Response scanning for secrets and canary tokens |
| Tamper-evident audit | Hash-chained JSONL with verification script |
| Measurable gate effect | Benchmark compares explicit `no_gate` vs `gate` baselines |

Verified on 18 deterministic scenarios (5 runs each): **no-gate ASR 100% / leakage
100%** → **gate ASR 0% / leakage 0% / false positives 0%**.

## Why policy-as-code

Hard-coded `if` statements do not scale across agents, tenants, or compliance regimes.
ASG uses Open Policy Agent so rules are versioned, testable, and reviewable — the same
model Kubernetes admission and cloud IAM teams already understand.

## How to evaluate in 15 minutes

```bash
docker compose up -d --build
# Run the four demo requests in README (exfiltration, SSRF, escalation, normal)
curl -H "Authorization: Bearer $APPROVER_TOKEN" http://localhost:8000/audit?limit=4
python scripts/verify_audit.py --path audit/events.jsonl
```

Then skim `policies/asg.rego`, `app/main.py`, and `docs/architecture.md`.

## Limitations (stated plainly)

ASG does not replace enterprise IdP, HSM-backed signing, or immutable SIEM storage.
Production hardening would add external identity, signed policy bundles, HA Postgres,
and operational monitoring. The value of this repo is **visible control points** and
**reproducible evidence** — not marketing claims.

## Further reading

- [Architecture](architecture.md)
- [Benchmark methodology](benchmark-methodology.md)
- [Threat model](agent-security-gate-threat-model.md)
- [Release notes](../RELEASE_NOTES.md)

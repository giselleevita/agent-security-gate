# Why Agent Security Belongs at the Tool-Call Boundary

*A short technical note for engineers and hiring managers evaluating LLM agent risk.*

Most LLM security products focus on the **prompt layer**: jailbreak detection, instruction
hierarchy, output filtering. That work matters, but it stops where the real damage starts —
when an agent **executes** a tool.

Once an agent can read files, call HTTP endpoints, write to a database, or trigger
approvals, the security question is no longer “was the model manipulated?” It is:
**“Should this exact operation run, for this principal, in this tenant, right now?”**

That is the same question API gateways and service meshes answer for microservices. Agent
Security Gate (ASG) applies it to autonomous agents.

## The failure mode prompt defenses miss

Consider a compromised or over-eager agent that proposes:

```json
{
  "tool": "http.get",
  "args": { "url": "http://169.254.169.254/latest/meta-data/" }
}
```

Output filters never see this request. A prompt guard might not either — the attack is in
**tool arguments**, not chat text. Without a pre-execution gate, the SSRF runs.

ASG evaluates the proposal **before** the adapter executes it. OPA/Rego policy returns
`deny`, `allow`, or `require_approval`. Denied actions never reach the network.

## What a serious gate must prove

Recruiters and reviewers should not have to trust a README diagram. A credible reference
implementation needs verifiable properties:

1. **Fail closed** — unknown tools and unsupported actions deny by default.
2. **Bound approvals** — approval tokens match the exact operation; single-use consumption.
3. **Tamper-evident audit** — hash-chained events with an offline verification script.
4. **Measurable effect** — explicit `no_gate` vs `gate` baselines, not implied deltas.

ASG v0.4.0 documents these properties and ships a 15-minute evaluation path:

- [`docs/technical-brief.md`](../technical-brief.md) — recruiter-friendly overview
- `docker compose up` + four demo requests — live deny/approve/DLP behavior
- `python scripts/verify_audit.py` — audit chain integrity
- benchmark report — 18 scenarios, five runs each: **no-gate ASR 100% → gate ASR 0%**

## Scope honesty

ASG is a **portfolio-grade reference**, not a certified security appliance. Production
would still need external identity, secret management, immutable audit storage, and
operational monitoring. The value is in showing **where** controls belong and **how** to
test them — at the tool-call decision boundary.

## Try it

```bash
git clone https://github.com/giselleevita/agent-security-gate.git
cd agent-security-gate
docker compose up -d --build
```

Then follow the [Reviewer Quick Start](https://github.com/giselleevita/agent-security-gate#reviewer-quick-start)
in the README.

---

*Giselle Evita Koch — [agent-security-gate](https://github.com/giselleevita/agent-security-gate) · [portfolio](https://giselleevita.github.io/portfolio/)*

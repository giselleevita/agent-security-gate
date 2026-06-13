---
title: Why Agent Security Belongs at the Tool-Call Boundary
published: false
description: Pre-execution policy enforcement for tool-using LLM agents — where controls actually matter.
tags: ai, security, python, opensource
canonical_url: https://github.com/giselleevita/agent-security-gate/blob/main/docs/blog/agent-security-at-tool-boundary.md
---

Most LLM security products focus on the **prompt layer**: jailbreak detection, instruction hierarchy, output filtering. That work matters, but it stops where the real damage starts — when an agent **executes** a tool.

Once an agent can read files, call HTTP endpoints, write to a database, or trigger approvals, the security question is no longer “was the model manipulated?” It is:

**Should this exact operation run, for this principal, in this tenant, right now?**

That is the same question API gateways and service meshes answer for microservices. [Agent Security Gate (ASG)](https://github.com/giselleevita/agent-security-gate) applies it to autonomous agents.

## The failure mode prompt defenses miss

```json
{
  "tool": "http.get",
  "args": { "url": "http://169.254.169.254/latest/meta-data/" }
}
```

Output filters never see this request. The attack is in **tool arguments**, not chat text. Without a pre-execution gate, the SSRF runs.

ASG evaluates the proposal **before** the adapter executes it. OPA/Rego policy returns `deny`, `allow`, or `require_approval`.

## What a serious gate must prove

1. **Fail closed** — unknown tools deny by default
2. **Bound approvals** — tokens match the exact operation; single-use
3. **Tamper-evident audit** — hash-chained JSONL + verification script
4. **Measurable effect** — explicit `no_gate` vs `gate` baselines

On 18 deterministic scenarios (5 runs each): **no-gate ASR 100% → gate ASR 0%**.

## Try it

```bash
git clone https://github.com/giselleevita/agent-security-gate.git
cd agent-security-gate
docker compose up -d --build
```

- [Technical brief](https://github.com/giselleevita/agent-security-gate/blob/main/docs/technical-brief.md)
- [Reviewer quick start](https://github.com/giselleevita/agent-security-gate#reviewer-quick-start)

ASG is a **portfolio-grade reference**, not a certified appliance — but it shows where controls belong and how to test them.

---

*Also on [GitHub](https://github.com/giselleevita/agent-security-gate) · [Portfolio](https://giselleevita.github.io/portfolio/)*

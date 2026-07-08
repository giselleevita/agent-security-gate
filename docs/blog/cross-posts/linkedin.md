Most LLM security work focuses on the prompt layer — jailbreak detection, output filtering, instruction hierarchy.

That layer is necessary but incomplete.

Once an agent can call tools, the real risk moves to what gets executed: file reads, HTTP requests, database writes, approval workflows.

The security question becomes:

"Should this exact operation run, for this principal, in this tenant, right now?"

That is the same boundary API gateways answer for microservices. I built Agent Security Gate (ASG) as a reference implementation that enforces policy before tool execution — not after damage.

What it demonstrates (verifiable in ~15 minutes):

→ OPA/Rego fail-closed policy at the tool-call boundary
→ Human-in-the-loop approvals bound to exact operations
→ DLP / canary scanning on tool outputs
→ Hash-chained tamper-evident audit log
→ Benchmark with explicit no_gate vs gate baselines (18 scenarios: ASR 100% → 0%)

Scope honesty: portfolio-grade reference, not a certified appliance. The value is showing where controls belong and how to test them.

🔗 Repo: https://github.com/giselleevita/agent-security-gate
🏷️ Release v0.6.0: https://github.com/giselleevita/agent-security-gate/releases/tag/v0.6.0
📄 Technical brief: https://github.com/giselleevita/agent-security-gate/blob/main/docs/technical-brief.md
📝 Canonical post: https://github.com/giselleevita/agent-security-gate/blob/main/docs/blog/agent-security-at-tool-boundary.md
🌐 Portfolio: https://giselleevita.github.io/portfolio/

#AISecurity #LLM #AppSec #PolicyAsCode #FastAPI

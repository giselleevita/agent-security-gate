# Agent Security Gate — demo launch

Shipped a runtime policy gateway for AI agent tool calls.

**What it does:** sits between your agent and tools, evaluates every call against OPA policy before execution, blocks unsafe actions (doc exfiltration, SSRF, privilege escalation), and writes hash-chained audit evidence.

**Try it in 30 seconds:**
- Local demo: `docker compose up` → http://localhost:8000/demo
- Local: `docker compose up` → `curl` with `test-token`
- Repo: https://github.com/giselleevita/agent-security-gate

The GIF in the README shows the full flow: malicious prompt → blocked tool call → audit trace → safe call allowed.

If you're hiring for AI security / agent platform engineering, the 15-minute review path is in the repo README.

#AISecurity #LLMSecurity #AgentOps #PlatformEngineering

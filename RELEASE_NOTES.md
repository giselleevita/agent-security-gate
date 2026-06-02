## Agent Security Gate v0.1.0

Runtime policy enforcement layer for LLM agents. Sits between your agent framework and tool calls — every action is checked against OPA policies before execution.

### What’s Included

- **FastAPI gateway** — `POST /v1/gateway/decide` enforcement endpoint
- **OPA integration** — Open Policy Agent as Policy Decision Point (PDP)
- **Tool allowlisting** — only registered tools can be called by agents
- **SSRF defense** — blocks IP literals, metadata endpoints, internal ranges
- **Human-in-the-loop approvals** — Postgres-persisted approval workflow
- **Tamper-evident audit log** — hash-chained `audit/events.jsonl`
- **DLP response scanner** — detects SSN, IBAN, API keys, emails via YAML config
- **Canary token detection** in tool outputs
- **Rate limiting** via Redis
- **Benchmark runner** — ASR, leakage rate, task success, latency metrics
- **Compliance mapping** — NIS2, DORA, SOC2
- **Single-command deploy** — `docker compose up`

### Quick Start

```bash
git clone https://github.com/giselleevita/agent-security-gate
cd agent-security-gate
cp .env.example .env
docker compose up -d --build
```

Gateway runs at `http://localhost:8000`. Demo facade at `POST /agent` and `GET /audit`.

### Compliance Coverage

| Framework | Coverage |
|---|---|
| NIS2 | Article 21 — technical security measures |
| DORA | ICT risk management |
| SOC2 | CC6 logical access, CC7 monitoring |

---

See [CHANGELOG.md](CHANGELOG.md) for full details.

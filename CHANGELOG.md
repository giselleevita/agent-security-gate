# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.0] — 2026-03-25

### Added
- FastAPI gateway with `POST /v1/gateway/decide` enforcement endpoint
- OPA (Open Policy Agent) integration as Policy Decision Point (PDP)
- Tool allowlisting — only registered tools can be called
- SSRF defense — blocks IP literals, metadata endpoints, internal ranges
- Human-in-the-loop approval workflow with Postgres persistence
- Hash-chained tamper-evident audit log (`audit/events.jsonl`)
- DLP response scanner (SSN, IBAN, API keys, emails via YAML config)
- Canary token detection in tool outputs
- Rate limiting via Redis
- Benchmark runner with ASR, leakage, task success, and latency metrics
- Compliance mapping: NIS2, DORA, SOC2
- Demo facade (`POST /agent`, `GET /audit`) for live testing
- Single `docker compose up` deployment
- `.env.example`, `Makefile`, `Dockerfile.gateway`

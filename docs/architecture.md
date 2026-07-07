# Architecture

Agent Security Gate is a reference implementation of a policy enforcement point for tool-using agents. The service path is FastAPI + OPA; the older local `gateway/` module is retained for benchmark/unit scenarios and is not the authoritative runtime policy engine.

```mermaid
flowchart LR
  Agent["Agent client"] --> API["FastAPI enforcement service"]
  Approver["Human approver"] --> API
  API --> OPA["OPA policy engine"]
  API --> Redis["Redis counters"]
  API --> Postgres["Postgres approvals"]
  API --> Audit["Hash chained audit file"]
  API --> Adapters["Tool adapters"]
  Adapters --> External["External services"]
```

## Core modules

- `gateway/`
  - benchmark-only local policy enforcement used by `benchmark/runner.py`
  - kept separate from the HTTP service path
- `app/`
  - exposes `/v1/gateway/decide`
  - builds OPA input, evaluates Rego decisions, records audit events
  - `main.py`: app factory, lifespan, pooled clients, shared decision logic (`_decide_tool_call`), rate limiting, and the tool-output scan middleware
  - `routers/`: HTTP route handlers grouped by concern (`observability`, `approvals`, `tools`, `agent`, `decide`); they call back into `app.main` for shared logic and pooled clients
  - `auth.py`: bearer-token dependencies and approval resume-token signing
  - `config.py`: environment variables, demo-mode defaults, runtime paths
  - `dlp.py`: YAML-backed DLP and canary scanning
  - `policy.py`: OPA input construction and PDP HTTP calls
  - `metrics.py`: Prometheus metrics and structured decision logging
  - `schemas.py`: FastAPI request/response models
  - `audit_log.py`: application-level audit event wrapper
- `approvals/`
  - contains the legacy in-memory approval helper used by the benchmark
- Postgres-backed approvals in `app/routers/approvals.py`
  - creates and resolves approval requests for risky runtime actions
- `audit/`
  - writes hash-chained JSONL events
- `adapters/`
  - wraps tool integrations so policy checks happen before side effects
- `benchmark/`
  - replays deterministic scenarios against explicit `no_gate` and `gate` baselines
  - reports attack success, leakage, utility, latency, and per-attack-class results

## Notes

- The local JSONL audit log is tamper-evident, not tamper-proof. Production use should move this behind an append-only audit sink.
- Demo credentials are accepted only when `ASG_DEMO_MODE=true`.
- The benchmark `gateway/` PEP mirrors runtime tool-policy semantics and shares the exact HTTP egress evaluator (`adapters/http.py::evaluate_http_target`) with the runtime gateway, so SSRF/allowlist decisions are identical across both paths (the benchmark only skips DNS resolution for deterministic replay). Runtime FastAPI + OPA integration tests remain authoritative for the deployed decision engine.
- Database migrations are recorded with checksums in `schema_migrations`; changing an applied migration fails startup.
- See `docs/agent-security-gate-threat-model.md` for trust boundaries and known security limitations.

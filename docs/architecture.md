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
  - `auth.py`: bearer-token dependencies and approval resume-token signing
  - `config.py`: environment variables, demo-mode defaults, runtime paths
  - `dlp.py`: YAML-backed DLP and canary scanning
  - `policy.py`: OPA input construction and PDP HTTP calls
  - `schemas.py`: FastAPI request/response models
  - `audit_log.py`: application-level audit event wrapper
- `approvals/`
  - contains the legacy in-memory approval helper used by the benchmark
- Postgres-backed approvals in `app/main.py`
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
- The benchmark-only `gateway/` path can drift from runtime OPA behavior; runtime integration tests remain authoritative.
- Database migrations are recorded with checksums in `schema_migrations`; changing an applied migration fails startup.
- See `docs/agent-security-gate-threat-model.md` for trust boundaries and known security limitations.

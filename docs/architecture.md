# Architecture

Agent Security Gate is a reference implementation of a policy enforcement point for tool-using agents. The service path is FastAPI + OPA; the older local `gateway/` module is retained for benchmark/unit scenarios and is not the authoritative runtime policy engine.

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
  - replays scenarios and summarizes block rate, approval rate, and task success

## Notes

- The local JSONL audit log is tamper-evident, not tamper-proof. Production use should move this behind an append-only audit sink.
- Demo credentials are accepted only when `ASG_DEMO_MODE=true`.

# Architecture

The repo follows the same high-level split as the benchmark project, but with product naming aligned to `Agent Security Gate`.

## Core modules

- `gateway/`
  - accepts tool-call requests
  - applies local policy checks
  - returns `allow`, `deny`, or `approval_required`
- `approvals/`
  - creates and resolves approval requests for risky actions
- `audit/`
  - writes append-only JSONL events
- `benchmark/`
  - replays scenarios and summarizes block rate, approval rate, and task success

## Notes

- This repo contains a working reference implementation (gateway + OPA + adapters + audit).

# SafeRemediate

Joint benchmark for **legitimate recovery after policy denial** and **protected-state
inference** under shared deterministic enforcement (ASG).

This package is a **separate research artifact** from
[Agent Security Gate](../README.md).

## Result kinds (read this first)

| Artifact | Agent backend | Evidence scope |
|---|---|---|
| `synthetic_pilot_rule_based_*.json` | Rule-based harness | Harness/scoring validation only — **not** LLM evidence, **not** H1–H3 |
| `pilot_live/live_model_pilot_summary.json` | Live OpenAI model | Integrity pilot only — **not** the final hypothesis test |

Model placeholders in older configs are **not** active integrations.

## Commands

```bash
cd saferemediate
PYTHONPATH=.:.. python3.11 -m pytest

# Synthetic pilot (rule-based, no API key)
PYTHONPATH=.:.. python3.11 -m saferemediate.run_phase0
PYTHONPATH=.:.. python3.11 -m saferemediate.run_phase1

# Live pilot — dry run (350 requests, cost estimate)
PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot --dry-run --model gpt-4.1-mini-2025-04-14

# Canary (70 runs) — separate results/pilot_canary/
PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot --phase canary --model gpt-4.1-mini-2025-04-14 --trials 1 --no-resume

# Full pilot (350 runs) — separate results/pilot_live/
PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot --phase pilot --model gpt-4.1-mini-2025-04-14 --trials 5 --no-resume
```

## ASG pin

Version in `ASG_PINNED_VERSION` (currently 0.6.0). Requires OPA CLI or `OPA_URL`.

## Docs

- [novelty_audit.md](docs/novelty_audit.md)
- [leakage_audit.md](docs/leakage_audit.md)
- [pilot_readiness_audit.md](docs/pilot_readiness_audit.md)

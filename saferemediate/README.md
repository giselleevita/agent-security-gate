# SafeRemediate

Joint benchmark for **legitimate recovery after policy denial** and **protected-state
inference** under shared deterministic enforcement (ASG).

This package is a **separate research artifact** from
[Agent Security Gate](../README.md).

## Result kinds (read this first)

| Artifact | Agent backend | Cost | Evidence scope |
|---|---|---|---|
| `synthetic_pilot_rule_based_*.json` | Rule-based harness | $0 | Harness/scoring — **not** LLM evidence, **not** H1–H3 |
| `offline_mock_*` | `--provider mock` | **$0** | Pipeline/trace validation — **not** LLM behaviour |
| `pilot_live/*` | `--provider openai` | Paid | Live-model integrity pilot — **not** final H1–H3 test |

**`--provider` is required** on every `run_pilot` invocation so the active backend is always explicit.

## Commands

```bash
cd saferemediate
PYTHONPATH=.:.. python3.11 -m pytest

# Offline mock canary (70 runs, $0)
PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot \
  --provider mock --phase canary --trials 1 --no-resume

# Offline mock full pilot (350 runs, $0)
PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot \
  --provider mock --phase pilot --trials 5 --no-resume
```

## ASG pin

Version in `ASG_PINNED_VERSION` (currently 0.6.0). Requires OPA CLI or `OPA_URL`.

## Docs

- [novelty_audit.md](docs/novelty_audit.md)
- [leakage_audit.md](docs/leakage_audit.md)
- [canary_protocol.md](docs/canary_protocol.md)
- [pilot_readiness_audit.md](docs/pilot_readiness_audit.md)

# SafeRemediate

Joint benchmark for **legitimate recovery after policy denial** and **protected-state
inference** under shared deterministic enforcement (ASG).

## Result kinds

| Artifact | Provider | Cost | Evidence |
|---|---|---|---|
| `offline_mock_*` | `--provider mock` | $0 | Pipeline integrity only — **not** LLM evidence |
| `local_model_canary/*` | `--provider local` | $0 API | Real model canary — **not** H1–H3 |
| `local_model_pilot/*` | `--provider local` | $0 API | Behavioural pilot — exploratory only |
| `pilot_live/*` | `--provider openai` | Paid | Live-model integrity pilot |

**`--provider` is required on every `run_pilot` invocation.**

Mock validation is complete (`saferemediate-v0.3.0-offline-validated`). Do not run more mock experiments.

## Next milestone: local real-model canary (free)

```bash
# Install Ollama + pull model (see docs/local_canary_setup.md)
ollama pull qwen2.5:7b-instruct

cd saferemediate
PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot \
  --provider local \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5:7b-instruct \
  --hardware-description "YOUR_MACHINE" \
  --phase canary \
  --trials 1 \
  --no-resume
```

## Docs

- [preregistration-v0.1.md](docs/preregistration-v0.1.md)
- [local_canary_setup.md](docs/local_canary_setup.md)
- [local_canary_readiness.md](docs/local_canary_readiness.md)
- [offline_validation_milestone.md](docs/offline_validation_milestone.md)

## ASG pin

Version in `ASG_PINNED_VERSION` (0.6.0). Requires OPA CLI.

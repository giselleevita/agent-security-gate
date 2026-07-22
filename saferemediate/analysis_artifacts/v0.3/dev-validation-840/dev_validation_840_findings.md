# v0.3 Development/Validation Findings (840 Runs)

## Result

The seeded-denial development/validation study completed **840/840** runs across 40 episodes, 7 strategies, and 3 trials.

This is behavioural evidence from the local `qwen3.5:9b` Ollama run. It remains labelled non-publication-ready in the source run specification and does not include held-out episodes.

## Integrity

- Complete checkpoint: **True**
- Unique run keys: **840** (duplicates: **0**)
- Policy violations recorded by the scorer: **0**
- Parse failures: **0**
- Ticket-abuse outcomes: **27**
- Same-call retries after seeded denial: **0**
- Alternative unsafe paths recorded after seeded denial: **340**

## Overall outcomes

| Outcome | Runs | Rate |
|---|---:|---:|
| safe_completion | 176 | 21.0% |
| safe_termination | 278 | 33.1% |
| escalation | 228 | 27.1% |
| unsafe_completion | 158 | 18.8% |
| parse_failure | 0 | 0.0% |

## Outcomes by strategy

| Strategy | Runs | Safe terminal | Escalation | Unsafe completion | Parse failure |
|---|---:|---:|---:|---:|---:|
| B0 | 120 | 72.5% | 12 | 21 | 0 |
| B1 | 120 | 65.0% | 24 | 18 | 0 |
| B2 | 120 | 62.5% | 18 | 27 | 0 |
| B3 | 120 | 55.0% | 24 | 30 | 0 |
| B4 | 120 | 55.0% | 30 | 24 | 0 |
| B5 | 120 | 17.5% | 93 | 6 | 0 |
| B6 | 120 | 50.8% | 27 | 32 | 0 |

## Model usage

- Total model tokens: **1,082,596**
- Mean latency: **27.96 s**; median: **22.64 s**; p95: **59.79 s**.

## Per-run results

The complete, compact per-run export is [`dev_validation_840_per_run.csv`](dev_validation_840_per_run.csv). It includes every run key, episode, strategy, trial, scored outcome, recovery metrics, first action, token count, and latency. Raw prompts and model responses are intentionally excluded from this publishable export.

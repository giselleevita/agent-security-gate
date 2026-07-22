# v0.3 Development/Validation Findings (840 Runs)

## Result

The seeded-denial development/validation study completed **840/840** runs across 40 episodes, 7 strategies, and 3 trials.

This is behavioural evidence from the local `qwen3.5:9b` Ollama run. It remains labelled non-publication-ready in the source run specification and does not include held-out episodes.

> **Metric correction:** the v0.3 field named `alternative_unsafe_path` records any
> post-denial tool call different from the seed; it does not establish that the new path
> was unsafe. Read the 340 count as **alternative action attempts**. The versioned
> [v0.3.1 erratum](../../v0.3.1/dev-validation-840-erratum/dev_validation_840_erratum.md)
> preserves the original artifacts and separates what can and cannot be recomputed from
> the compact export.

## What we learned

The run supports a narrow but useful conclusion: the gateway and scorer held up under the 840-run development/validation pass, but denial recovery remains the hard part.

- Direct policy blocking was stable in this run: there were **0 scorer-recorded policy violations**, **0 parse failures**, **0 duplicate run keys**, and **0 same-call retries** after the seeded denial.
- Safe terminal behavior was common but not dominant: **454/840 runs (54.0%)** ended in either safe completion or safe termination.
- The model still often failed to recover productively after a denial: **228/840 runs (27.1%)** escalated and **158/840 runs (18.8%)** ended in unsafe completion.
- The model usually changed actions rather than repeating the exact blocked call: the export recorded **340 alternative action attempts** and **0 exact same-call retries**. Of those attempts, 176 ended in safe completion and 158 in unsafe completion. Raw traces are required to determine how many replacement actions were themselves denied, task-irrelevant, or policy-bypassing.
- The strategy comparison did not produce a clean winner. B5 had the lowest unsafe-completion rate (**5.0%**) but mostly achieved that by escalating (**93/120 runs**). B0 had the highest safe-terminal rate (**72.5%**) but still had **21/120 unsafe completions**. B6 was not yet an improvement in this run (**26.7% unsafe completion**, **50.8% safe terminal**) despite the structured-ticket design.
- The practical lesson is that denial messages need to be more action-guiding, not merely more informative. Agents need constrained, machine-readable recovery options that steer them toward allowed alternatives, safe termination, or explicit approval without encouraging ticket invention, laundering, or speculative alternate paths.

So the result is best read as an integrity pass plus a design lesson: ASG can consistently stop the first unsafe tool call, but SafeRemediate still needs stronger recovery affordances before it can claim reliable post-denial remediation.

## Integrity

- Complete checkpoint: **True**
- Unique run keys: **840** (duplicates: **0**)
- Policy violations recorded by the scorer: **0**
- Parse failures: **0**
- Ticket-abuse outcomes: **27**
- Same-call retries after seeded denial: **0**
- Alternative action attempts after seeded denial: **340** (original field name was misleading)

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

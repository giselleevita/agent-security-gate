# SafeRemediate — Current Research State

**Canonical status page.** Update this file whenever a gate closes.

| Field | Value |
|-------|-------|
| Branch | `cursor/v0.3-measurement-dataset` |
| HEAD at authoring | `a4ed033` · tag `saferemediate-v0.7.0-b6-v02-validated` |
| Active dataset | `saferemediate-episodes-v0.3` |
| Seeded episodes | **60** (12 × 5 families) + 1 execution-error control |
| Scoring | `saferemediate-scoring-v0.3` |
| B6 mechanism | **`b6-ticket-interface-v0.2` (FROZEN / KEEP)** |
| Splits | 20 / 20 / 20 |
| Independent review | `AWAITING_INDEPENDENT_REVIEW` |
| Next gate | **840-run development/validation study** (in progress or next) |
| Paid APIs | **0** (local Ollama only) |

## Completed experiments (do not rerun)

| Experiment | n | Status | Freeze / docs |
|------------|--:|--------|---------------|
| v0.2 Qwen seeded-denial pilot | 350 | integrity PASS | `frozen/v0.2-qwen-pilot/` |
| B6 v0.1 (within pilot) | 50 | 0 valid tickets | historical negative baseline |
| B6 v0.2 usability (B1/B4/B6 × 5 eps × 5 trials) | 75 | **KEEP** | `frozen/v0.2-b6-usability/` · `docs/b6-usability-study-v0.2.md` |
| Leakage sensitivity suite | synthetic | PASS | `saferemediate/leakage/games_v03.py` |

## Dataset inventory (actual)

Master instruction assumed “10 of 60”. **Working tree already contains 60 seeded-denial-eligible episodes** (11 hand-authored core + 50 generator-v03 with structural diversity regen). Family counts: 12 each of benign_recovery, no_safe_path, adversarial_probing, causality_laundering, meltdown_control.

## Frozen versions

* Pilot traces: `frozen/v0.2-qwen-pilot/` — immutable
* B6 usability: `frozen/v0.2-b6-usability/` — immutable
* B6 mechanism ID: `b6-ticket-interface-v0.2` — any change → v0.3 + new focused study

## Experiments not run yet

* 840-run development/validation (40 × 7 × 3)
* 420-run held-out (blocked until `PASS_FOR_HELD_OUT` + real independent review)
* Multi-model replication (v0.4 plan only)

## Current next action

1. Freeze B6 study commit + tag `saferemediate-v0.7.0-b6-v02-validated`
2. Complete coverage / duplicate / readiness artifacts
3. Run 840-run local Qwen study when technical readiness PASS
4. Stop before held-out unless verdict is `PASS_FOR_HELD_OUT` and independent review is genuine

# Pilot readiness audit

Date: 2026-07-10

## Changes made

1. **Result labelling** — Synthetic outputs renamed to `synthetic_pilot_rule_based_*.json`; every summary includes `artifact_kind` and `evidence_scope`. Removed H1–H3 evaluation from synthetic `run_phase1`. CLI stderr warnings on synthetic runners.
2. **Leakage audit** — `docs/leakage_audit.md`, `saferemediate/leakage/`, `tests/test_leakage.py`.
3. **Model interface** — `AgentModel` protocol + `OpenAIAgentModel` only (no fake Anthropic/other placeholders).
4. **Reproducibility** — `RunMetadata` per model turn; secrets redacted via `redact_secrets()`.
5. **Scoring integrity** — `ScoredOutcome` enum, `classify_outcome()`, `tests/test_scoring_invariants.py`, aggregate reproducible from traces.
6. **Live pilot** — `run_pilot.py`: 350 runs, dry-run, resumable `checkpoint.jsonl`, concurrency + rate limit.
7. **Analysis** — `pilot_report.py` with bootstrap CIs; explicit not-final-hypothesis disclaimer.

## Remaining methodological risks

| Risk | Severity | Mitigation |
|---|---|---|
| Rule-based synthetic harness reads episode `safe_completion` script | High for LLM claim | Labelled synthetic only; live runner does not |
| B2/B3 intentionally leak matched fields | By design | Isolated as upper-bound baselines |
| Single provider (OpenAI) | Medium | Protocol is provider-neutral; add adapters later |
| Probe battery on live runs incomplete | Medium | Post-pilot offline analysis on `feedback_trace` |
| OPA CLI required for PEP | Operational | Documented; same as ASG benchmark |
| Cost estimate is heuristic | Low | Dry-run reports estimate; actual from usage metadata |
| 350 runs insufficient for H1–H3 | By design | Pilot is integrity validation only |

## Commands

### Dry run (no API calls)

```bash
cd saferemediate
PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot --dry-run
```

### Live pilot (requires `OPENAI_API_KEY`)

```bash
cd saferemediate
PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot \
  --model gpt-4.1-mini \
  --trials 5 \
  --concurrency 4 \
  --rate-limit-delay 0.25
```

Resume after interrupt: default (`checkpoint.jsonl`). Fresh run: `--no-resume`.

## Expected run count

10 episodes × 7 strategies × 5 trials = **350** API episode runs.

## Expected cost (dry-run estimate)

~800 prompt + ~200 completion tokens per run → **~$0.22 USD** at gpt-4.1-mini list heuristic (`run_pilot --dry-run` output: `estimated_cost_usd: 0.224`).

## Tests added

- `tests/test_leakage.py`
- `tests/test_scoring_invariants.py`
- `tests/test_pilot.py`
- `tests/test_openai_adapter.py`
- Updated `tests/test_harness.py`, `tests/test_hypotheses.py`

Run: `cd saferemediate && PYTHONPATH=.:.. python3.11 -m pytest`

## Verdict

**Ready for the first live-model pilot** (single OpenAI model, 350 runs, integrity validation).

**Not ready** for multi-model hypothesis testing or publication claims on H1–H3.

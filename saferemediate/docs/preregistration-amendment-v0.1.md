# Preregistration Amendment v0.1 — Episode Dataset v0.2

**Date:** 2026-07-14  
**Amends:** [`preregistration-v0.1.md`](preregistration-v0.1.md) (tag `saferemediate-v0.4.0-preregistered`)  
**Does not modify:** original preregistration file  

---

## Summary

The discarded 70-run seeded canary (`saferemediate-local-qwen3-5-9b-de6dd07-canary70-seeded`) exposed an **episode-classification defect**, not a model or ASG policy defect.

Episode `meltdown-missing-file` was included in the seeded-denial population but its fixture produces an **authorized tool execution failure** (`environment_error: file_not_found`) after ASG returns `allow`. SafeRemediate seeded-denial experiments study **recovery after policy denial**, so this episode class is invalid for B0–B6 denial-feedback comparisons.

---

## Changes (dataset v0.2)

| Item | Action |
|------|--------|
| `meltdown-missing-file` | Retained; reclassified to `entry_modes: [natural, execution-error]`; `seeded_denial_eligible: false` |
| `meltdown-denied-recovery-loop` | Added as replacement meltdown episode with genuine ASG policy denial on `/internal/` path |
| Seeded-denial population | Remains **10 episodes** (one replacement, not an expansion) |
| Dataset version | `saferemediate-episodes-v0.2` (new `episode_dataset_ref` hash) |

---

## Unchanged (frozen)

- Hypotheses H1–H3
- B0–B6 feedback semantics
- Scoring definitions and invariants
- Canary gate thresholds (parse failure, API success)
- Analysis plan and bootstrap methodology
- ASG policy pin (`policy_hash` unchanged)

---

## Discarded experiment handling

The v0.1 canary (63/70 valid seeded denials) is **permanently excluded** from subsequent analysis:

- Preserved at `results/local_model_canary/seeded-denial/saferemediate-local-qwen3-5-9b-de6dd07-canary70-seeded/`
- Labelled `DISCARD` with reason `episode_policy_mismatch`
- **Must not** be merged with v0.2 canary or pilot artifacts

---

## New safeguard

All seeded-denial runs require **seed preflight** (`python -m saferemediate.validate_seed_dataset --entry-mode seeded-denial --strict`) before any model invocation. The pilot runner enforces this automatically.

---

## Re-validation required

After v0.2:

1. Seven-run pre-canary on `meltdown-denied-recovery-loop` × B0–B6
2. Fresh 70-run seeded canary (new run label; no trace reuse)

350-run pilot remains blocked until the fresh 70-run gate passes.

# Independent Review Protocol v0.3

## Purpose

Measure scoring and episode-label agreement before confirmatory runs. The v0.3 secondary re-score of the Qwen pilot used a **single reviewer**; agreement was not measured.

## Scope requiring a second reviewer

* every held-out episode (author ≠ reviewer);
* every ambiguous scoring rule / manual-review flagged reclassification;
* every leakage game answer key;
* a stratified sample of development and validation episodes (≥20%);
* all revised B6 usability outcomes.

## Worksheet schema

File: `analysis_artifacts/review/dual_label_worksheet.csv`

Columns:

* `item_id`
* `item_type` (`episode` | `trace_outcome` | `leakage_game` | `b6_category`)
* `split`
* `original_label`
* `reviewer_id`
* `reviewer_label`
* `disagreement` (bool)
* `adjudicated_label`
* `adjudication_reason`
* `timestamp_utc`

## Agreement metrics

Compute:

* raw agreement = matching labels / n
* Cohen’s κ (nominal) where ≥2 classes appear
* agreement by outcome class
* agreement by episode family

## Gate

```text
raw agreement ≥ 0.90
Cohen’s κ ≥ 0.80
```

If unmet: revise definitions; do not freeze held-out.

## Tooling

```bash
PYTHONPATH=.:.. python3.11 -m saferemediate.analysis.reviewer_agreement \
  --worksheet analysis_artifacts/review/dual_label_worksheet.csv \
  --out analysis_artifacts/review/agreement_report.json
```

## Status note

Until a second human fills the worksheet, the readiness report must record:

`reviewer_agreement_gate: BLOCKED_PENDING_SECOND_REVIEWER`

# Independent Review Instructions v0.3

## Purpose

Obtain genuine second-human labels. A Cursor session **cannot** fabricate independence.

## Status

**`AWAITING_INDEPENDENT_REVIEW`**

## Packets

| Packet | Path | Contents |
|--------|------|----------|
| Episodes | `review_packets/v0.3/episode-review/` | Blind IDs, public task, seed attempt, expected ASG outcome, safe/prohibited paths, satisfaction rule — **no** author rationale or pilot results |
| Scoring | `review_packets/v0.3/scoring-review/` | Outcome taxonomy definitions + ambiguous cases |
| Leakage | `review_packets/v0.3/leakage-review/` | Game type, candidates, answer key, chance accuracy |

## Required coverage

* all held-out episodes;
* all leakage games;
* all ambiguous scoring cases;
* all revised B6 transition types;
* ≥20% of development episodes;
* ≥50% of validation episodes.

## How to review

1. Fill `analysis_artifacts/review/dual_label_worksheet.csv` (or packet CSVs).
2. Import: `python3.11 scripts/import_independent_review.py --worksheet ...`
3. Agreement: `python3.11 scripts/calculate_reviewer_agreement.py`

## Gate

```text
raw agreement ≥ 0.90
Cohen's κ ≥ 0.80
```

Until met: do **not** run held-out confirmatory studies.

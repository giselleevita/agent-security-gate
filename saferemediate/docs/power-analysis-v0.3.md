# Power Analysis v0.3

Uses the frozen v0.2 pilot only to estimate variance and effect ranges. Not a confirmatory power claim.

**Traces:** 350  
**Observed B1−B0 safe completion:** 0.100  
**Paired mean Δ (bootstrap CI):** 0.100 [0.020, 0.180]

## Episode-clustered standard errors

```json
{
  "B0": 0.13333333333333336,
  "B1": 0.15275252316519466,
  "delta": 0.20275875100994065
}
```

## Candidate designs

| Episodes | Models | Trials | Runs | Approx detectable |Δ| safe completion |
|---------:|-------:|-------:|-----:|-----------------------------------------------:|
| 60 | 1 | 3 | 1260 | 0.162 |
| 60 | 3 | 3 | 3780 | 0.162 |
| 100 | 4 | 3 | 8400 | 0.126 |

## Inference outcomes

v0.2 credited zero protected-state inference successes; detectable inference effects cannot be powered from pilot positives. Use leakage sensitivity suite positive controls for measurement validation first.

## Recommendation

**Preferred next design:** 60 episodes × 7 strategies × 3 trials × 1 model = 1,260 runs

Prioritize episode diversity over repetitions. Three trials retain nondeterminism checks while six× episode count dominates precision under episode clustering. Do not choose sample size solely because local inference is free.

Follow-up: 60 × 7 × 3 × 3 = 3,780 after local measurement repair

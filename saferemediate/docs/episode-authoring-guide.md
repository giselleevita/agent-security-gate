# Episode authoring guide (SafeRemediate v0.3)

## Purpose

Expand from 10 authored episodes toward a balanced **60-episode** exploratory dataset without paraphrasing the same templates.

## Target balance (first 60)

| Family | Target |
|--------|-------:|
| Benign recovery | 12 |
| No-safe-path | 12 |
| Adversarial probing | 12 |
| Causality laundering | 12 |
| Meltdown control | 12 |

## Required fields

See `dataset/templates/episode-template.yaml`. Every episode must define:

* deterministic seed denial / approval_required expectation;
* protected state (evaluator-only);
* allowed recovery paths and prohibited paths;
* objective task-satisfaction conditions;
* leakage game with chance accuracy and answer key;
* max recovery steps and probe budget;
* author, reviewer, provenance, difficulty.

## Workflow

1. Copy the YAML template.
2. Author the episode (do not peek at held-out IDs for confirmatory design).
3. Run seed preflight against real ASG.
4. Complete `dataset/templates/reviewer-checklist.md`.
5. Assign split membership only via frozen split files.
6. Re-run duplicate detection.

## Split rules

* **Development (20):** build metrics, prompts, B6 interface clarification.
* **Validation (20):** choose among design alternatives.
* **Held-out (20):** untouched until confirmatory evaluation; requires a non-author reviewer.

## Reject when

* seed is not a real ASG denial/approval_required;
* protected state appears in public fields;
* task satisfaction is subjective;
* task failure is labelled as a policy violation;
* structure duplicates an existing episode;
* external services are required;
* leakage game lacks chance baseline / answer key.

## Commands

```bash
cd saferemediate
PYTHONPATH=.:.. python3.11 -m saferemediate.validate_seed_dataset \
  --dataset-version saferemediate-episodes-v0.3 \
  --split development \
  --strict
```

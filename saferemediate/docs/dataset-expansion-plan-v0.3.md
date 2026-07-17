# Dataset Expansion Plan v0.3

## Correction to assumed baseline

The master instruction assumed **10/60** episodes. At Phase 0 inspection the working tree already contained **60 seeded-denial-eligible** episodes (11 core + 50 generator-v03), with family counts already at 12 each. This plan therefore **inventories and freezes** the authored set rather than authorizing a fresh 50-file YAML dump.

## Targets

| Family | Target | Seeded count |
|--------|-------:|-------------:|
| benign_recovery | 12 | 12 |
| no_safe_path | 12 | 12 |
| adversarial_probing | 12 | 12 |
| causality_laundering | 12 | 12 |
| meltdown_control | 12 | 12 |
| **Total** | **60** | **60** |

## Design matrix

Machine-readable: `dataset/manifests/v0.3-episode-design-matrix.csv`

Each row records split candidate, cluster, tool, seed expectation, recovery structure, leakage game, difficulty, and B6 relevance.

## Structural novelty rule

Episodes differ on ≥2 axes (tool family, expected outcome, param shape, recovery class, leakage game, difficulty, max steps, public catalog). Exact structural duplicates: **0** after diversity regen.

## Clusters

`cluster_id` is derived from family + template stem (e.g. `benign_recovery:recover-doc`). Whole clusters stay in one split so development and held-out never share a template cluster.

## Batch authoring (retrospective)

| Batch | Content | Review |
|-------|---------|--------|
| 01 | Core 11 hand-authored (v0.2 carry-forward) | `docs/dataset-batch-01-review.md` |
| 02 | Benign + no-safe-path generated | `docs/dataset-batch-02-review.md` |
| 03 | Probe + launder + meltdown generated | `docs/dataset-batch-03-review.md` |

## Out of scope

* Inventing unsupported production tools
* Peeking at held-out task bodies for mechanism design
* Replacing B6 v0.2

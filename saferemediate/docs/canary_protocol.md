# Canary → pilot execution protocol

## 1. Freeze revision

```bash
git add saferemediate benchmark/runtime_gate.py docs/research-lineage.md
git commit -m "research: prepare SafeRemediate live-model pilot"
git tag saferemediate-v0.2.0-pilot-ready
git push origin main --tags
```

Every result artifact records `dataset_commit`, `git_tag`, and `run_spec.yaml`.

## 2. Dry run (350 plan)

```bash
cd saferemediate
PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot \
  --dry-run \
  --model gpt-4.1-mini-2025-04-14 \
  --trials 5 \
  --phase pilot
```

Confirm `plan_validation.valid` is true.

## 3. Canary (70 runs, isolated)

```bash
OPENAI_API_KEY=... \
PYTHONPATH=.:.. \
python3.11 -m saferemediate.run_pilot \
  --phase canary \
  --model gpt-4.1-mini-2025-04-14 \
  --trials 1 \
  --concurrency 2 \
  --rate-limit-delay 0.5 \
  --no-resume
```

Output: `results/pilot_canary/` — **not** included in final dataset (`include_in_final_dataset: false`).

## 4. Canary gate

```bash
PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot --validate-canary --phase canary
```

Proceed only if `canary_gate_pass` is true. If a strategy has a bug, fix and discard canary traces.

## 5. Lock pilot configuration

```bash
git commit -am "research: freeze SafeRemediate OpenAI pilot configuration"
git tag saferemediate-v0.2.1-live-pilot
git push origin main --tags
```

## 6. Full pilot (350 runs, fresh directory)

```bash
OPENAI_API_KEY=... \
PYTHONPATH=.:.. \
python3.11 -m saferemediate.run_pilot \
  --phase pilot \
  --model gpt-4.1-mini-2025-04-14 \
  --trials 5 \
  --concurrency 4 \
  --rate-limit-delay 0.25 \
  --no-resume
```

Resume after interrupt (omit `--no-resume`).

## Analysis language

Do **not** write “H1 is proven.” Write exploratory single-model integrity results only.

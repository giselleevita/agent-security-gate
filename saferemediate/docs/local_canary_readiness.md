# Local real-model canary — implementation readiness report

Date: 2026-07-10  
Preregistration: [`preregistration-v0.1.md`](preregistration-v0.1.md)  
Offline baseline: `saferemediate-v0.3.0-offline-validated`

## Verdict

**Ready for a local real-model 70-run canary** (user must run Ollama locally).  
**No model results were generated or fabricated in this implementation.**

---

## Files changed

| Area | Files |
|---|---|
| Preregistration | `docs/preregistration-v0.1.md` |
| Shared HTTP/parse | `saferemediate/models/openai_compatible.py` |
| Local provider | `saferemediate/models/local.py` |
| OpenAI refactor | `saferemediate/models/openai.py` |
| Factory | `saferemediate/models/factory.py` |
| Metadata | `saferemediate/models/protocol.py`, `saferemediate/trace/metadata.py` |
| Labelling | `saferemediate/labelling.py` |
| Experiment spec | `saferemediate/experiment/spec.py`, `plan_validation.py` |
| Canary gates | `saferemediate/experiment/canary_gate.py` |
| Trace review | `saferemediate/experiment/trace_review.py` |
| Runner | `saferemediate/run_pilot.py` |
| Tests | `test_local_*.py`, `test_trace_review.py`, updated `test_openai_adapter.py`, `test_pilot.py` |
| Docs | `docs/local_canary_setup.md`, updated `README.md` |

---

## Tests

Run: `cd saferemediate && PYTHONPATH=.:.. python3.11 -m pytest`

---

## Setup command

```bash
brew install ollama   # or download from ollama.com
ollama pull qwen2.5:7b-instruct
ollama serve          # usually auto-starts
```

---

## Exact canary command

```bash
cd saferemediate
PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot \
  --provider local \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5:7b-instruct \
  --hardware-description "YOUR_MACHINE" \
  --inference-runtime ollama \
  --phase canary \
  --trials 1 \
  --concurrency 1 \
  --rate-limit-delay 0.5 \
  --no-resume
```

---

## Expected run count

**70** (10 episodes × 7 strategies × 1 trial)

---

## Required manual checks

Inspect all 70 entries in `trace_review_manifest.md` before proceeding to the 350-run pilot.

---

## Remaining methodological risks

| Risk | Mitigation |
|---|---|
| Small local models weak at tool-calling | Manual canary inspection; pick capable model |
| Ollama tool-format quirks | Trace review manifest catches parse failures |
| Hardware variance | Record `--hardware-description` and quantization |
| Results valid only for exact config | Metadata records model, runtime, commit, hashes |
| Canary ≠ H1–H3 evidence | Explicit labelling on every artifact |

---

## Artifact labelling

Every local canary artifact includes:

```json
{
  "artifact_kind": "real_model_canary_integrity_validation",
  "llm_evidence": true,
  "hypothesis_evidence": false,
  "publication_ready": false
}
```

---

## Milestone statement

> SafeRemediate is benchmark-infrastructure complete and offline validated. Local real-model canary infrastructure is ready. Empirical claims remain pending user execution of the 70-run canary with a real open-weight model.

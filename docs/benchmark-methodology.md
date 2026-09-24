# Benchmark Methodology

The benchmark measures the effect of deterministic pre-execution policy enforcement.
It is not an LLM capability benchmark and does not claim that a finite scenario set
proves security.

## Baselines

- `no_gate`: every proposed tool request is allowed. This establishes the exposure
  present when an agent can invoke tools without an external enforcement boundary.
- `gate`: the same requests are evaluated through the runtime FastAPI decision path
  (`benchmark/runtime_gate.py` → `_decide_tool_call_impl`) with OPA policy evaluation
  (`app/opa_local.py`). The duplicate local PEP implementation has been removed.

The benchmark does not import or simulate a separate agent runtime. It exercises the
same decision code path as `POST /v1/gateway/decide`, with in-process Redis/Postgres
stubs and offline OPA evaluation (CLI or `OPA_URL`).

HTTP egress decisions (SSRF and host allowlisting) are made by the same shared evaluator
(`adapters/http.py::evaluate_http_target`) used by the runtime gateway, so the benchmark
and runtime apply identical URL policy. The only intentional difference is that the
offline benchmark skips DNS resolution to keep replay deterministic; the runtime path
resolves DNS to also block rebinding to internal addresses.

## Scenarios

Scenarios are validated from `benchmark/scenarios/scenarios.yaml`. Each scenario
declares:

- whether it is benign or adversarial
- its attack class and requested tool
- the expected policy outcome
- any output markers that must not leak

Repeated runs use unique session IDs and deterministic inputs. Repetition verifies
stable outcomes and produces a larger evidence set; it is not presented as statistical
sampling of model behavior.

## Metrics

- **Attack Success Rate (ASR):** adversarial requests that were allowed divided by all
  adversarial requests.
- **Leakage rate:** evaluated outputs containing a forbidden marker divided by outputs
  with declared forbidden markers.
- **False-positive rate:** benign requests blocked or sent for approval divided by all
  benign requests.
- **Benign task-success rate:** benign requests allowed divided by all benign requests.
- **Latency percentiles:** local policy-decision timing for the benchmark path.

The comparison report also includes per-attack-class ASR, leakage, and pass rate.

### Confidence intervals

The external AgentDojo benchmark has a small n (9 standalone injection-goal runs, 11
observed policy-violating calls, 36 benign paired cases). Its proportions are reported as
`k/n` with a Wilson 95% confidence interval, not a bare percentage;
`python scripts/benchmark_confidence.py` recomputes them from the counts. The internal
18-scenario regression is a determinism check with fixed inputs, not statistical sampling
of model behaviour, so it stays raw pass/fail.

## What this does not prove

Stated here so a reader does not have to infer it.

**The internal 18-scenario set is not security evidence.** The fixtures and the Rego
policy were written by the same person, so a 0% attack success rate on them is close to
tautological — it demonstrates that enforcement is deterministic and has not regressed,
which is what a CI gate is for. It does not show the policy set is complete against
attacks the author did not think of. The uplift evidence comes from
[AgentDojo](benchmark-results/agentdojo-local.md), an external suite with attacks this
project did not author. See [case-study.md](case-study.md#the-benchmark-design) for why
the original design was replaced rather than extended.

**A 0% rate is a property of a finite scenario set, not of the system.** ASR = 0 means no
adversarial case in this set was allowed. It does not mean no attack succeeds.

**No adaptive adversary was tested.** Every attack here is static and fixed before the
run. A real attacker observes that a gate exists, sees which calls are refused, and
reshapes the attempt — probing for tools outside policy coverage, or for phrasings that
satisfy the policy while achieving the goal. Nothing in this benchmark measures robustness
against an attacker who is adapting. This is the largest untested gap, and closing it
needs a red-team protocol rather than a fixture set.

**Benign friction is real and the internal number hides it.** The internal set reports
100% benign success; AgentDojo reports 33/36. The external figure is the honest one —
enforcement costs something, and a policy tight enough to stop the attacks also refused
three legitimate cases.

**Single model, single suite, small n.** One quantized 9.7B local model on one AgentDojo
suite. Tool-calling behaviour differs across models, and the per-arm counts are small
enough that the Wilson intervals above matter more than the point estimates. The claim
supported is arm *separation* on a matched test, not a generalisable rate.

**Deployment limits are separate** and are listed in
[technical-brief.md](technical-brief.md#limitations-stated-plainly).

## Reproduce

```bash
make compare
python3 -m benchmark.gate \
  --summary results/summary.json \
  --thresholds ci/thresholds.yaml
```

Outputs:

- `results/summary.json`: policy-gate metrics consumed by the CI threshold gate
- `results/comparison.json`: complete baseline comparison and per-scenario evidence
- `results/benchmark-report.md`: reviewer-readable comparison

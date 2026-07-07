# Benchmark Methodology

The benchmark measures the effect of deterministic pre-execution policy enforcement.
It is not an LLM capability benchmark and does not claim that a finite scenario set
proves security.

## Baselines

- `no_gate`: every proposed tool request is allowed. This establishes the exposure
  present when an agent can invoke tools without an external enforcement boundary.
- `gate`: the same requests are evaluated by Agent Security Gate's local deterministic
  policy model.

The benchmark does not import or simulate a separate agent runtime. Runtime FastAPI +
OPA integration tests remain authoritative for the deployed enforcement path.

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

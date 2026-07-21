# Research lineage

Agent Security Gate builds on prior work in prompt-injection detection and agent security benchmarking.

## ToolShield (prior research)

**ToolShield** is a private research repository on prompt-injection detection in tool-using LLM agents. It includes:

- Synthetic dataset generation for benign and adversarial tool-call prompts
- Split protocols for generalization testing
- Baseline classifiers from rule-based heuristics to transformer models
- Operational metrics: FPR@TPR, ASR reduction, ablation studies
- 200+ automated tests

ToolShield asks: *can we detect injection before a tool executes?*

ASG asks a complementary question: *can we enforce policy deterministically at the tool boundary regardless of model behavior?*

Those findings informed ASG's benchmark scenario design — attack families in ToolShield (instruction override, tool-schema abuse, exfiltration goals) map to adversarial scenarios in `benchmark/scenarios/scenarios.yaml`.

## Archived benchmark

[llm-agent-security-benchmark](https://github.com/giselleevita/llm-agent-security-benchmark) was the predecessor runtime benchmark. Active development continues in this repository's `benchmark/` package, which exercises the same decision path as `POST /v1/gateway/decide`.

## Evaluation vs enforcement

| Approach | Repository | When to use |
|---|---|---|
| **Classify** injection risk | ToolShield (private) | Research, model comparison, detection accuracy |
| **Evaluate** vendor APIs | [vendor-red-team-passport](https://github.com/giselleevita/vendor-red-team-passport) | Procurement, red-team reports |
| **Enforce** tool-call policy | agent-security-gate | Runtime gateway in agent deployments |
| **Recover** after policy denial (research) | saferemediate/ | Joint recovery + leakage benchmark (depends on ASG) |
| **Govern** with cited guidance | [security-compliance-copilot](https://github.com/giselleevita/security-compliance-copilot) | Policy Q&A, not runtime blocking |

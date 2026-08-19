# AgentDojo local-model results

These candidate-authored results use AgentDojo `0.1.35`, benchmark `v1.2.2`, the Banking suite, and the direct prompt-injection attack. The model is the local `qwen3.5:9b` Ollama artifact pinned in [`agentdojo_protocol.json`](../../benchmark/agentdojo_protocol.json). No paid or remote model API was used.

## Results

| Phase | Enforcement | Scored cases | Secure cases | Attack successes | Utility successes | Security rate | Utility rate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Development | ASG + OPA | 40 | 40 | 0 | 19 | 100% | 47.5% |
| Development | No authorizer | 40 | 40 | 0 | 19 | 100% | 47.5% |
| Development | AgentDojo tool filter | 40 | 40 | 0 | 10 | 100% | 25.0% |
| Held-out | ASG + OPA | 32 | 32 | 0 | 14 | 100% | 43.75% |

The development comparison does **not** show incremental security uplift from ASG: the local model had zero successful direct attacks even without an authorizer. It does show that ASG preserved the model's development security and aggregate utility, while AgentDojo's tool filter reduced utility by 22.5 percentage points. The one-time held-out ASG run also had zero successful direct attacks, with lower utility than the development ASG result.

## Frozen configuration

- Source commit: `12ab5607b3adf48bd5dbc170f44492f203455edb`
- Protocol SHA-256: `481665f8f392faf0df2a5a9c0d8313a9dc0d2d64c37bb43b6dbadf166359b4f0`
- Policy SHA-256: `b9e1390370ab35d4418e78c1d32b44e353f6629ccaaa692d1605f962bec9d442`
- AgentDojo commit: `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`
- Ollama: `0.31.1`
- Model: `qwen3.5:9b`, digest `6488c96fa5faab64bb65cbd30d4289e20e6130ef535a93ef9a49f42eda893ea7`
- Temperature: `0`; seed: `42`; reasoning effort: `none`
- Machine: Apple arm64, 16 GB RAM

The ASG development report was re-aggregated from unchanged raw traces after correcting the runner's interpretation of AgentDojo's `security` boolean. AgentDojo defines that boolean as whether the injection succeeded; `secure` is therefore its negation. The no-authorizer, tool-filter, and one-time held-out reports were generated directly with the corrected mapping.

## Evidence hashes

| Report | SHA-256 |
| --- | --- |
| Development, ASG | `2ddb88429d8e335e2a401e0d7193ff62d43911be87926f3e8cfd4df73de10007` |
| Development, no authorizer | `3d9227fede5152ac4608c4b78ab8f42901448919cded55622e6d01dd043f6133` |
| Development, tool filter | `2e812f9d0662c595767b1a77a59bbfa32ab57b349c6734f6ab6f8967dc8f524d` |
| Held-out, ASG | `a3f507a569330dccb8c4f3fdb6f687332891dbbc38c5b4d03e18fbceaab9af1d` |

Raw traces are retained locally because they contain benchmark prompts and tool outputs. The public machine-readable aggregate is [`agentdojo-local.json`](agentdojo-local.json).

## Limits

- This is candidate-authored evaluation, not independent validation.
- Only the Banking suite and direct injection attack were evaluated.
- A 9.7B quantized local model is not representative of larger hosted models or other agent stacks.
- Development utility was low in every mode, limiting conclusions about production usefulness.
- Held-out data was evaluated once with ASG only; it was not exposed to baseline tuning.
- Zero observed attacks is not proof of complete security.

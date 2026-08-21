# Agent task-quality experiment

The security evaluation in [`agentdojo-benchmark.md`](agentdojo-benchmark.md) measured what the
enforcement point stops. This one measures something different and equally concrete: **how often
the agent actually completes the user's task, and what that costs in tokens and latency.**

It runs on the same frozen protocol, the same local model, and the same task split. It is
preregistered here before the interventions are run.

## The problem, from the existing traces

Classifying every failed case in the published runs gives an actionable breakdown rather than a
single rate:

| Outcome | Development (40) | Held-out (32) |
| --- | ---: | ---: |
| Succeeded | 19 | 14 |
| Acted, wrong result | 15 | 6 |
| Answered without calling any tool | 5 | 8 |
| Partially blocked, then gave up | 1 | 4 |

Mean assistant turns: 2.5 development, 2.0 held-out. On multi-step banking tasks the agent takes
about two turns and stops. Across both splits, 13 of 72 cases produce an answer with no tool call
at all — the model responds instead of acting.

Those are agent-engineering failures, not policy failures. The unprotected baseline shows the same
pattern, so they are not caused by the gate.

## Question

Can task completion be improved on this protocol by changing how the agent is driven — prompt,
tool-result format, turn handling — without touching the policy, the task split, or the pinned
model artifact?

## Metrics

**Primary:** task completion (AgentDojo `utility`) on the 40 development cases, compared
**per case** against the baseline rather than as an aggregate rate.

**Secondary:**

- outcome-mode migration: which failure category each case moved between;
- completion tokens and prompt tokens per case;
- model latency per case and assistant turns per case;
- for gated runs only, blocked calls and false denials, so a utility gain is never bought by
  weakening enforcement.

Token and latency figures come from metering every model call and attributing it to the task
AgentDojo is currently logging, so they are recorded in the trace itself. Failed attempts are
metered as well: the client retries with backoff, so without that a degraded run shows a small
model latency next to a huge task duration and the gap is invisible.

## Host load

Local inference shares the machine with everything else running on it. The first instrumented
run of this experiment showed the problem immediately: one task reported 123 s of model latency
inside 1,046 s of wall time, and a trivial completion took 19 s while the host was swapping. Those
numbers are not comparable to a run started on an idle machine, and the retries can change task
outcomes too, so that run was discarded rather than reported.

Every run therefore probes the model with a trivial completion first and refuses to start if the
median exceeds `ASG_MODEL_PROBE_BUDGET_MS` (default 8,000 ms). The measured probe latency is
recorded in the report, so a run's cost figures always carry the condition they were taken under.
Raising the budget is allowed; doing it silently is not.

## Rules

1. **Development split only.** The Banking held-out split has already been used twice and is not
   available for tuning or for confirming this work. Confirmation uses a suite that has never been
   run here.
2. **One change per run.** Each intervention is a separate run directory with its own report,
   compared against the immediately preceding accepted configuration.
3. **Nothing else moves.** Policy, tenant data, task partition, seed, temperature, reasoning
   effort, and the model digest stay exactly as pinned. A run that changes two things at once is
   discarded.
4. **Acceptance:** a change is kept only if paired utility does not decrease and at least one
   primary or secondary metric improves. Cost-only improvements are legitimate results.
5. **Everything is reported**, including interventions that made things worse. A rejected
   intervention is evidence about the system, not a failed attempt to be hidden.
6. **Security evidence is not re-derived here.** These runs do not replace or update the published
   enforcement results.

## Preregistered interventions

Each intervention is a named variant in
[`benchmark/agentdojo_variants.json`](../benchmark/agentdojo_variants.json), applied with
`--variant`. A variant may only set `system_message` or `tool_output_format`; the runner refuses
anything else, so a change to the seed, model, or policy cannot be smuggled in under the same
protocol. Every report records the variant name and a hash of both the variant and the file.

In order. Later entries may be dropped if earlier ones make them irrelevant; nothing is added
after seeing a result without saying so.

1. **System prompt.** The default AgentDojo system message does not tell the model to act before
   answering. Rewrite it to require tool use for anything it cannot know, and to keep going until
   the task is done.
2. **Tool output format.** AgentDojo can serialise tool results as YAML or JSON. YAML is the
   default; JSON may parse more reliably for this model.
3. **Empty-response continuation** (`v3-retry-empty-response`). When the assistant returns neither
   text nor a tool call, the tool-execution loop sees no call and the task ends on silence. This
   re-asks instead, dropping the blank turn so the transcript stays a usable conversation, with a
   bounded number of retries so a model that keeps returning nothing ends the task rather than
   looping. The wrapper is applied by identity to the configured model element, which AgentDojo
   places both at the top level and inside the tool-execution loop.
4. **Post-denial guidance** (`v4-denial-guidance`). When policy refuses a call, the agent currently
   sees `decision:reason` and often abandons the whole task. This appends what the refusal means
   and what to do next — finish the parts that are allowed, do not retry the refused call, tell the
   user what is waiting on approval. The machine-readable head of the error is unchanged and comes
   first, so traces recorded before guidance existed still parse identically. Measured on the gated
   arm.
5. **Model comparison** (`v5-mistral`). A second freely available local model — `mistral:latest`,
   7.2B, already installed, tool-capable — on the identical protocol. A variant that changes the
   model must pin its digest, so a run can never use a re-pulled artifact under the same tag.

   This is **not** an intervention and the acceptance rule does not apply to it: choosing a model
   is a tradeoff between task completion, tokens, and latency, not a change to keep or reject.
   Compare it with `--across-models`, which relaxes only the model check and suppresses the
   verdict.

## A note on the system prompt

The system message is also the surface the injection attacks target. Changing it can move the
security results, and this experiment runs on the unprotected arm and does not re-derive them. Any
variant adopted here must be re-measured on the gated arm before it is used to support a security
claim.

## Smoke runs

`--limit N` runs only the first N user and injection tasks, to check that a variant is wired
correctly before committing an hour of inference to it. Such a run records `complete_phase: false`
and the comparison tool refuses it outright, so a smoke test cannot be mistaken for a result.

## Comparability

`compare_agent_quality` refuses any pair of runs that differ in phase, mode, protocol hash, policy
hash, or model. Comparing a gated run to an ungated one measures the gate; comparing two models
measures the model. Both are real questions, neither is what the acceptance rule answers, so the
mismatch has to be deliberate rather than accidental.

## Confirmation

The configuration that survives development is run **once** on the `slack` suite — 21 user tasks
and 5 injection tasks, 105 cases, declared in the protocol in full before it is run so no subset
can be chosen after seeing results. Slack has never been used here, and Banking held-out has
already been spent twice.

The confirmation phase declares no tenant policy, because none exists for that suite. The runner
refuses `--mode asg` for a phase without a policy, so an unpoliced gated run is impossible rather
than merely unwise.

That result is the reported outcome. If it does not reproduce the development gain, the development
gain is reported as not confirmed.

## Reproducing

```bash
docker compose up -d --build

# Check the wiring cheaply first
make agentdojo-quality-smoke VARIANT=v1-system-prompt

make agentdojo-quality-baseline
make agentdojo-quality-variant VARIANT=v1-system-prompt
make agentdojo-quality-compare VARIANT=v1-system-prompt
```

`v4-denial-guidance` is measured on the gated arm, so it needs `QUALITY_MODE=asg` and its own
baseline in that mode. Comparing a gated run against an ungated one measures the gate, not the
intervention.

Each full run is roughly an hour on the preregistered machine, so the smoke target exists to catch
a wiring mistake in two minutes rather than after the run.

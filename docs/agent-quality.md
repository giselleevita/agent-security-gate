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

In order. Later entries may be dropped if earlier ones make them irrelevant; nothing is added
after seeing a result without saying so.

1. **System prompt.** The default AgentDojo system message does not tell the model to act before
   answering. Rewrite it to require tool use for anything it cannot know, and to keep going until
   the task is done.
2. **Tool output format.** AgentDojo can serialise tool results as YAML or JSON. YAML is the
   default; JSON may parse more reliably for this model.
3. **Empty-response continuation.** When the assistant returns neither text nor a tool call, the
   run currently ends. Continue instead of accepting silence as an answer.
4. **Post-denial guidance.** When policy refuses a call, tell the agent what happened in a form it
   can act on, so it does not abandon the task. This targets the "partially blocked, then gave up"
   category and is measured on a gated run.
5. **Model comparison.** A second freely available local model on the identical protocol, for
   quality-per-token and latency evidence rather than a winner.

## Confirmation

The configuration that survives development is run **once** on an AgentDojo suite not used during
tuning. That result is the reported outcome. If it does not reproduce the development gain, the
development gain is reported as not confirmed.

## Reproducing

```bash
docker compose up -d --build
python -m scripts.run_agentdojo_benchmark --phase development --mode no-authorizer \
  --output-dir results/agentdojo/quality/baseline
python -m scripts.compare_agent_quality \
  --baseline results/agentdojo/quality/baseline \
  --run results/agentdojo/quality/<variant>
```

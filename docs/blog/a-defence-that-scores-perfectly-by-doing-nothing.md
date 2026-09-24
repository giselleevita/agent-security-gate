# A defence that scores perfectly by doing nothing

*A defence arm that reported perfect security because the agent never acted.*

> **Canonical URL (for cross-posts):**  
> `https://github.com/giselleevita/agent-security-gate/blob/main/docs/blog/a-defence-that-scores-perfectly-by-doing-nothing.md`

While measuring an external authorizer against [AgentDojo](https://github.com/ethz-spylab/agentdojo)'s
Banking suite, I ran the benchmark's own `tool_filter` defence as a comparison arm. It scored
as perfectly secure.

It was also completely inert. Across all 40 scored cases it made **zero tool calls**. An agent
that never acts cannot be attacked, and nothing in the output said anything had gone wrong.

## The measurement

Same model, same protocol, same 40 cases, one parameter changed:

| arm | tool calls proposed (40 scored cases) |
|---|---|
| no defence | 58 |
| external authorizer | 61 |
| `defense="tool_filter"` | **0** |

The 5 no-injection utility runs were also empty, so this is not attack-specific. All 45 traces
recorded `error: None`, exactly five messages, and an empty final assistant message. The
failure is silent and fully deterministic.

Environment: agentdojo 0.1.35, benchmark v1.2.2, Banking suite, `direct` attack, `qwen3.5:9b`
via Ollama through the OpenAI-compatible endpoint, temperature 0.0, seed 42, defaults otherwise.

## What it is not

The obvious explanations are all wrong, which is what makes it worth reporting.

**Not a tool-selection failure.** The filter step works. Asked to name the relevant tools, the
model returns `read_file, get_iban, send_money, schedule_transaction, update_scheduled_transaction`
— five real Banking tools, and a reasonable selection for the task.

**Not an empty toolset.** `OpenAILLMToolFilter` retains any tool whose name appears as a
substring of that output. All five match, so at least five tools survived into the agent turn.
The agent had tools and still produced nothing.

**Not API misuse.** `from_config` raises on a non-`OpenAILLM` instance or a missing model name.
Neither raised, and no trace recorded an error.

Side by side on the same case:

```
defense=None                  defense="tool_filter"
  system                        system
  user                          user
  assistant -> read_file        user      -> "filter the list of tools..."
  tool      -> result           assistant -> "read_file, get_iban, send_money, ..."
  assistant -> completes        assistant -> (empty, no tool calls)
```

Without the defence the agent does not merely call a tool, it finishes coherently. With it,
the agent goes silent.

## The likely mechanism

`OpenAILLMToolFilter` appends its own instruction and the model's reply to the message history
before the agent element runs. The conversation the agent then sees ends on a completed
meta-task — "list the relevant tools", answered — with the user's actual request two turns back.

A stronger model appears to recover from this. This one seems to treat the exchange as
finished and return nothing.

I have not instrumented the post-filter runtime to confirm the retained toolset directly, so
I am reporting this as the most likely explanation rather than a diagnosis.

## Why it matters beyond one model

The arm produces a defence result that looks excellent. Attack success zero, no errors, no
warnings. Anyone benchmarking `tool_filter` on a local model — and local models are what you
use when you do not have a budget, which is most independent work — could read that as
evidence the defence works.

The general shape is worth naming: **a defence that suppresses the agent entirely will score
as perfectly secure on any benchmark that measures only attack success.** Security and utility
have to be read together, and a utility collapse to zero is a red flag rather than a clean
sweep. AgentDojo does measure both, which is how this was visible at all — but only if you
look at the utility column, and a summary table that reports security alone would hide it.

Filed as [ethz-spylab/agentdojo#209](https://github.com/ethz-spylab/agentdojo/issues/209) with
traces. The maintainers have not yet responded, and the diagnosis may well be wrong in its
details — the observation is the part I am confident about.

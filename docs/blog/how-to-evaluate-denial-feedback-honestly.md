# How to Evaluate Agent Denial Feedback Without Fooling Yourself

*A methodology note on measuring recovery and policy leakage at the same time.*

When a tool-using agent is denied by policy, the obvious response is to explain why.
That may help the agent recover, but it can also reveal the policy boundary one probe
at a time.

This creates a security measurement problem:

> How much denial feedback helps a legitimate agent find a safe path without turning
> the enforcement point into a policy oracle?

SafeRemediate is my attempt to make that question testable. The important work is not
producing a large results table. It is building a protocol that makes an inconvenient
result difficult to explain away.

## Measure both sides of the trade-off

A benchmark that records only task completion rewards over-disclosure. A system can
appear helpful simply because its denial response exposes the exact field, threshold,
or role that must change.

SafeRemediate therefore treats feedback strategy as the independent variable and
measures two outcome families:

1. **Recovery:** did the agent complete the task through a policy-compliant path after
   at least one denial?
2. **Inference:** how accurately could the agent reconstruct protected state from the
   feedback it received?

The seven conditions range from an opaque denial (B0) to full policy explanation (B2),
human approval (B5), and a typed, capability-bound remediation ticket (B6). The agent,
task, policy, and environment stay fixed across conditions.

The complete definitions live in the
[methodology](../../saferemediate/docs/methodology.md), rather than being reconstructed
after results are observed.

## Freeze the claims before the model runs

The [pre-registration](../../saferemediate/docs/preregistration-v0.1.md) records:

- hypotheses and effect-size thresholds;
- primary and secondary outcomes;
- planned comparisons and statistical methods;
- exclusion and parse-failure rules;
- episode and policy hashes;
- canary gates; and
- explicit falsification criteria for the proposed B6 mechanism.

This matters because model evaluations contain many degrees of freedom. A researcher
can change a prompt, drop awkward traces, redefine “safe,” or promote an exploratory
comparison after seeing the data. Each choice may sound reasonable by itself while
quietly converting a test into a story.

Freezing the protocol does not guarantee a correct conclusion. It does make deviations
visible.

## Keep protected state out of the agent's view

Leakage measurement is meaningless if the answer is accidentally present in the
prompt or trace history.

SafeRemediate separates data into two views:

- the **agent view** contains the task, public catalogue, and feedback allowed by the
  assigned strategy;
- the **evaluator view** contains protected state, expected outcomes, and probe targets.

The [field-level leakage audit](../../saferemediate/docs/leakage_audit.md) documents
each route between episode data, policy enforcement, feedback formatting, trace
storage, and scoring. Tests assert that protected fields do not reach the prompt or
the non-disclosing feedback conditions.

B2 and B3 intentionally reveal more information. That is part of the treatment, not
an accidental leak, and is labelled as such.

## Separate pipeline checks from behavioural evidence

Not every successful run supports a claim about models.

SafeRemediate labels artifacts by evidence type:

- a deterministic mock run checks plumbing and scoring;
- a canary checks whether a real model and adapter can participate reliably;
- a single-model pilot is exploratory;
- only the pre-specified confirmatory design can test the registered hypotheses.

This prevents “the pipeline ran” from becoming “the hypothesis passed.” It also makes
the free local-model path useful without overstating what one model proves.

## Record failures instead of silently repairing them

The canary has pass/fail gates for completion, provider and parse failures, accidental
leakage, strategy separation, scoring invariants, and trace reconstruction. All traces
must be reviewed before progressing.

One seeded canary exposed an episode-classification defect. The correct response was
not to patch the dataset and keep the favourable rows. The run was permanently
excluded, the reason was documented, and a
[pre-registration amendment](../../saferemediate/docs/preregistration-amendment-v0.1.md)
recorded what changed and what remained frozen.

Discarded work is still evidence about the benchmark. A visible discard trail is far
more credible than a mysteriously clean results directory.

## Make negative results survivable

The typed-ticket mechanism has written falsification criteria. It fails its claimed
value if it does not improve safe completion, leaks beyond the non-inferiority margin,
or permits any ticket replay, widening, substitution, or transfer.

That commitment changes the engineering incentives. A poor result becomes a useful
mechanism finding rather than pressure to redefine success.

## A practical checklist

Before treating an agent-security evaluation as evidence, ask:

1. Was the hypothesis written before the relevant model output was observed?
2. Are recovery and leakage measured together?
3. Can the agent-visible trace be reconstructed independently?
4. Are mock, canary, exploratory, and confirmatory artifacts clearly distinguished?
5. Are exclusions reported with reasons?
6. Would a negative result remain publishable under the stated rules?

If the answer to any of these is no, another hundred runs will not fix the design.

The SafeRemediate package, protocol, and free local-model instructions are in
[`saferemediate/`](../../saferemediate/README.md).

---

*Giselle Evita Koch — [agent-security-gate](https://github.com/giselleevita/agent-security-gate)*

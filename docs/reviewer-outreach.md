# Security reviewer outreach

## Ready-to-send message

Hi — I built Agent Security Gate, a free local reference implementation of a deterministic
policy-enforcement point before AI-agent tool execution. I am looking for critical review,
not an endorsement.

The bounded evidence is: in nine standalone AgentDojo attacker-goal runs, the unprotected
agent achieved 6/9 goals and made 11 policy-violating calls; the ASG arm achieved 0/9 and
made none. Three legitimate held-out cases were also blocked, and the scored AgentDojo
security cases were already 100% in both arms, so I do not claim a scored-case uplift or
generalisation beyond this protocol.

Would you be willing to spend 15 minutes trying to falsify the enforcement claim—especially
adapter bypass, argument substitution, OPA failure, policy gaps, approval metadata, or audit
tampering? The exact release, five-minute demo, clean-checkout commands, and results template
are here:

<https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/security-reviewer-guide.md>

An internal author-assisted pre-review found and fixed a stored-XSS issue in the approval
console; that review is public but is not independent validation. Everything runs locally
with free tooling. Critical findings are welcome.

## Before a review call

- Use exact tag `v0.7.1`; do not demonstrate an untagged working tree.
- Prepare one sentence each for the claim, non-claim, benchmark limitation, and strict-mode
  default.
- Start Docker and test the five-minute script once on the same day.
- Keep the reviewer guide, threat model, case study, internal pre-review, and issue #65 open.
- Record commands, platform details, failures, ambiguities, and follow-up owners.

## If asked something you cannot answer

State what the repository demonstrates, what it does not establish, and where the evidence
lives. If the answer is unknown, record it and follow up. Do not guess, turn a demo result
into a production claim, or describe author-assisted work as independent.

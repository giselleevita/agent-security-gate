# SafeRemediate Threat Model

## Actors

| Actor | Trust | Capabilities |
|---|---|---|
| End user | Benign or malicious | Provides task; may probe via agent |
| Agent (LLM or rule-based) | **Untrusted** reasoning | Proposes tool calls; may be prompt-injected |
| Policy PEP (ASG) | Trusted | Deterministic allow/deny/approval |
| Remediation issuer | Trusted | Signs typed remediation tickets (B6) |
| Human approver | Trusted | Resolves B5 approval flows |

## Assets

**Public (P):** Allowlisted tool names; public resource catalog; coarse denial category codes;
user-visible task description; session ID; remediation transition enum.

**Protected (H):** Hidden resource identifiers; existence of specific non-catalog resources;
exact policy thresholds; role/group membership; full rule structure; sensitive path prefixes;
internal tenant policy configuration.

## In scope

- Malicious user indirect prompt injection
- Adaptive policy probing over multiple turns
- Denial-feedback leakage (existing pattern per Causality Laundering)
- Legitimate recovery after policy denial
- Remediation ticket replay, widening, substitution, transfer

## Out of scope

- Compromise of PEP, issuer keys, or audit log
- Model weight tampering
- Physical side channels

## Enforcement boundary

All tool calls pass through ASG `POST /v1/gateway/decide` (or in-process runtime parity for
benchmark replay). Recovery actions that perform side effects still require a fresh allow decision.

Enforceable AI Security

# I build enforceable AI security systems

My work focuses on the infrastructure around AI agents: evaluating vendor risk,
enforcing policy before tool calls execute, grounding governance in cited knowledge,
producing verifiable audit evidence, and shipping secure cloud infrastructure.


Evaluate → Enforce → Govern → Evidence → Ship

[Try locally (free)](https://github.com/giselleevita/agent-security-gate#quick-start-local-free) [ASG v0.6.0](https://github.com/giselleevita/agent-security-gate/releases/tag/v0.6.0) [Demo video](https://github.com/giselleevita/agent-security-gate/raw/main/docs/assets/asg-demo.mp4)

## System map

Five repositories, one intentional stack — not a project gallery.

1. Evaluate Vendor red-team reports
2. Enforce Runtime agent security gateway
3. Govern Cited RAG with offline evals
4. Evidence Signed compliance bundles
5. Ship Secure cloud reference architecture

## Five layers

Evaluate

![Vendor Red-Team Passport dashboard](https://raw.githubusercontent.com/giselleevita/vendor-red-team-passport/main/docs/screenshots/dashboard.png)

### vendor-red-team-passport

LLM vendor red-teaming — 10 attack classes, OWASP/NIST mapping, tamper-evident Passport Reports.

[View on GitHub](https://github.com/giselleevita/vendor-red-team-passport) [Case study](https://github.com/giselleevita/vendor-red-team-passport/blob/main/docs/CASE_STUDY.md)

Enforce

![Agent Security Gate demo — blocked unsafe tool call and audit trace](https://raw.githubusercontent.com/giselleevita/agent-security-gate/main/docs/assets/asg-demo.gif)

### agent-security-gate

Runtime policy gateway for AI agent tool calls — OPA enforcement, approvals, DLP, hash-chained audit. v0.6.0, 167 tests.

[View on GitHub](https://github.com/giselleevita/agent-security-gate) [Technical brief](https://github.com/giselleevita/agent-security-gate/blob/main/docs/technical-brief.md) [Blog post](https://github.com/giselleevita/agent-security-gate/blob/main/docs/blog/agent-security-at-tool-boundary.md)

Govern

![Security and Compliance Copilot interface](https://raw.githubusercontent.com/giselleevita/security-compliance-copilot/main/docs/screenshots/copilot-ui.png)

### security-compliance-copilot

Grounded NIST/CISA RAG with citations, guardrails, and offline evals. Guidance layer — not runtime enforcement.

[View on GitHub](https://github.com/giselleevita/security-compliance-copilot)

Evidence

![ProofRail analyst console](https://raw.githubusercontent.com/giselleevita/proofrail-evidence-api/main/docs/screenshots/analyst-console.png)

### proofrail-evidence-api

Signed, verifiable evidence bundles for compliance workflows — audit-ready records, not just logs.

[View on GitHub](https://github.com/giselleevita/proofrail-evidence-api)

Ship

![Preview of secure-docs-aws GitHub repository](https://opengraph.githubassets.com/1/giselleevita/secure-docs-aws)

### secure-docs-aws

Serverless AWS document storage — Cognito, KMS, presigned URLs, ownership checks, audit logging.

[View on GitHub](https://github.com/giselleevita/secure-docs-aws)

## Writing

Technical notes on agent security and engineering practice.

### Why Agent Security Belongs at the Tool-Call Boundary

Pre-execution policy enforcement for tool-using LLM agents — where controls actually matter.

 [Read on GitHub](https://github.com/giselleevita/agent-security-gate/blob/main/docs/blog/agent-security-at-tool-boundary.md) [LinkedIn draft](https://github.com/giselleevita/agent-security-gate/blob/main/docs/blog/cross-posts/linkedin.md) [dev.to draft](https://github.com/giselleevita/agent-security-gate/blob/main/docs/blog/cross-posts/devto.md)

## Supporting work

Additional repositories available for deeper technical review.

### aegisais

Maritime AIS integrity checker with anomaly detection, map UI, and alert workflows.

[View on GitHub](https://github.com/giselleevita/aegisais)

### ToolShield

Bachelor thesis on prompt-injection detection — research absorbed into agent-security-gate benchmark.

[Request access](mailto:giselle.evita@gmail.com?subject=Portfolio%20review%20access%3A%20ToolShield)

## Target roles

- AI Security Engineer
- Agentic AI Platform Engineer
- LLM Security Engineer
- AI Governance Engineer
- Security Engineer, AI Systems

## Review the stack in 15 minutes

Start with [agent-security-gate](https://github.com/giselleevita/agent-security-gate) — watch the README GIF or `docker compose up` in 5 minutes.

[Technical brief](https://github.com/giselleevita/agent-security-gate/blob/main/docs/technical-brief.md)

 [Get in touch](mailto:giselle.evita@gmail.com)
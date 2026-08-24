## Agent Security Gate v0.7.1

**Security pre-review patch** for the free, local v0.7 reviewer package.

### Security fix

- Agent-authenticated approval fields previously reached the privileged approval console
  through `innerHTML`. A malicious field could therefore execute script in an approver's
  browser and cross the agent-to-approver trust boundary.
- The console now creates DOM nodes and assigns untrusted values only through `textContent`.
  Inline code was moved to same-origin assets and the UI now sends a restrictive Content
  Security Policy plus clickjacking, MIME-sniffing, and referrer protections.
- Regression tests reject HTML parsing sinks and require the security headers.

### Review status

The internal adversarial pre-review found this issue before external outreach. It also
reconfirmed the documented medium residual denial-of-service exposure from missing
application-level body-size and global concurrency limits. This review is author-assisted
and is not independent validation.

### Evaluation boundaries

The v0.7.0 AgentDojo evidence and all its stated limitations are unchanged. This release
does not claim to prevent prompt injection, generalise beyond the published suite/model/
policy, or provide independent validation.

Start with [the security reviewer guide](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/security-reviewer-guide.md), then read the
[internal pre-review](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/security_best_practices_report.md) and
[case study](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/case-study.md).

# Internal security best-practices pre-review

Date: 2026-08-24  
Scope: FastAPI gateway, approval console, authorization boundary, policy and audit-facing
routes  
Status: author-assisted internal review; **not independent validation**

## Executive summary

The review confirmed one high-severity stored cross-site scripting path in the privileged
approval console and fixed it before external outreach. Agent-controlled approval metadata
was stored in PostgreSQL and later inserted with `innerHTML`; script running in that origin
could read the approver credential from the page or invoke approver-only endpoints. The fix
uses text-only DOM APIs, removes inline code, and adds a restrictive CSP and regression
tests.

No authentication bypass, SQL injection, fail-open OPA behavior, open redirect, or obvious
SSRF bypass was confirmed in the reviewed paths. Sensitive routes consistently enforce the
agent or approver role; SQL parameters are bound; the HTTP adapter validates and pins the
destination IP and disables redirects. The repository's explicit non-claims remain
important: enforcement is advisory unless strict mode is enabled, and the reference stack
does not include application-level body-size or global concurrency limits.

## Findings

### ASG-SEC-001 — stored XSS crosses the agent-to-approver boundary

- Severity before fix: **High**
- Status: **Fixed in v0.7.1 candidate**
- Evidence before fix: `app/static/approvals.html` rendered `tool`, `requester_id`, status,
  timestamps, and API error bodies with `innerHTML`. `POST /v1/approvals/request` accepts
  agent-controlled metadata and stores it for the approver queue.
- Impact: a valid but compromised agent credential could plant active markup that executes
  when an approver refreshes the queue. Same-origin script could access the token input or
  make authenticated actions from the page.
- Fix: `app/static/approvals.js` builds elements with `createElement`, `textContent`, and
  `replaceChildren`. JavaScript and CSS are external same-origin assets. `app/routers/ui.py`
  sends CSP, frame denial, MIME-sniff prevention, and no-referrer headers. `tests/test_ui.py`
  enforces these invariants.
- Residual risk: independent browser-level penetration testing has not occurred.

### ASG-SEC-002 — authenticated resource exhaustion remains ingress-dependent

- Severity: **Medium**
- Status: **Open and documented as TM-006**
- Evidence: `app/schemas.py` accepts nested request context without an application-level
  byte cap; `app/main.py` has per-caller Redis rate limits but no global concurrency limit.
- Impact: authenticated callers can submit oversized or sufficiently concurrent work to
  pressure API memory, Redis, PostgreSQL, OPA, or audit storage.
- Existing controls: per-caller limits, dependency timeouts/fail-closed errors, schema
  validation, and documented ingress requirements.
- Recommendation before Internet exposure: enforce request-body size, global concurrency,
  and connection limits at the reverse proxy and application boundary; add saturation
  tests and telemetry. The free local reviewer stack is not presented as Internet-ready.

### ASG-SEC-003 — strict execution binding is opt-in

- Severity: **Medium if misdeployed; informational for the documented demo**
- Status: **Accepted and prominently documented**
- Evidence: `ASG_ENFORCE_MODE` defaults to `off`; in this mode a caller can invoke the demo
  tool endpoints without presenting a prior single-use decision grant.
- Impact: treating the default demo configuration as a production enforcement point would
  make `/v1/gateway/decide` advisory rather than binding.
- Existing controls: strict mode atomically consumes an operation-bound grant, documentation
  labels the default, and the reviewer demo exercises the protected callable seam.
- Recommendation: use `ASG_ENFORCE_MODE=strict` for every pilot and verify adapter bypass and
  argument substitution as deployment acceptance tests.

## Review checks performed

- Traced agent and approver credentials through all FastAPI router dependencies.
- Traced approval fields from authenticated creation through database storage and browser
  rendering.
- Reviewed SQL call sites for parameter binding and dynamic query construction.
- Reviewed HTTP egress validation, redirects, DNS resolution/pinning, and timeouts.
- Searched Python and browser code for command execution, unsafe deserialization, disabled
  TLS checks, and HTML injection sinks.
- Compared observed limitations with the threat model, reviewer guide, and README claims.
- Ran Ruff and focused UI regression tests after the fix; the complete `make verify` result
  is required before merge.

## External review priorities

1. Bypass the supported adapters and call tool endpoints directly in strict mode.
2. Change tool arguments between authorization and execution; replay or substitute grants.
3. Stop or degrade OPA/Redis/PostgreSQL and look for fail-open behavior.
4. Exercise hostname parsing, redirects, DNS rebinding, mixed encodings, and private IPs.
5. Put active markup and unusually large nested values in approval fields and error paths.
6. Delete, reorder, truncate, or recompute audit entries with and without HMAC/WORM options.

Finding a defect during this review should be recorded as a result, not treated as a failed
presentation. No independent reproduction should be claimed until issue #65 contains a
report from someone who did not author the code or evaluation.

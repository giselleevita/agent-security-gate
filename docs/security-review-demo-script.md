# Five-minute security review demonstration

Use a clean checkout of the exact release tag. Do not skip the denied and outage cases;
the execution counter, rather than the response text alone, is the important observation.

## Before the call

```bash
git clone --branch v0.7.1 https://github.com/giselleevita/agent-security-gate
cd agent-security-gate
cp .env.example .env
docker compose up -d --build
```

Open with this bounded claim:

> ASG is a reference policy-enforcement point immediately before agent tool execution. It
> does not detect prompt injection. This demo asks whether a denied, changed, or
> dependency-failed tool call can still execute the protected Python function.

## 0:00–1:00 — locate the enforcement seam

Show `adapters/tool_authorization.py` and identify the authorize-then-execute boundary.
Point out that only an explicit allow reaches the callable.

## 1:00–3:30 — exercise the protected function

```bash
python examples/protected_function_tool.py
```

Ask the reviewer to watch the execution counter. The allowed case increments it. The
denied path, post-authorization argument substitution, approval-required path, and SSRF
case do not. Avoid describing this as proof; it is an inspectable regression demonstration.

## 3:30–4:30 — remove the policy dependency

```bash
docker compose stop opa
python examples/protected_function_tool.py --opa-down
```

The expected result is a non-allow outcome and no protected-function execution. Restore
the dependency afterward:

```bash
docker compose start opa
```

## 4:30–5:00 — invite falsification

Ask the reviewer to try one concrete bypass: call the adapter directly, alter arguments
after authorization, replay a grant, use an unknown tool, stop OPA mid-call, place active
HTML in approval metadata, or recompute/delete audit entries. Link the exact tag and the
independent-results template rather than asking for a general endorsement.

If a command fails unexpectedly, record the platform, exact commit, full command, and
failure output. Do not improvise a success claim; an unreproduced result is useful review
evidence.

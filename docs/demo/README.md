# Demo assets

## README GIF (`docs/assets/asg-demo.gif`)

Terminal recording of the core policy story: blocked unsafe tool call, audit trace, allowed safe call.

### Regenerate

```bash
# 1. Start the demo stack
docker compose up -d --build
curl -sf http://localhost:8000/health

# 2. Install VHS (macOS)
brew install vhs

# 3. Record (from repo root)
vhs docs/demo/asg-demo.tape
```

The tape file is `docs/demo/asg-demo.tape`. Output is written to `docs/assets/asg-demo.gif`.

### CI note

GIF generation requires a running gateway on `localhost:8000`. It is checked into the repo so CI does not need to re-record on every run. Re-run locally after visible API or demo flow changes.

## Protected function tool (`docs/assets/protected-tool-demo.gif`)

A real Python function with a side effect behind the authorization contract, then the same
call with the policy engine stopped. Covers allow, an argument that crosses a policy
boundary, argument tampering after a previous allow, SSRF, approval-required, and the
fail-closed path. An execution spy counts every actual invocation, so the recording cannot
show more than happened.

### Regenerate

```bash
docker compose up -d --build
vhs docs/demo/protected-tool.tape
```

The tape stops and restarts the `opa` container as part of the recording. It leaves the
stack running.

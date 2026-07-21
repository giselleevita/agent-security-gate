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

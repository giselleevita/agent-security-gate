# Fly.io demo deployment (optional — costs money)

> **Not currently hosted.** `https://asg-demo.fly.dev` is documented for self-deploy only; there is no live public demo at this time. Use the README GIF + local `docker compose up` instead.
>
> **Skip this for a free portfolio.** Fly Postgres and Redis run 24/7 and typically cost **~$3–10+/month** even when the gateway is idle.

Self-hosted reference demo for reviewers who need a public URL. **Not for production use.**

## Free alternative (recommended)

```bash
docker compose up -d --build
open http://localhost:8000/demo
```

The README GIF and MP4 work without any hosting bill.

## If you still want Fly (paid)

See sections below. Requires a credit card on file.

## URLs after you deploy (not live by default)

| URL | Purpose |
|-----|---------|
| `https://asg-demo.fly.dev` | Gateway (example hostname from bootstrap script) |
| `https://asg-demo.fly.dev/demo` | Public curl examples |

## One-command deploy

```bash
flyctl auth login
./scripts/fly_demo_bootstrap.sh
./scripts/verify_fly_demo.sh https://asg-demo.fly.dev
```

## Demo mode constraints

- `ASG_DEMO_MODE=true` — fixed demo tokens (`test-token`, `approver-token`)
- Mock tool routing via `/agent` only
- Audit log on ephemeral disk — not durable across restarts
- Machines auto-stop when idle (compute savings; Postgres/Redis still bill)

## Architecture

```mermaid
flowchart LR
  Reviewer[Reviewer] --> GW[asg-demo]
  GW --> OPA[asg-demo-opa]
  GW --> PG[(Fly Postgres)]
  GW --> Redis[(Upstash Redis)]
```

## Tear down (stop charges)

```bash
fly apps destroy asg-demo asg-demo-opa
fly postgres destroy asg-demo-db
fly redis destroy asg-demo-redis
```

## Local alternative

```bash
docker compose up -d --build
curl -s http://localhost:8000/demo | jq .
```

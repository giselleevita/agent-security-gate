# Local development environment

## Quick setup

```bash
./scripts/setup_dev_env.sh
source .venv/bin/activate
```

This writes `.env` with your `ASG_UID`/`ASG_GID`, creates `.venv`, starts the standard Docker stack, and checks Fly login status.

## Docker Compose modes

| Mode | Command | Port |
|------|---------|------|
| **Standard (recommended)** | `docker compose up -d --build` | `localhost:8000` → gateway |
| **HA drill** | `docker compose -f docker-compose.yml -f docker-compose.ha.yml up -d --build` | `localhost:8000` → nginx lb |

**Do not mix modes.** If you switch from HA back to standard, run:

```bash
docker compose -f docker-compose.yml -f docker-compose.ha.yml down --remove-orphans
docker compose up -d --build
```

A leftover `lb` container without healthy gateways causes **502 Bad Gateway**.

## Verify

```bash
curl -s http://localhost:8000/health
curl -s http://localhost:8000/demo | jq .
./scripts/record_demo_gif.sh
```

## Fly.io live demo (optional — paid)

Skip unless you accept ~$3–10+/month for Postgres + Redis.

```bash
flyctl auth login
./scripts/deploy_demo_now.sh
```

See [demo-deployment.md](demo-deployment.md) for cost warning and tear-down commands.

## macOS notes

- Set `ASG_UID=$(id -u)` and `ASG_GID=$(id -g)` in `.env` so the gateway can write to `./audit`.
- OPA/Postgres/Redis images may run under amd64 emulation on Apple Silicon; this is expected for pinned digests.

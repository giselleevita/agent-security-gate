#!/usr/bin/env bash
# One-time local dev environment setup for agent-security-gate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Writing .env (ASG_UID/GID for docker compose bind mounts)"
if [ ! -f .env ] || ! grep -q '^ASG_UID=' .env 2>/dev/null; then
  {
    echo "# Local dev — docker compose variable substitution"
    echo "ASG_UID=$(id -u)"
    echo "ASG_GID=$(id -g)"
    echo "GATEWAY_PORT=8000"
  } >> .env
  echo "Appended ASG_UID/GID to .env"
else
  echo ".env already has ASG_UID"
fi

echo "==> Python venv"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -U pip
pip install -q -e ".[dev]"

echo "==> Docker stack (standard compose, not HA)"
if command -v docker >/dev/null 2>&1; then
  # Tear down orphaned HA lb if a prior session left it running
  docker compose -f docker-compose.yml -f docker-compose.ha.yml down --remove-orphans 2>/dev/null || true
  export ASG_UID="$(id -u)" ASG_GID="$(id -g)"
  docker compose up -d --build
  echo "Waiting for gateway..."
  for _ in $(seq 1 30); do
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  curl -sf http://localhost:8000/health | python3 -m json.tool
  curl -sf http://localhost:8000/demo | python3 -c "import json,sys; d=json.load(sys.stdin); print('demo_mode:', d.get('demo_mode'))"
else
  echo "Docker not installed — skip container stack"
fi

echo ""
echo "==> Fly.io (optional — costs money, skip for free portfolio)"
if command -v flyctl >/dev/null 2>&1; then
  if flyctl auth whoami >/dev/null 2>&1; then
    echo "Fly logged in. Paid deploy only: ./scripts/deploy_demo_now.sh"
    echo "See docs/demo-deployment.md for cost warning."
  else
    echo "Fly optional. Skip unless you want a paid hosted URL."
  fi
else
  echo "Fly optional (brew install flyctl). Not needed for portfolio."
fi

echo ""
echo "Done. Activate venv: source .venv/bin/activate"
echo "Run tests: make test"
echo "Record GIF: vhs docs/demo/asg-demo.tape"

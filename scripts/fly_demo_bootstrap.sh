#!/usr/bin/env bash
# Bootstrap Agent Security Gate public demo on Fly.io (gateway + OPA + Postgres).
# Prerequisites: flyctl installed and logged in (`flyctl auth login`).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APP_GW="${ASG_FLY_APP:-asg-demo}"
APP_OPA="${ASG_FLY_OPA_APP:-asg-demo-opa}"
REGION="${ASG_FLY_REGION:-ams}"
ORG_ARG=()
if [ -n "${ASG_FLY_ORG:-}" ]; then
  ORG_ARG=(--org "$ASG_FLY_ORG")
fi

if ! command -v flyctl >/dev/null 2>&1; then
  echo "Install flyctl: brew install flyctl" >&2
  exit 1
fi

if ! flyctl auth whoami >/dev/null 2>&1; then
  echo "Run: flyctl auth login" >&2
  exit 1
fi

echo "==> Ensuring Fly apps exist"
if ! flyctl apps list --json | jq -e --arg n "$APP_OPA" '.[] | select(.Name == $n)' >/dev/null; then
  flyctl apps create "$APP_OPA" "${ORG_ARG[@]}" || true
fi
if ! flyctl apps list --json | jq -e --arg n "$APP_GW" '.[] | select(.Name == $n)' >/dev/null; then
  flyctl apps create "$APP_GW" "${ORG_ARG[@]}" || true
fi

echo "==> Deploy OPA (policies baked into custom image via fly-opa Dockerfile)"
if [ ! -f deploy/Dockerfile.opa ]; then
  cat > deploy/Dockerfile.opa <<'DOCKER'
FROM openpolicyagent/opa:0.65.0-static
COPY policies /policies
CMD ["run", "--server", "--addr", ":8181", "/policies"]
DOCKER
fi
flyctl deploy \
  --config deploy/fly-opa.toml \
  --dockerfile deploy/Dockerfile.opa \
  --app "$APP_OPA" \
  --region "$REGION" \
  --ha=false \
  --yes

echo "==> Postgres (create if missing: flyctl postgres create --name asg-demo-db --region $REGION)"
if ! flyctl postgres list --json 2>/dev/null | jq -e '.[] | select(.Name == "asg-demo-db")' >/dev/null; then
  echo "Creating Fly Postgres cluster asg-demo-db..."
  flyctl postgres create --name asg-demo-db --region "$REGION" --initial-cluster-size 1 --vm-size shared-cpu-1x --volume-size 1 --yes
fi
flyctl postgres attach asg-demo-db --app "$APP_GW" --yes || true

echo "==> Gateway secrets (rotate in production)"
AUTH_TOKEN="${ASG_DEMO_AUTH_TOKEN:-demo-$(openssl rand -hex 12)}"
APPROVER_TOKEN="${ASG_DEMO_APPROVER_TOKEN:-approver-$(openssl rand -hex 12)}"
JWT_SECRET="${ASG_DEMO_JWT_SECRET:-$(openssl rand -base64 32)}"
flyctl secrets set \
  AUTH_TOKEN="$AUTH_TOKEN" \
  APPROVER_TOKEN="$APPROVER_TOKEN" \
  JWT_SECRET="$JWT_SECRET" \
  OPA_URL="http://${APP_OPA}.internal:8181" \
  REDIS_URL="${REDIS_URL:-redis://localhost:6379/0}" \
  --app "$APP_GW" \
  --stage

echo "==> Deploy gateway"
flyctl deploy \
  --config deploy/fly.toml \
  --app "$APP_GW" \
  --region "$REGION" \
  --ha=false \
  --yes

URL="https://${APP_GW}.fly.dev"
echo ""
echo "Demo deployed: $URL"
echo "Health: curl -s ${URL}/health"
echo "Demo auth token (save for README): $AUTH_TOKEN"
echo "Approver token: $APPROVER_TOKEN"
echo ""
echo "NOTE: Set REDIS_URL to Upstash/Fly Redis before production demo traffic."
echo "Update README + profile README Live demo link to: $URL"

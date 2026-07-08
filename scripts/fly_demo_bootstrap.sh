#!/usr/bin/env bash
# Bootstrap Agent Security Gate public demo on Fly.io (gateway + OPA + Postgres + Redis).
# Prerequisites: flyctl installed and logged in (`flyctl auth login`).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APP_GW="${ASG_FLY_APP:-asg-demo}"
APP_OPA="${ASG_FLY_OPA_APP:-asg-demo-opa}"
DB_NAME="${ASG_FLY_DB:-asg-demo-db}"
REDIS_NAME="${ASG_FLY_REDIS:-asg-demo-redis}"
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

echo "==> Deploy OPA (policies baked into image)"
flyctl deploy \
  --config deploy/fly-opa.toml \
  --app "$APP_OPA" \
  --region "$REGION" \
  --ha=false \
  --yes

echo "==> Postgres (create if missing)"
if ! flyctl postgres list --json 2>/dev/null | jq -e --arg n "$DB_NAME" '.[] | select(.Name == $n)' >/dev/null; then
  echo "Creating Fly Postgres cluster ${DB_NAME}..."
  flyctl postgres create --name "$DB_NAME" --region "$REGION" --initial-cluster-size 1 --vm-size shared-cpu-1x --volume-size 1 --yes
fi
flyctl postgres attach "$DB_NAME" --app "$APP_GW" --yes || true

echo "==> Upstash Redis (create if missing)"
if ! flyctl redis list --json 2>/dev/null | jq -e --arg n "$REDIS_NAME" '.[] | select(.name == $n)' >/dev/null; then
  echo "Creating Upstash Redis ${REDIS_NAME}..."
  flyctl redis create --name "$REDIS_NAME" --region "$REGION" --no-replicas --enable-eviction
fi

REDIS_URL="$(flyctl redis status "$REDIS_NAME" --json 2>/dev/null | jq -r '.private_url // .PrivateURL // empty')"
if [ -z "$REDIS_URL" ]; then
  echo "Could not read Redis URL. Set manually:" >&2
  echo "  flyctl redis status $REDIS_NAME" >&2
  exit 1
fi

echo "==> Gateway secrets (demo mode — public tokens documented in /demo)"
flyctl secrets set \
  OPA_URL="http://${APP_OPA}.internal:8181" \
  REDIS_URL="$REDIS_URL" \
  --app "$APP_GW"

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
echo ""
echo "Verify:"
echo "  ./scripts/verify_fly_demo.sh $URL"
echo ""
echo "Public demo tokens (ASG_DEMO_MODE=true):"
echo "  Agent:    test-token"
echo "  Approver: approver-token"
echo ""
echo "Update README Live Demo link to: $URL"

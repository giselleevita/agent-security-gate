#!/usr/bin/env bash
# Deploy ASG reference demo to Fly.io (requires flyctl auth and provisioned secrets).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v fly >/dev/null 2>&1; then
  echo "Install flyctl: https://fly.io/docs/hands-on/install-flyctl/" >&2
  exit 1
fi

echo "Deploying OPA (if app exists)..."
fly deploy --config deploy/fly-opa.toml || echo "Skip OPA deploy — configure manually"

echo "Deploying gateway..."
fly deploy --config deploy/fly.toml

echo "Health check:"
fly status -a asg-demo
curl -sf "https://asg-demo.fly.dev/health" && echo " OK" || echo " Update README with your app URL"

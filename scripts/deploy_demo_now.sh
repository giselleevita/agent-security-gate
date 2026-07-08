#!/usr/bin/env bash
# Deploy public ASG demo to Fly.io (requires interactive login once).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! flyctl auth whoami >/dev/null 2>&1; then
  echo "==> Fly.io login required (opens browser)"
  flyctl auth login
fi

exec ./scripts/fly_demo_bootstrap.sh

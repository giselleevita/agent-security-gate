#!/usr/bin/env bash
# Deploy ASG reference demo to Fly.io (wrapper around fly_demo_bootstrap.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec "$ROOT/scripts/fly_demo_bootstrap.sh" "$@"

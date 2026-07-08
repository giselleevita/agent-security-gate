#!/usr/bin/env bash
# Quick visibility sprint status check (run from repo root).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

pass=0
warn=0
fail=0

ok() { echo "✓ $1"; pass=$((pass + 1)); }
warn() { echo "⚠ $1"; warn=$((warn + 1)); }
bad() { echo "✗ $1"; fail=$((fail + 1)); }

echo "=== Visibility Sprint Check ==="

[ -f docs/VISIBILITY_SPRINT.md ] && ok "VISIBILITY_SPRINT.md exists" || bad "missing VISIBILITY_SPRINT.md"
[ -f docs/assets/demo-terminal.svg ] && ok "demo visual asset exists" || bad "missing demo visual"
[ -f docs/benchmark-results/latest.md ] && ok "benchmark snapshot committed" || bad "missing benchmark snapshot"
[ -f deploy/fly.toml ] && ok "Fly config exists" || bad "missing fly.toml"
[ -f examples/langgraph_gated_agent.py ] && ok "LangGraph example exists" || bad "missing LangGraph example"
[ -f app/static/approvals.html ] && ok "approval UI exists" || bad "missing approval UI"

if command -v flyctl >/dev/null 2>&1; then
  if flyctl auth whoami >/dev/null 2>&1; then
    if flyctl apps list --json 2>/dev/null | jq -e '.[] | select(.Name == "asg-demo")' >/dev/null; then
      URL="https://asg-demo.fly.dev"
      if curl -sf "${URL}/health" >/dev/null 2>&1; then
        ok "Fly demo healthy at $URL"
      else
        warn "asg-demo app exists but /health not reachable"
      fi
    else
      warn "flyctl logged in but asg-demo app not found — run scripts/fly_demo_bootstrap.sh"
    fi
  else
    warn "flyctl not logged in — run: flyctl auth login"
  fi
else
  warn "flyctl not installed — brew install flyctl"
fi

if command -v gh >/dev/null 2>&1; then
  PINNED=$(gh api graphql -f query='{ viewer { pinnedItems(first: 10) { totalCount nodes { ... on Repository { name } } } } }' --jq '.data.viewer.pinnedItems' 2>/dev/null || echo '{}')
  COUNT=$(echo "$PINNED" | jq -r '.totalCount // 0')
  if [ "$COUNT" -ge 6 ]; then
    ok "GitHub profile has $COUNT pinned repos"
  else
    warn "Only $COUNT pinned repos (target: 6) — pin manually in GitHub UI"
  fi
else
  warn "gh CLI not available — cannot check pinned repos"
fi

echo ""
echo "Result: $pass passed, $warn warnings, $fail failed"
[ "$fail" -eq 0 ]

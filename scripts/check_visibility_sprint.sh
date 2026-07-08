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

echo "=== Visibility Sprint Check (free portfolio) ==="

[ -f docs/VISIBILITY_SPRINT.md ] && ok "VISIBILITY_SPRINT.md exists" || bad "missing VISIBILITY_SPRINT.md"
[ -f docs/RECRUITER_PACKET.md ] && ok "RECRUITER_PACKET.md exists" || bad "missing RECRUITER_PACKET.md"
[ -f docs/assets/asg-demo.gif ] && ok "README demo GIF exists" || bad "missing asg-demo.gif"
[ -f docs/assets/asg-demo.mp4 ] && ok "demo MP4 exists" || warn "missing asg-demo.mp4"
[ -f docs/benchmark-results/latest.md ] && ok "benchmark snapshot committed" || bad "missing benchmark snapshot"
[ -f examples/langgraph_gated_agent.py ] && ok "LangGraph example exists" || bad "missing LangGraph example"
[ -f app/routers/demo.py ] && ok "/demo endpoint exists" || bad "missing /demo router"
[ -f docs/blog/cross-posts/linkedin-demo.md ] && ok "LinkedIn draft ready" || bad "missing LinkedIn draft"
[ -f docs/blog/cross-posts/devto.md ] && ok "dev.to draft ready" || bad "missing dev.to draft"

if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
  ok "local gateway healthy (localhost:8000)"
  curl -sf http://localhost:8000/demo >/dev/null 2>&1 && ok "local /demo responds" || warn "/demo not reachable locally"
else
  warn "local stack not running — docker compose up -d --build"
fi

if command -v gh >/dev/null 2>&1; then
  PINNED=$(gh api graphql -f query='{ viewer { pinnedItems(first: 10) { totalCount nodes { ... on Repository { name } } } } }' --jq '.data.viewer.pinnedItems' 2>/dev/null || echo '{}')
  COUNT=$(echo "$PINNED" | jq -r '.totalCount // 0')
  if [ "$COUNT" -ge 5 ]; then
    ok "GitHub profile has $COUNT pinned repos (target: 5)"
    echo "$PINNED" | jq -r '.nodes[].name' 2>/dev/null | sed 's/^/    - /'
  else
    warn "Only $COUNT pinned repos (target: 5) — pin manually: docs/github-profile-setup.md"
  fi
else
  warn "gh CLI not available — cannot check pinned repos"
fi

echo ""
echo "Result: $pass passed, $warn warnings, $fail failed"
echo "Manual: pin 5 repos → post LinkedIn → apply with docs/RECRUITER_PACKET.md"
[ "$fail" -eq 0 ]

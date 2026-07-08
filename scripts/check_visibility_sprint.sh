#!/usr/bin/env bash
# Portfolio readiness check (run from repo root).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

pass=0
warn=0
fail=0

ok() { echo "✓ $1"; pass=$((pass + 1)); }
warn() { echo "⚠ $1"; warn=$((warn + 1)); }
bad() { echo "✗ $1"; fail=$((fail + 1)); }

echo "=== Portfolio Readiness Check ==="

README_LINES=$(wc -l < README.md | tr -d ' ')
if [ "$README_LINES" -le 250 ]; then
  ok "README is concise ($README_LINES lines, target ≤250)"
else
  warn "README is $README_LINES lines (target ≤250 for recruiter scan)"
fi

grep -q "does not include an LLM" README.md && ok "README states no in-tree LLM" || bad "README missing no-LLM scope callout"
grep -q "ASG_ENFORCE_MODE=strict" README.md && ok "README documents strict enforcement" || bad "README missing strict enforcement section"
grep -q "agent-security-gate-threat-model" README.md && ok "README links threat model above fold" || bad "README missing threat model link"

[ -f docs/assets/asg-demo.gif ] && ok "README demo GIF exists" || bad "missing asg-demo.gif"
[ -f docs/assets/asg-demo.mp4 ] && ok "demo MP4 exists" || warn "missing asg-demo.mp4"
[ -f docs/benchmark-results/latest.md ] && ok "benchmark snapshot committed" || bad "missing benchmark snapshot"
[ -f docs/agent-security-gate-threat-model.md ] && ok "threat model exists" || bad "missing threat model"
[ -f examples/gated_agent.py ] && ok "strict-mode example exists" || bad "missing examples/gated_agent.py"
[ -f examples/langgraph_gated_agent.py ] && ok "LangGraph example exists" || bad "missing LangGraph example"
[ -f app/routers/demo.py ] && ok "/demo endpoint exists" || bad "missing /demo router"
[ ! -f docs/investment-assessment.md ] && ok "startup diligence doc removed from tree" || bad "docs/investment-assessment.md still present"

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
    warn "Only $COUNT pinned repos (target: 5) — see docs/github-profile-setup.md"
  fi
else
  warn "gh CLI not available — cannot check pinned repos"
fi

echo ""
echo "Result: $pass passed, $warn warnings, $fail failed"
echo "Manual: pin repos → share docs/technical-brief.md → run strict-mode demo for reviewers"
[ "$fail" -eq 0 ]

import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print("top-level keys:", list(d))
for k in ("suite_name","user_task_id","injection_task_id","utility","security","error","injections"):
    if k in d: print(f"{k}: {json.dumps(d[k])[:600]}")
msgs = d.get("messages", [])
print("\nmessages:", len(msgs))
for i, m in enumerate(msgs):
    role = m.get("role")
    content = m.get("content")
    if isinstance(content, list):
        content = " ".join(c.get("content", "") if isinstance(c, dict) else str(c) for c in content)
    tcs = m.get("tool_calls") or []
    line = f"[{i}] {role}: {(content or '')[:300]!r}"
    for tc in tcs:
        line += f"\n      CALL {tc.get('function')} {json.dumps(tc.get('args'))[:300]}"
    if m.get("error"): line += f"\n      ERROR: {str(m['error'])[:300]}"
    print(line)

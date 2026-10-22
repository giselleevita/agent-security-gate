import json
import sys
import collections
d = json.load(open(sys.argv[1], encoding="utf-8"))
print("top-level type:", type(d).__name__)
if isinstance(d, dict):
    print("keys:", list(d)[:10])
    rows = d.get("pairs") or next((v for v in d.values() if isinstance(v, list)), [])
else:
    rows = d
print("rows:", len(rows))
print("sample row:", json.dumps(rows[0])[:400])
key = next(k for k in rows[0] if "categ" in k.lower())
c = collections.Counter(r[key] for r in rows)
for k, v in sorted(c.items()):
    print(f"  {k}: {v}")
print("cat2+cat3 =", sum(v for k, v in c.items() if str(k).startswith(("2_", "3_"))))

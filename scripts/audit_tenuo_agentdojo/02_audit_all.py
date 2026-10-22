import json, sys, tarfile, csv, collections
root, tarpath = sys.argv[1], sys.argv[2]
pairs = json.load(open(f"{root}/analysis/pairs_v1.2.2.json", encoding="utf-8"))
targets = json.load(open(f"{root}/policies/targets.json", encoding="utf-8"))
same = [p for p in pairs if p["category"].startswith(("2_", "3_"))]
key = lambda s, u, i: (s, u, i)
same_keys = {key(p["suite"], p["user_task"], p["injection_task"]) for p in same}

# ---- A. policy coverage: does the attack set any argument the policy guards?
print("== A. POLICY COVERAGE (89 same-tool pairs) ==")
guarded, unguarded = set(), set()
for p in same:
    k = key(p["suite"], p["user_task"], p["injection_task"])
    hit = False
    for tool, args in p["injection_writes"]:
        tg = set(targets[p["suite"]].get(tool, {}).get("targets", []))
        if tg & set(args):
            hit = True
    (guarded if hit else unguarded).add(k)
print(f"pairs whose attack sets a guarded (target) argument: {len(guarded)}")
print(f"pairs whose attack sets NO guarded argument:         {len(unguarded)}")
no_write = [p for p in same if not p["injection_writes"]]
print(f"pairs with no recorded injection write: {len(no_write)}")
by = collections.Counter((p['suite'], t) for p in same if key(p['suite'],p['user_task'],p['injection_task']) in unguarded for t,_ in p['injection_writes'])
print("unguarded by (suite, tool):", dict(by))

# ---- B. independent recount from the raw per-episode JSON inside the tarball
print("\n== B. RECOUNT FROM RAW EPISODE LOGS (not the CSV) ==")
res = collections.defaultdict(dict)   # arm -> key -> (utility, security)
with tarfile.open(tarpath, "r:gz") as tf:
    for m in tf:
        n = m.name
        if not (m.isfile() and n.endswith(".json")) or "/._" in n or "important_instructions" not in n:
            continue
        parts = n.split("/")
        # dev/<model>/v1.2.2/<arm>/<pipeline>/<suite>/<user_task>/important_instructions/<inj>.json
        arm, suite, ut, inj = parts[3], parts[5], parts[6], parts[-1][:-5]
        k = key(suite, ut, inj)
        if k not in same_keys:
            continue
        d = json.load(tf.extractfile(m))
        res[arm][k] = (d["utility"], d["security"])
for arm in sorted(res):
    r = res[arm]
    print(f"{arm:20} n={len(r):3} attack={sum(s for _,s in r.values()):3} utility={sum(u for u,_ in r.values()):3}")

# ---- cross-check against the CSV
csvp = f"{root}/results/summary/dev/gpt-4o-mini-2024-07-18/v1.2.2/episodes.csv"
rows = list(csv.DictReader(open(csvp, encoding="utf-8")))
bad = 0
for r in rows:
    k = key(r["suite"], r["user_task"], r["injection_task"])
    if k in same_keys and r["arm"] in res and k in res[r["arm"]]:
        u, s = res[r["arm"]][k]
        if (r["utility"] == "True") != u or (r["attack_success"] == "True") != s:
            bad += 1
print(f"CSV rows disagreeing with raw logs: {bad}")

# ---- C. executed malicious call but scorer says no attack
print("\n== C. TRACE SAYS EXECUTED, SCORER SAYS NO ATTACK (89 pairs) ==")
for arm in sorted({r['arm'] for r in rows}):
    rr = [r for r in rows if r["arm"] == arm and key(r["suite"], r["user_task"], r["injection_task"]) in same_keys
          and int(r["malicious_executed"] or 0) > 0 and r["attack_success"] != "True"]
    g = sum(key(r["suite"], r["user_task"], r["injection_task"]) in guarded for r in rr)
    print(f"{arm:20} {len(rr):2} rows  (guarded-arg attacks: {g}, unguarded: {len(rr)-g})")
    if arm in ("tenuo", "tenuo_tool_filter", "baseline"):
        for r in rr: print("     ", r["suite"], r["user_task"], r["injection_task"])
# and attack successes split by guarded/unguarded for the tenuo-family arms
print("\n== D. ATTACK SUCCESSES BY POLICY COVERAGE ==")
for arm in sorted(res):
    g = sum(res[arm][k][1] for k in guarded if k in res[arm]); u = sum(res[arm][k][1] for k in unguarded if k in res[arm])
    print(f"{arm:20} guarded-pairs attacks={g:2}/{len(guarded)}  unguarded-pairs attacks={u:2}/{len(unguarded)}")

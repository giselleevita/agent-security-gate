import csv
import json
import sys
import tarfile

root, tarpath = sys.argv[1], sys.argv[2]
pairs = json.load(open(f"{root}/analysis/pairs_v1.2.2.json", encoding="utf-8"))
same = {(p["suite"], p["user_task"], p["injection_task"]): p for p in pairs if p["category"].startswith(("2_", "3_"))}
rows = list(csv.DictReader(open(f"{root}/results/summary/dev/gpt-4o-mini-2024-07-18/v1.2.2/episodes.csv", encoding="utf-8")))
want = {(r["arm"], r["suite"], r["user_task"], r["injection_task"]) for r in rows
        if (r["suite"], r["user_task"], r["injection_task"]) in same and int(r["malicious_executed"] or 0) > 0 and r["attack_success"] != "True"}
print("rows to inspect:", len(want))


def gt_strings(p):
    out = set()
    for _, args in p["injection_writes"]:
        for v in args.values():
            s = str(v).strip()
            if len(s) >= 4:
                out.add(s)
    return out


with tarfile.open(tarpath, "r:gz") as tf:
    for m in tf:
        n = m.name
        is_attack_episode = m.isfile() and n.endswith(".json") and "/._" not in n and "important_instructions" in n
        if not is_attack_episode:
            continue
        p = n.split("/")
        k = (p[3], p[5], p[6], p[-1][:-5])
        if k not in want:
            continue
        d = json.load(tf.extractfile(m))
        pr = same[k[1:]]
        tools = {t for t, _ in pr["injection_writes"]}
        gts = gt_strings(pr)
        results = {mm.get("tool_call_id"): mm for mm in d["messages"] if mm["role"] == "tool"}
        print(f"\n[{k[0]}] {k[1]} {k[2]} {k[3]}  scorer_security={d['security']}")
        for mm in d["messages"]:
            for c in (mm.get("tool_calls") or []) if mm["role"] == "assistant" else []:
                if c["function"] not in tools:
                    continue
                text = json.dumps(c["args"], default=str)
                hits = sorted(s for s in gts if s in text)
                err = (results.get(c.get("id")) or {}).get("error")
                print(f"    {c['function']} {text[:150]}")
                print(f"       attack-strings present: {hits}  | tool error: {str(err)[:50] if err else None}")

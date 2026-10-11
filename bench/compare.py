"""Compares two matrix.py runs on the same pages: pass counts, failures, field differences, cost.

Usage: python3 compare.py bench-curl.jsonl bench-camoufox.jsonl
"""
import json
import statistics as st
import sys


def load(path):
    return {(r["kind"], r["slug"]): r for r in map(json.loads, open(path))}


def ok(r):
    if r is None:
        return False
    return r["status"] == "OK" and ((r.get("count") or 0) > 0 if r["kind"] == "trend" else True)


base, cand = load(sys.argv[1]), load(sys.argv[2])
for kind in ("trend", "content"):
    keys = [k for k in base if k[0] == kind]
    print(f"{kind}: baseline {sum(ok(base[k]) for k in keys)}/{len(keys)}, "
          f"candidate {sum(ok(cand.get(k)) for k in keys)}/{len(keys)}")
    for k in keys:
        if not ok(cand.get(k)):
            r = cand.get(k) or {}
            print(f"   FAIL {k[1]}: {(r.get('error') or r.get('status') or 'missing')[:110]}")

print("content fields that differ on the same URL:")
for k in [k for k in base if k[0] == "content"]:
    a, b = base[k], cand.get(k)
    if ok(a) and ok(b):
        diff = {f: (a.get(f), b.get(f)) for f in ("author", "image", "published", "words") if a.get(f) != b.get(f)}
        if diff:
            print(f"   {k[1]}: {diff}")

for kind in ("trend", "content"):
    kb_a = [r["kb"] for k, r in base.items() if k[0] == kind]
    kb_b = [r["kb"] for k, r in cand.items() if k[0] == kind]
    s_a = [r["secs"] for k, r in base.items() if k[0] == kind]
    s_b = [r["secs"] for k, r in cand.items() if k[0] == kind]
    print(f"{kind}: proxy KB median {st.median(kb_a)} vs {st.median(kb_b)}; "
          f"seconds median {st.median(s_a)} vs {st.median(s_b)} (max {max(s_b)})")

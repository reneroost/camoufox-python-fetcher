"""Trend + content diagnostics for every source prod fetches with curl_cffi, against a local
news-scraper dev app on :8090. See bench/README.md for the whole procedure.

Usage: python3 matrix.py <label> <slugs.txt> [urls.json]
  Without urls.json: content runs on the first trend candidate (or the source's latest article in
  the dev database), and the URLs used are written to bench-urls.json.
  With urls.json: content runs on exactly those URLs, so two runs compare the same pages.
Proxy bytes per fetch come from relay.py's counter in /tmp/relay-bytes.txt.
Writes one JSON line per fetch to bench-<label>.jsonl.
"""
import json
import sys
import time
import urllib.parse
import urllib.request

APP = "http://127.0.0.1:8090"

# Sources whose prod trend or content route is NOT curl_cffi (Bright Data, Jsoup, ScrapingAnt as of
# 2026-10-11 — see news-scraper's ARCHITECTURE.md, "Fetcher Routing: Why Each Route"). They are
# never called here, so a run spends no vendor credit. Update when a route moves.
NO_TREND = {"politico-us", "sky-news", "the-hill", "wall-street-journal", "cbc",
            "south-china-morning-post", "ars-technica"}
NO_CONTENT = {"sky-news"}

label, slugs_file = sys.argv[1], sys.argv[2]
fixed_urls = json.load(open(sys.argv[3])) if len(sys.argv) > 3 else None
slugs = [s.strip() for s in open(slugs_file) if s.strip()]
out = open(f"bench-{label}.jsonl", "w")
urls_used = {}


def relay_bytes():
    up, down = map(int, open("/tmp/relay-bytes.txt").read().split())
    return up + down


def get(path):
    b0, t0 = relay_bytes(), time.time()
    try:
        with urllib.request.urlopen(APP + path, timeout=300) as r:
            body = json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = {"status": f"HTTP {e.code}", "errorMessage": e.read()[:300].decode(errors="replace")}
    except Exception as e:
        body = {"status": "CLIENT_ERROR", "errorMessage": repr(e)[:300]}
    time.sleep(0.5)  # let the relay counter settle
    return body, round(time.time() - t0, 1), relay_bytes() - b0


for slug in slugs:
    candidates = []
    if slug not in NO_TREND:
        body, secs, nbytes = get(f"/trend/test/{slug}")
        candidates = body.get("candidates") or []
        rec = {"kind": "trend", "slug": slug, "status": body.get("status"), "count": body.get("extractedCount"),
               "fetcher": body.get("fetcherName"), "secs": secs, "kb": nbytes // 1024,
               "error": (body.get("errorMessage") or "")[:200]}
        out.write(json.dumps(rec) + "\n"); out.flush()
        print(f"T {slug:26} {rec['status']!s:8} n={rec['count']!s:>3} {secs:5.1f}s {rec['kb']:6} KB {rec['error'][:80]}", flush=True)
    if slug in NO_CONTENT:
        continue
    url = (fixed_urls or {}).get(slug) or (candidates[0]["url"] if candidates else None)
    path = f"/content/test/{slug}/by-url?url={urllib.parse.quote(url, safe='')}" if url else f"/content/test/{slug}"
    body, secs, nbytes = get(path)
    urls_used[slug] = url or body.get("targetUrl")
    c = body.get("extractedContent") or {}
    rec = {"kind": "content", "slug": slug, "status": body.get("status"), "fetcher": body.get("fetcherName"),
           "url": urls_used[slug], "title": (body.get("extractedTitle") or "")[:80], "author": c.get("author"),
           "image": bool(c.get("originalImageUrl")), "published": c.get("publishedAt"), "words": c.get("wordCount"),
           "body": body.get("bodyLength"), "secs": secs, "kb": nbytes // 1024,
           "error": (body.get("errorMessage") or "")[:200]}
    out.write(json.dumps(rec) + "\n"); out.flush()
    print(f"C {slug:26} {rec['status']!s:8} body={rec['body']!s:>6} words={rec['words']!s:>5} {secs:5.1f}s {rec['kb']:6} KB {rec['error'][:80]}", flush=True)

if not fixed_urls:
    json.dump(urls_used, open("bench-urls.json", "w"), indent=1)

# Fallback benchmark

Proves, before an upgrade is deployed or a launch is needed, that this sidecar can stand in for
curl_cffi: every source prod fetches with curl_cffi is run through news-scraper's own strategies
twice on the same pages — once on curl_cffi (the control), once on camoufox — and compared.
Last run 2026-10-11: trend 43/43 both; content 49/49 vs 46/49 (DataDome on nytimes.com ×2 and
wsj.com).

Run it on the laptop. It spends no vendor credit (sources routed to Bright Data, Jsoup or
ScrapingAnt are skipped — keep `NO_TREND`/`NO_CONTENT` in `matrix.py` in step with prod), and
~100 MB of DataImpulse traffic for the camoufox half.

1. **Relay** — counts proxy bytes so each fetch's traffic is measured:
   `python3 bench/relay.py &` (listens on 127.0.0.1:8823, forwards to gw.dataimpulse.com:823).
2. **Sidecars** — curl_cffi on :8082 (`light-python-fetcher`) and this one on :8085
   (`.venv/bin/python3 main.py`).
3. **Slugs** — one per line, from the dev database:
   `psql … -At -c "select slug from sources order by 1" > /tmp/slugs.txt`
4. **Route files** — every key prod routes to curl_cffi, pointed at each transport. From the
   news-scraper checkout:
   ```bash
   python3 - <<'EOF'
   import json, yaml
   r = yaml.safe_load(open('src/main/resources/application.yaml'))['fetcher-routing']['routes']
   r.update((yaml.safe_load(open('src/main/resources/application-prod.yaml')).get('fetcher-routing') or {}).get('routes') or {})
   keys = [k for k, v in r.items() if v == 'CURL_CFFI_SIDECAR']
   for t, f in (('CURL_CFFI_SIDECAR', 'curl'), ('CAMOUFOX_SIDECAR', 'camoufox')):
       json.dump({'fetcher-routing': {'routes': {k: t for k in keys}}}, open(f'/tmp/routes-{f}.json', 'w'))
   EOF
   ```
5. **Control** — the dev app on curl_cffi, through the relay, then the matrix:
   ```bash
   SPRING_APPLICATION_JSON="$(cat /tmp/routes-curl.json)" java -jar target/news-scraper.jar \
     --spring.profiles.active=dev --server.port=8090 --scraper.proxy.host=127.0.0.1 --scraper.proxy.port=8823
   python3 bench/matrix.py curl /tmp/slugs.txt
   ```
   Sources whose trend route is not curl_cffi have no candidate URL and fall back to their
   latest article in the dev database; if it has none, add a URL to `bench-urls.json` by hand.
6. **Camoufox** — restart the app with `/tmp/routes-camoufox.json`, then
   `python3 bench/matrix.py camoufox /tmp/slugs.txt bench-urls.json`.
7. **Compare** — `python3 bench/compare.py bench-curl.jsonl bench-camoufox.jsonl`.

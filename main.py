"""
camoufox sidecar — FastAPI service for patched-Firefox browser fetching.

VERSION: 2.0.0

WHY THIS EXISTS
---------------
camoufox is a patched Firefox build designed for web scraping evasion. It is
news-scraper's Firefox engine beside the nodriver (Chrome over CDP) sidecar:

  - Gecko rendering engine: WebGL renderer, canvas fingerprint, and font metrics
    differ structurally from Chrome's Blink stack, bypassing Chrome-targeted
    detection heuristics.
  - Playwright drives it over Firefox's Juggler protocol, which does not share
    Chrome's Runtime.enable CDP telltale.
  - Fingerprints are applied inside the binary, not by patched JS getters, and
    window.webdriver is patched out at the binary level.

VERSIONS
--------
pythonlib camoufox 0.5.8 + Playwright 1.62, browser v156.0.1-beta.36 (Firefox
156). The browser is a separate ~1.2 GB download. Install it pinned, so a new
stable release cannot change the browser under a running deployment:

  .venv/bin/python -m camoufox set official/stable/156.0.1-beta.36
  .venv/bin/python -m camoufox fetch

The Firefox 135 build this sidecar ran before was blocked almost everywhere:
on 2026-10-11, 6 of 35 single-attempt fetches of hard news sources passed,
against 25 of 35 on this version with the challenge wait below.

ARCHITECTURE
------------
- One shared Firefox process, launched at startup and relaunched by the next
  fetch if it dies (see _ensure_browser).
- asyncio.Semaphore(MAX_CONCURRENT_FETCHES) limits concurrency.
- Per request: a new context with its own fingerprint identity (AsyncNewContext)
  → navigate → wait out a Cloudflare interstitial if one appears → dwell or
  selector wait → extract → close. No cookies or storage shared between fetches.
- Java sends the proxy URL, locale, referrer hint and timing. The sidecar owns
  browser lifecycle, identity, route interception, navigation and extraction.

IDENTITY PER CONTEXT
--------------------
Every fetch gets a fresh identity — UA, screen, WebGL, fonts, voices, audio
noise — drawn by camoufox's fingerprint generator, so fetches from many exit
IPs do not all present one device. With a proxy, the context's timezone and
WebRTC IP come from the proxy's actual exit IP (camoufox looks it up through
the proxy at ip-api.com). The exit country is random in production, so the
timezone_id Java sends would contradict the IP; it is used only without a
proxy. Accept-Language is left to Firefox, which derives it from the locale
and keeps it identical to navigator.languages. If the exit lookup fails, the
fetch fails and Java retries it on a fresh exit, rather than sending the
host's timezone from behind a foreign IP.

CAMOUFOX_OS pins the OS of the drawn identities ("windows" | "macos" | "linux");
unset, each context draws its own.

HEADLESS / HEADED MODE
-----------------------
Configure via CAMOUFOX_HEADLESS:
  CAMOUFOX_HEADLESS=1       → headless (default)
  CAMOUFOX_HEADLESS=virtual → a headed Firefox on a private Xvfb display that
                              camoufox manages (needs Xvfb installed); set
                              CAMOUFOX_VIRTUAL_DISPLAY_SIZE=1920x1080x24, as the
                              default display is 1x1
  CAMOUFOX_HEADLESS=0       → headed on the host display
On 2026-10-11 the virtual display passed the same share of fetches as headless
(15 of 35 each, before the challenge wait), so headless stays the default.

MEMORY
------
Firefox plus the sidecar measured ~1.2 GB PSS (median), 1.46 GB peak, over
35 fetches. Size the unit's MemoryMax above that: when the cgroup kills
Firefox, the sidecar relaunches it, but every fetch in between fails.

ENDPOINTS
---------
  POST /api/v1/fetch            — fetch a URL with region and proxy context
  GET  /api/v1/browser-version  — {"version": "156.0.1-beta.36", "major": "156"}
  GET  /health                  — liveness probe
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
from contextlib import asynccontextmanager
from enum import Enum
from urllib.parse import urlparse

import uvicorn
from camoufox.async_api import AsyncCamoufox, AsyncNewContext
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_CONCURRENT_FETCHES  = 1
DEFAULT_TIMEOUT_SECONDS = 30

# Cloudflare's managed challenge answers the first navigation with HTTP 403 (or
# 503) and an interstitial that a real browser solves on its own, then reloads
# into the page. Returning at that point throws away the one thing a browser has
# over curl_cffi, so the fetch waits for it to clear. The marker is the inline
# `window._cf_chl_opt = {...}` every challenge page carries; the title is not
# one ("Security Verification" at first paint, "Just a moment..." once its
# script runs), and pages that merely load Cloudflare's background scripts
# (cdn-cgi/challenge-platform/scripts/...) do not define it.
# Bounded well inside the 30 s request budget Java gives this sidecar.
CHALLENGE_STATUSES  = frozenset({403, 503})
CHALLENGE_MARKER    = "_cf_chl_opt"
CHALLENGE_WAIT_MS   = 15_000
CHALLENGE_POLL_MS   = 500

# Aborting these is safe: no anti-bot sensor is delivered as an image or font.
BLOCKED_RESOURCE_TYPES: frozenset[str] = frozenset({"image", "media", "font"})

# "analytics" intentionally absent — vendor sensor scripts may include it.
AD_AND_TRACKING_KEYWORDS: frozenset[str] = frozenset({
    "google-analytics",
    "doubleclick",
    "scorecardresearch",
    "taboola",
    "outbrain",
    "adnxs",
    "facebook.net",
    "adsystem",
})

# Vendor sensor / challenge scripts that must ALWAYS be allowed through.
# Aborting these is itself a detectable signal — the vendor's collector sees
# "client blocked our script" as a high-confidence automation tell.
SENSOR_PASSTHROUGH_PATTERNS: frozenset[str] = frozenset({
    # DataDome
    "datadome.co",
    "geo.captcha-delivery.com",
    "js.datadome.co",
    # Cloudflare managed challenge / Turnstile
    "challenges.cloudflare.com",
    # PerimeterX / HUMAN Security
    "perimeterx.net",
    "humansecurity.com",
    "px.js",
    # Kasada
    "kasada.io",
    # Akamai Bot Manager
    "akstat.io",
    # Imperva / Incapsula
    "incapsula.com",
})

# ── ReferrerHint ──────────────────────────────────────────────────────────────


class ReferrerHint(str, Enum):
    """
    Mirror of the Java ReferrerHint enum.
    Values must stay in sync with ReferrerHint.sidecarValue() in Java.
    """
    GOOGLE_SEARCH = "google_search"
    GOOGLE_NEWS   = "google_news"
    TWITTER       = "twitter"
    DIRECT        = "direct"


_REFERRER_URL: dict[ReferrerHint, str] = {
    ReferrerHint.GOOGLE_SEARCH: "https://www.google.com/",
    ReferrerHint.GOOGLE_NEWS:   "https://news.google.com/",
    ReferrerHint.TWITTER:       "https://t.co/",
    ReferrerHint.DIRECT:        "",
}

# ── DTOs ──────────────────────────────────────────────────────────────────────


class CamouFoxFetchRequest(BaseModel):
    """
    Wire-format request: news-scraper's NativeBrowserFetchRequest, sent by
    BrowserSidecarFetcher.

    Java sends only region and navigation context. camoufox draws UA, screen,
    OS, canvas/WebGL and fonts per context — those fields are absent by design.

    timezone_id is used only when there is no proxy_url (see IDENTITY PER
    CONTEXT); accept_language is accepted and ignored, as Firefox derives the
    header from locale_tag.
    """
    url:                 str
    proxy_url:           str | None = Field(default=None)
    locale_tag:          str        = Field(default="en-US")
    timezone_id:         str        = Field(default="America/New_York")
    accept_language:     str        = Field(default="en-US,en;q=0.9")
    referrer_hint:       str        = Field(default="direct")
    default_wait_millis: int        = Field(default=1500, ge=0)
    timeout_seconds:     int        = Field(default=DEFAULT_TIMEOUT_SECONDS, ge=1, le=120)
    wait_for_selector:   str | None = Field(default=None)


class CamouFoxFetchResponse(BaseModel):
    html:        str | None = None
    final_url:   str | None = None
    status_code: int

# ── Application state ─────────────────────────────────────────────────────────

# Holds the live browser instance across requests.
# AsyncCamoufox context manager ownership lives in lifespan(); do not close
# the browser outside of the lifespan teardown.
_state: dict[str, object]            = {}
_fetch_semaphore: asyncio.Semaphore | None = None

# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Manages the singleton Firefox process for the lifetime of the sidecar."""
    global _fetch_semaphore
    _fetch_semaphore = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

    # ── OS fingerprint ────────────────────────────────────────────────────────
    #
    # camoufox selects OS fingerprint at LAUNCH time. The OS choice governs UA,
    # font set, screen resolution, and several navigator.* properties as an
    # internally consistent bundle. Changing it per-request is not possible
    # without relaunching the browser.
    #
    # CAMOUFOX_OS options: "windows" | "macos" | "linux" | "" (random each start)
    # Default: not set → camoufox picks randomly on each process start.
    # Production recommendation: CAMOUFOX_OS=windows (highest market share).
    raw_os = os.environ.get("CAMOUFOX_OS", "").strip()
    os_arg: str | None = raw_os if raw_os in {"windows", "macos", "linux"} else None
    if os_arg:
        log.info("camoufox OS fingerprint pinned to: %s", os_arg)
    else:
        log.info("CAMOUFOX_OS not set — camoufox will pick OS fingerprint randomly.")

    # ── Headless mode ─────────────────────────────────────────────────────────
    #
    # CAMOUFOX_HEADLESS=1        → headless=True   (default)
    # CAMOUFOX_HEADLESS=virtual  → headless="virtual" (camoufox-managed Xvfb)
    # CAMOUFOX_HEADLESS=0        → headless=False  (requires host Xvfb)
    raw_headless = os.environ.get("CAMOUFOX_HEADLESS", "1").strip()
    if raw_headless == "0":
        headless: bool | str = False
    elif raw_headless == "virtual":
        headless = "virtual"
    else:
        headless = True

    # ── Launch kwargs ─────────────────────────────────────────────────────────
    launch_kwargs: dict = {"headless": headless}
    if os_arg:
        launch_kwargs["os"] = os_arg

    # --no-sandbox is required when the process runs as root (uid 0).
    # Running as root in production should be avoided; the service file should
    # specify a non-root user. Kept as a guard for container environments.
    if os.getuid() == 0:
        launch_kwargs["args"] = ["--no-sandbox"]
        log.warning(
            "Running as root — passing --no-sandbox to Firefox. "
            "This is a mild automation signal. Prefer a non-root user "
            "in the service file."
        )

    _state["launch_kwargs"] = launch_kwargs
    _state["os"] = os_arg
    await _launch_browser()
    try:
        yield
    finally:
        await _close_browser()
        log.info("camoufox sidecar shutdown complete.")
        _state.clear()


async def _launch_browser() -> None:
    launcher = AsyncCamoufox(**_state["launch_kwargs"])
    browser  = await launcher.__aenter__()
    _state["launcher"] = launcher
    _state["browser"]  = browser
    log.info(
        "camoufox / Firefox launched. Version: %s | headless=%s | os=%s",
        getattr(browser, "version", "unknown"),
        _state["launch_kwargs"]["headless"],
        _state["os"] or "random",
    )


async def _close_browser() -> None:
    launcher = _state.pop("launcher", None)
    _state.pop("browser", None)
    if launcher is not None:
        try:
            await launcher.__aexit__(None, None, None)
        except Exception as exc:
            log.warning("Error while closing the browser: %s", exc)


async def _ensure_browser():
    """
    The live browser, relaunched first if the previous one has gone.

    Firefox can die under the sidecar (a crash, or the unit's MemoryMax killing
    it) while this process stays up. Without this, every later fetch answered
    503 and /health "degraded" until someone restarted the service by hand.
    Called under the fetch semaphore, so a relaunch never races a fetch.
    """
    browser = _state.get("browser")
    if browser is not None and browser.is_connected():
        return browser
    log.error("Browser is not connected — relaunching it.")
    await _close_browser()
    await _launch_browser()
    return _state["browser"]


app = FastAPI(title="camoufox-sidecar", version="2.0.0", lifespan=lifespan)

# ── Route interception ────────────────────────────────────────────────────────


async def _handle_route(route) -> None:
    """
    Per-request resource filter.

    Priority order:
      1. Sensor / challenge domains ALWAYS pass through.
         Aborting them is a high-confidence automation tell.
      2. Heavy resource types (image, media, font) are aborted — bandwidth
         and page-load time reduced; no anti-bot sensor uses these types.
      3. Known ad/tracking network hostnames trigger abort.
      4. Everything else continues unmodified.
    """
    request_url   = route.request.url.lower()
    resource_type = route.request.resource_type

    for pattern in SENSOR_PASSTHROUGH_PATTERNS:
        if pattern in request_url:
            await route.continue_()
            return

    if resource_type in BLOCKED_RESOURCE_TYPES:
        await route.abort()
        return

    for keyword in AD_AND_TRACKING_KEYWORDS:
        if keyword in request_url:
            await route.abort()
            return

    await route.continue_()

# ── Core fetch logic ──────────────────────────────────────────────────────────


async def _dwell(page, base_wait_ms: int) -> None:
    """
    Scripted dwell with randomised timing and a single natural scroll.

    Jitter budget of ±33%, and the phase split between pre/post scroll is
    randomised independently, so the timing histogram does not cluster into a
    recognisable machine pattern.
    """
    try:
        jitter      = random.randint(0, base_wait_ms // 3)
        total_wait  = base_wait_ms + jitter
        split_ratio = random.uniform(0.45, 0.65)
        pre_scroll  = int(total_wait * split_ratio)
        post_scroll = total_wait - pre_scroll

        await page.wait_for_timeout(pre_scroll)

        scroll_px = random.randint(100, 350)
        await page.evaluate(f"() => window.scrollBy(0, {scroll_px})")

        await page.wait_for_timeout(post_scroll)
    except Exception as exc:
        log.debug("Dwell interrupted — proceeding with content extraction: %s", exc)


async def _is_cloudflare_interstitial(page) -> bool:
    try:
        return CHALLENGE_MARKER in await page.content()
    except Exception:
        return False


def _remaining_ms(deadline: float) -> int:
    return int((deadline - asyncio.get_running_loop().time()) * 1000)


async def _await_challenge(page, url: str, first_status: int,
                           last_document_status: dict[str, int], deadline: float) -> int:
    """
    Waits for a Cloudflare interstitial to clear and returns the status of the
    page it cleared into: the challenge script reloads the main frame, and the
    response listener records that document's status. If it never clears, returns
    the original status, so Java treats the fetch as blocked and retries it on a
    fresh exit. Never waits past the request's deadline.
    """
    budget_ms = min(CHALLENGE_WAIT_MS, _remaining_ms(deadline) - 1_000)
    log.info("Cloudflare interstitial on %s — waiting up to %d ms for it to clear", url, max(budget_ms, 0))
    for _ in range(max(budget_ms, 0) // CHALLENGE_POLL_MS):
        await page.wait_for_timeout(CHALLENGE_POLL_MS)
        status = last_document_status.get("status", first_status)
        if status < 400:
            try:
                await page.wait_for_load_state(
                    "domcontentloaded", timeout=max(_remaining_ms(deadline), 1_000))
            except Exception:
                pass
            log.info("Cloudflare interstitial cleared for %s  status=%d", url, status)
            return status
    log.info("Cloudflare interstitial did not clear for %s", url)
    return first_status


def _resolve_referrer_hint(raw: str) -> ReferrerHint:
    try:
        return ReferrerHint(raw)
    except ValueError:
        log.warning("Unknown referrer_hint %r — defaulting to DIRECT.", raw)
        return ReferrerHint.DIRECT


def _build_proxy_config(proxy_url: str) -> dict:
    """
    Converts a DataImpulse-format proxy URL to the dict camoufox/playwright expects.

    Python's urlparse percent-decodes username and password automatically, so
    the URL-encoded credentials produced by Java's ProxySessionManager arrive
    here as plain strings — the correct format for playwright's proxy config.
    """
    parsed = urlparse(proxy_url)
    config: dict = {
        "server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}",
    }
    if parsed.username:
        config["username"] = parsed.username
    if parsed.password:
        config["password"] = parsed.password
    return config


async def _execute_fetch(browser, req: CamouFoxFetchRequest) -> CamouFoxFetchResponse:
    """
    Core per-request fetch logic.

    Each request gets a new context with its own drawn identity, so cookies,
    storage and fingerprint are never shared between fetches. This function
    sets the per-request variables:
      - locale (navigator.language and Accept-Language)
      - proxy (per-session DataImpulse sticky credentials), from whose exit IP
        camoufox derives the timezone and WebRTC IP
      - referrer (per-attempt navigation origin variation)
    """
    # One deadline for the whole fetch. Java reads for timeout_seconds plus five
    # seconds of grace, and a read timeout there counts as the sidecar being
    # down — so the exit lookup, navigation and challenge wait all spend from
    # the same budget rather than each taking its own.
    deadline     = asyncio.get_running_loop().time() + req.timeout_seconds
    hint         = _resolve_referrer_hint(req.referrer_hint)
    referrer_url = _REFERRER_URL[hint]

    context_kwargs: dict = {"locale": req.locale_tag}
    if req.proxy_url:
        context_kwargs["proxy"] = _build_proxy_config(req.proxy_url)
    else:
        context_kwargs["timezone_id"] = req.timezone_id

    context = await AsyncNewContext(browser, os=_state.get("os"), **context_kwargs)
    try:
        page = await context.new_page()
        try:
            await page.route("**/*", _handle_route)

            nav_kwargs: dict = {
                "wait_until": "domcontentloaded",
                "timeout":    max(_remaining_ms(deadline), 1_000),
            }
            # Passing referer to goto() sets the Referer header on the initial
            # navigation request and causes Firefox to derive Sec-Fetch-Site
            # natively and correctly ("cross-site" for any external referrer;
            # "none" for direct). Applied only to the initial navigation, not
            # sub-resource requests.
            if referrer_url:
                nav_kwargs["referer"] = referrer_url

            # Status of the latest main-frame document: after a solved challenge
            # that is the page Cloudflare reloaded into, not the 403 that goto saw.
            last_document_status: dict[str, int] = {}

            def _track_document(resp) -> None:
                if resp.frame == page.main_frame and resp.request.is_navigation_request():
                    last_document_status["status"] = resp.status

            page.on("response", _track_document)

            response = await page.goto(req.url, **nav_kwargs)

            if response is None:
                log.error("Navigation returned None for %s", req.url)
                return CamouFoxFetchResponse(html=None, final_url=None, status_code=0)

            status_code = response.status
            if status_code in CHALLENGE_STATUSES and await _is_cloudflare_interstitial(page):
                status_code = await _await_challenge(
                    page, req.url, status_code, last_document_status, deadline)
            final_url   = page.url

            log.info("navigation complete  status=%d  url=%s", status_code, req.url)

            # Selector wait takes priority over dwell when specified by the
            # extraction strategy (per-site config in Java). Selector wait
            # is more precise for sites whose dynamic content loads into a
            # known element; dwell is the fallback for generic scraping.
            if req.wait_for_selector:
                try:
                    await page.wait_for_selector(
                        req.wait_for_selector, timeout=min(5_000, max(_remaining_ms(deadline), 1_000)))
                except Exception:
                    log.debug(
                        "wait_for_selector '%s' timed out for %s — proceeding with content",
                        req.wait_for_selector,
                        req.url,
                    )
            elif req.default_wait_millis > 0:
                await _dwell(page, req.default_wait_millis)

            content = await page.content()
            if not content or not content.strip():
                log.error("page.content() returned empty DOM for %s", req.url)
                return CamouFoxFetchResponse(html=None, final_url=final_url, status_code=status_code)

            return CamouFoxFetchResponse(html=content, final_url=final_url, status_code=status_code)

        finally:
            await page.close()
    finally:
        await context.close()

# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.post("/api/v1/fetch", response_model=CamouFoxFetchResponse)
async def execute_fetch(req: CamouFoxFetchRequest) -> CamouFoxFetchResponse:
    """
    Fetches a URL using a camoufox Firefox context with the given region context.

    The asyncio semaphore limits execution to MAX_CONCURRENT_FETCHES (1), which
    mirrors the Java BrowserSidecarFetcher's Semaphore(1) in beforeFetch /
    afterFetch. A second request blocks here until the slot is free; the Java-side
    read timeout (sidecar timeout + 5 s grace) is the ultimate backstop.

    Returns status_code=502 in the body (not an HTTP 502) for execution failures
    so that the Java retry / circuit-breaker path fires. Raising an HTTP exception
    here would bypass the Java retry engine entirely.
    """
    async with _fetch_semaphore:
        try:
            browser = await _ensure_browser()
        except Exception as exc:
            log.exception("Could not relaunch the browser: %s", exc)
            raise HTTPException(status_code=503, detail="Browser not available") from exc
        try:
            return await _execute_fetch(browser, req)
        except Exception as exc:
            log.exception("camoufox fetch failed for %s: %s", req.url, exc)
            return CamouFoxFetchResponse(html=None, final_url=None, status_code=502)


@app.get("/api/v1/browser-version")
async def get_browser_version() -> dict[str, str]:
    """
    Returns the version of the running Firefox binary.

    Called at Java startup by BrowserSidecarValidator to log the Firefox version
    for diagnostics; nothing on the Java side depends on it.
    """
    browser = _state.get("browser")
    if browser is None:
        raise HTTPException(status_code=503, detail="Browser not available")
    version: str = getattr(browser, "version", "unknown")
    major:   str = version.split(".")[0] if "." in version else version
    return {"version": version, "major": major}


@app.get("/health")
async def health() -> dict[str, object]:
    """
    Liveness probe for systemd and upstream load balancers.

    Returns {"status": "ok"} when the browser process is connected and ready
    to accept fetch requests. Returns {"status": "degraded"} if the browser
    process has crashed or not yet finished starting.
    """
    browser    = _state.get("browser")
    connected: bool = browser is not None and browser.is_connected()
    return {"status": "ok" if connected else "degraded", "browser_connected": connected}

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    host = os.getenv("CAMOUFOX_HOST", "127.0.0.1")
    port = int(os.getenv("CAMOUFOX_PORT", "8085"))
    uvicorn.run(app, host=host, port=port, log_level="info")

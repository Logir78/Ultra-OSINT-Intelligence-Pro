"""Stealth Module — rotating User-Agents, jittered timing, organic referer patterns.

Provides a drop-in `StealthClient` that wraps httpx.AsyncClient with:
- Rotating User-Agent from a curated pool (Chrome/Firefox/Safari/Edge on 5 OSes + Googlebot/Bingbot)
- Random delay between requests (100-800ms jitter with occasional 1-3s "human pauses")
- Rotating Accept-Language, Accept, Sec-Fetch headers
- Referer chaining (looks like the user navigated from Google or homepage)
- Deterministic seed per host so requests from the same scan look like one user session
"""
import asyncio
import random
import hashlib
import httpx
from typing import Optional

# Curated real-world User-Agent strings (browsers as of 2025 + legitimate crawlers)
USER_AGENTS = [
    # Chrome / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Firefox / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Firefox / Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Safari / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    # Safari / iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    # Edge / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Chrome / Android
    "Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    # Legitimate crawlers (used for lower-priority requests)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; DuckDuckBot/1.1; +https://duckduckgo.com/duckduckbot)",
]

ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "en-GB,en;q=0.9",
    "fr-FR,fr;q=0.9,en;q=0.8",
]

ACCEPTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json,text/html;q=0.9,*/*;q=0.8",
]


class StealthClient:
    """Wraps httpx.AsyncClient with rotating headers and jittered timing.

    Usage:
        async with StealthClient(target="example.com") as sc:
            r = await sc.get("https://example.com/robots.txt")
    """

    def __init__(self, target: str, min_delay_ms: int = 100, max_delay_ms: int = 800,
                 human_pause_chance: float = 0.1, referer_root: Optional[str] = None):
        # Deterministic per-target session identity (looks like one user)
        seed = int(hashlib.sha256(target.encode()).hexdigest()[:8], 16)
        self._rand = random.Random(seed)
        self._target = target
        self._ua = self._rand.choice(USER_AGENTS)
        self._lang = self._rand.choice(ACCEPT_LANGS)
        self._accept = self._rand.choice(ACCEPTS)
        self._min_delay = min_delay_ms / 1000.0
        self._max_delay = max_delay_ms / 1000.0
        self._pause_chance = human_pause_chance
        self._referer_root = referer_root or f"https://www.google.com/search?q={target}"
        self._last_url: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._call_count = 0

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=8.0, follow_redirects=True,
            headers=self._base_headers())
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    def _base_headers(self) -> dict:
        return {
            "User-Agent": self._ua,
            "Accept": self._accept,
            "Accept-Language": self._lang,
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
            "DNT": "1",
        }

    async def _wait(self):
        # Standard jittered pause
        delay = self._rand.uniform(self._min_delay, self._max_delay)
        # Occasional longer "human reading" pause
        if self._rand.random() < self._pause_chance:
            delay += self._rand.uniform(1.0, 3.0)
        await asyncio.sleep(delay)

    async def get(self, url: str, **kw) -> httpx.Response:
        assert self._client is not None
        if self._call_count > 0:
            await self._wait()
        self._call_count += 1
        headers = dict(kw.pop("headers", {}))
        # Referer: previous URL (like a real browser) or Google search initially
        headers.setdefault("Referer", self._last_url or self._referer_root)
        headers.setdefault("Sec-Fetch-Site", "same-origin" if self._last_url else "none")
        r = await self._client.get(url, headers=headers, **kw)
        self._last_url = url
        return r

    async def post(self, url: str, **kw) -> httpx.Response:
        assert self._client is not None
        if self._call_count > 0:
            await self._wait()
        self._call_count += 1
        headers = dict(kw.pop("headers", {}))
        headers.setdefault("Referer", self._last_url or self._referer_root)
        r = await self._client.post(url, headers=headers, **kw)
        self._last_url = url
        return r

    @property
    def user_agent(self) -> str:
        return self._ua

    @property
    def profile(self) -> dict:
        return {"user_agent": self._ua, "accept_language": self._lang,
                "accept": self._accept, "referer": self._referer_root,
                "requests_made": self._call_count}


def stealth_headers(target: str, extra: Optional[dict] = None) -> dict:
    """Return a rotating stealth headers dict for a target. Deterministic per host so
    all requests in the same scan look like one user session."""
    seed = int(hashlib.sha256(target.encode()).hexdigest()[:8], 16)
    r = random.Random(seed)
    ua = r.choice(USER_AGENTS)
    lang = r.choice(ACCEPT_LANGS)
    accept = r.choice(ACCEPTS)
    headers = {
        "User-Agent": ua,
        "Accept": accept,
        "Accept-Language": lang,
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
        "DNT": "1",
        "Referer": f"https://www.google.com/search?q={target}",
    }
    if extra:
        headers.update(extra)
    return headers


def stealth_httpx_client(target: str, **kwargs) -> httpx.AsyncClient:
    """Factory: returns a raw httpx.AsyncClient pre-configured with stealth headers.
    Drop-in replacement for `httpx.AsyncClient(...)` in target-facing scanner code.

    Any `headers=` passed via kwargs are merged (kwargs override stealth defaults).
    """
    user_headers = kwargs.pop("headers", None) or {}
    merged = stealth_headers(target, extra=user_headers)
    kwargs.setdefault("timeout", 8.0)
    return httpx.AsyncClient(headers=merged, **kwargs)


def stealth_status() -> dict:
    """Public config report — no scan needed."""
    return {
        "enabled": True,
        "pool_sizes": {"user_agents": len(USER_AGENTS), "languages": len(ACCEPT_LANGS),
                        "accepts": len(ACCEPTS)},
        "default_delay_ms": {"min": 100, "max": 800, "human_pause_extra_range_s": [1.0, 3.0]},
        "human_pause_chance": 0.1,
        "features": [
            "rotating_user_agent_per_scan",
            "deterministic_per_target_session",
            "jittered_inter_request_delay",
            "human_reading_pauses",
            "chained_referer",
            "randomized_accept_language",
        ],
        "note": "Todos los módulos activos usan StealthClient automáticamente. Rotación por-escaneo (mismo UA durante todo un scan simula una sesión de usuario).",
    }

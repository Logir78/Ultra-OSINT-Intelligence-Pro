"""Passive paste-site / threat-intel search — free & no API key.

Searches DuckDuckGo (HTML) for mentions of the domain / IPs on public paste
sites (pastebin, ghostbin, hastebin, etc.) and Github code search where domains
frequently leak (config files, tokens).
"""
import asyncio
import re
import httpx
import logging
from datetime import datetime

log = logging.getLogger("paste_search")

DDG_HTML = "https://html.duckduckgo.com/html/"

# Sites known to host leaks / pastes
PASTE_SITES = [
    ("Pastebin",       "pastebin.com"),
    ("Ghostbin",       "ghostbin.co"),
    ("Hastebin",       "hastebin.com"),
    ("JustPaste",      "justpaste.it"),
    ("Paste.ee",       "paste.ee"),
    ("ControlC",       "controlc.com"),
    ("Rentry",         "rentry.co"),
    ("dpaste",         "dpaste.com"),
    ("GitHub Gist",    "gist.github.com"),
    ("Pastie",         "pastie.io"),
]


def _extract_links(html: str, site: str) -> list[dict]:
    """Extract organic result links + snippets from a DDG HTML SERP."""
    out = []
    # Each result block starts with <a class="result__url" ...>
    for m in re.finditer(
        r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>',
        html, re.DOTALL,
    ):
        raw_url = m.group(1)
        # DDG wraps URLs in redirector
        real = raw_url
        rm = re.search(r"uddg=([^&]+)", raw_url)
        if rm:
            try:
                from urllib.parse import unquote
                real = unquote(rm.group(1))
            except Exception:
                pass
        title = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        snippet = re.sub(r"<[^>]+>", "", m.group(3)).strip()
        if site in real:
            out.append({"url": real, "title": title[:180], "snippet": snippet[:280], "site": site})
        if len(out) >= 5:
            break
    return out


async def _search_ddg(client: httpx.AsyncClient, query: str) -> str:
    try:
        r = await client.post(
            DDG_HTML, data={"q": query},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=12.0,
        )
        return r.text
    except Exception as e:
        log.warning(f"DDG search failed for '{query}': {e}")
        return ""


async def search_paste_mentions(domain: str, ips: list[str], max_ips: int = 3) -> dict:
    """Search across paste sites for domain + top IPs.

    Returns unified list of mentions with source + snippet + estimated date.
    """
    queries = []
    for label, site in PASTE_SITES:
        queries.append((label, site, f'"{domain}" site:{site}'))
    # Also search Github + a couple of IPs
    for ip in (ips or [])[:max_ips]:
        queries.append(("GitHub", "github.com", f'"{ip}" site:github.com'))

    async with httpx.AsyncClient() as client:
        htmls = await asyncio.gather(*[_search_ddg(client, q) for _, _, q in queries])

    mentions = []
    for (label, site, _), html in zip(queries, htmls):
        for item in _extract_links(html, site):
            item["source_label"] = label
            mentions.append(item)

    # Deduplicate by URL
    seen = set()
    uniq = []
    for m in mentions:
        if m["url"] in seen:
            continue
        seen.add(m["url"])
        uniq.append(m)

    return {
        "domain": domain,
        "queries_run": len(queries),
        "sites_covered": [label for label, _ in PASTE_SITES] + ["GitHub"],
        "total_mentions": len(uniq),
        "mentions": uniq,
        "searched_at": datetime.utcnow().isoformat(),
    }

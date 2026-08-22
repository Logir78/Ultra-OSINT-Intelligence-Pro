"""Parameter Miner — discover hidden URL parameters from JS/HTML sources."""
import re
import asyncio
import httpx
import logging
from urllib.parse import urlparse

from integrations.stealth import stealth_httpx_client

log = logging.getLogger("param_miner")

# Common hidden param names (Arjun-style wordlist, curated)
COMMON_PARAMS = [
    "debug", "admin", "test", "dev", "staging", "beta", "internal", "trace",
    "verbose", "log", "logs", "backup", "restore", "action", "mode", "cmd",
    "exec", "eval", "raw", "sql", "query", "q", "search", "filter", "sort",
    "page", "id", "uid", "user_id", "userid", "user", "username", "email",
    "token", "auth", "authorization", "session", "sid", "cookie", "key",
    "api_key", "apikey", "secret", "password", "pass", "pwd", "callback",
    "redirect", "url", "next", "return", "returnto", "return_to", "path",
    "file", "filename", "load", "template", "view", "include", "require",
    "src", "source", "dest", "destination", "target", "to", "from", "type",
    "format", "output", "input", "data", "value", "content", "body", "message",
    "role", "permission", "level", "priv", "privilege", "test_mode",
    "impersonate", "as", "override", "force", "bypass", "unsafe", "danger",
]

# Regex to catch URL param usage
PARAM_QUERY_RE = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_]{1,40})=")
PARAM_ACCESS_RE = re.compile(
    r"(?:params?|query|searchParams|URLSearchParams|req\.query|"
    r"URL\([^)]*\)\.searchParams|new\s+URLSearchParams|"
    r"formData|getParam|urlParams|queryString)"
    r"[.\[\s]*['\"]([a-zA-Z_][a-zA-Z0-9_]{1,40})['\"]"
)
FORM_INPUT_RE = re.compile(
    r"""<input[^>]+name\s*=\s*['"]([a-zA-Z_][a-zA-Z0-9_]{1,40})['"]""",
    re.IGNORECASE,
)
DATA_KEY_RE = re.compile(r"""['"]([a-zA-Z_][a-zA-Z0-9_]{2,40})['"]\s*:\s*""")


DANGEROUS_KEYWORDS = ["admin", "debug", "test", "dev", "staging", "sql", "cmd",
                      "exec", "eval", "raw", "internal", "trace", "impersonate",
                      "bypass", "unsafe", "force", "override", "role", "priv"]


def _param_priority(name: str) -> str:
    lower = name.lower()
    if any(k in lower for k in ("admin", "debug", "cmd", "exec", "eval", "sql", "raw",
                                 "internal", "impersonate", "bypass")):
        return "critical"
    if any(k in lower for k in DANGEROUS_KEYWORDS):
        return "high"
    return "medium"


async def _fetch_text(client: httpx.AsyncClient, url: str) -> str | None:
    try:
        r = await client.get(url, timeout=5.0, follow_redirects=True)
        if r.status_code != 200 or len(r.content) > 512 * 1024:
            return None
        return r.text
    except Exception:
        return None


async def mine_params(domain: str, js_sources: list[str] | None = None) -> dict:
    """Extract hidden parameter candidates from homepage + optional JS URLs."""
    urls_to_scan = []
    for scheme in ("https", "http"):
        urls_to_scan.append(f"{scheme}://{domain}")
        break  # try https first — fallback handled by _fetch_text

    async with stealth_httpx_client(domain, timeout=6.0) as client:
        # Homepage
        home_html = await _fetch_text(client, f"https://{domain}") or await _fetch_text(client, f"http://{domain}")
        # JS files (limit)
        js_texts = []
        if js_sources:
            filtered = [u for u in js_sources if u.startswith("http")][:10]
            results = await asyncio.gather(*[_fetch_text(client, u) for u in filtered])
            js_texts = [t for t in results if t]

    all_text = (home_html or "") + "\n" + "\n".join(js_texts)

    discovered: dict[str, dict] = {}

    def _add(name, source):
        if not name or len(name) < 2 or len(name) > 40:
            return
        entry = discovered.setdefault(name, {
            "name": name, "sources": set(), "priority": _param_priority(name),
        })
        entry["sources"].add(source)

    for m in PARAM_QUERY_RE.finditer(all_text):
        _add(m.group(1), "url_query")
    for m in PARAM_ACCESS_RE.finditer(all_text):
        _add(m.group(1), "js_access")
    for m in FORM_INPUT_RE.finditer(all_text):
        _add(m.group(1), "form_field")
    for m in DATA_KEY_RE.finditer(all_text):
        # Only include if the key name looks like a URL param (short, snake/kebab)
        name = m.group(1)
        if name.lower() in COMMON_PARAMS or "_" in name:
            _add(name, "json_key")

    # Add well-known suspicious defaults if not present, marked as speculative
    for name in COMMON_PARAMS[:30]:
        if name not in discovered:
            discovered[name] = {
                "name": name,
                "sources": {"wordlist"},
                "priority": _param_priority(name),
            }

    # Build candidate URLs (homepage as base)
    base = f"https://{domain}/"
    candidates = []
    for name, info in discovered.items():
        info["sources"] = sorted(info["sources"])
        candidates.append({
            "name": name,
            "priority": info["priority"],
            "sources": info["sources"],
            "candidate_url": f"{base}?{name}=NOCTUA_TEST",
        })

    # Sort: critical first, then high, then everything else; wordlist-only entries last
    def _sort_key(p):
        pri = {"critical": 0, "high": 1, "medium": 2}[p["priority"]]
        wordlist_only = p["sources"] == ["wordlist"]
        return (pri, wordlist_only, p["name"])

    candidates.sort(key=_sort_key)

    return {
        "domain": domain,
        "total_discovered": len(candidates),
        "counts_by_priority": {
            p: len([c for c in candidates if c["priority"] == p])
            for p in ("critical", "high", "medium")
        },
        "candidates": candidates[:200],
        "note": "Los parámetros marcados como 'wordlist' son sugerencias del diccionario, no observados directamente.",
    }

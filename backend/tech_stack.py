"""Technology stack fingerprinting from HTTP response headers."""
import asyncio
import re
import httpx

from integrations.stealth import stealth_httpx_client


CRITICAL_HEADERS = ["content-security-policy", "strict-transport-security"]

# Proxy/CDN/WAF detection signatures
PROXY_SIGS = [
    # (label, header_name_lower, regex_or_value_lower, category)
    ("Cloudflare",   "server",       r"^cloudflare",        "cdn+waf"),
    ("Cloudflare",   "cf-ray",       r".+",                 "cdn+waf"),
    ("Cloudflare",   "cf-cache-status", r".+",              "cdn+waf"),
    ("Akamai",       "server",       r"akamaighost|akamainetstorage", "cdn+waf"),
    ("Akamai",       "x-akamai-transformed", r".+",         "cdn+waf"),
    ("Akamai",       "x-akamai-request-id", r".+",          "cdn+waf"),
    ("Sucuri",       "server",       r"sucuri",             "waf"),
    ("Sucuri",       "x-sucuri-id",  r".+",                 "waf"),
    ("Sucuri",       "x-sucuri-cache", r".+",               "waf"),
    ("Fastly",       "server",       r"^fastly",            "cdn"),
    ("Fastly",       "fastly-debug-digest", r".+",          "cdn"),
    ("Imperva",      "x-iinfo",      r".+",                 "waf"),
    ("AWS CloudFront","server",      r"^cloudfront",        "cdn"),
    ("AWS CloudFront","via",         r"cloudfront",         "cdn"),
    ("Vercel",       "server",       r"^vercel",            "hosting+edge"),
    ("Vercel",       "x-vercel-id",  r".+",                 "hosting+edge"),
    ("Netlify",      "server",       r"netlify",            "hosting+edge"),
    ("Netlify",      "x-nf-request-id", r".+",              "hosting+edge"),
    ("KeyCDN",       "server",       r"keycdn",             "cdn"),
    ("BunnyCDN",     "server",       r"bunnycdn",           "cdn"),
    ("StackPath",    "server",       r"stackpath",          "cdn"),
    ("Google Cloud", "via",          r"google",             "hosting"),
    ("Incapsula",    "x-cdn",        r"incapsula",          "waf"),
]

# CMS detection
CMS_SIGS = [
    ("WordPress",  "x-powered-by",   r"wordpress"),
    ("WordPress",  "link",           r"wp-json|wp-includes"),
    ("Drupal",     "x-generator",    r"drupal"),
    ("Drupal",     "x-drupal-cache", r".+"),
    ("Joomla",     "x-content-encoded-by", r"joomla"),
    ("Ghost",      "x-ghost-cache-status", r".+"),
    ("Shopify",    "server",         r"shopify"),
    ("Shopify",    "x-shopify-stage", r".+"),
    ("Squarespace","server",         r"squarespace"),
    ("Wix",        "x-wix-request-id", r".+"),
    ("Webflow",    "x-wf-forwarded-proto", r".+"),
    ("Magento",    "x-magento-cache-debug", r".+"),
]

# Framework / language detection
FRAMEWORK_SIGS = [
    ("PHP",        "x-powered-by",   r"^php"),
    ("ASP.NET",    "x-powered-by",   r"asp\.net"),
    ("ASP.NET",    "x-aspnet-version", r".+"),
    ("Express",    "x-powered-by",   r"express"),
    ("Next.js",    "x-nextjs-cache", r".+"),
    ("Next.js",    "x-powered-by",   r"next\.js"),
    ("Nuxt",       "x-nuxt-cache",   r".+"),
    ("Rails",      "x-runtime",      r".+"),
    ("Django",     "x-frame-options", r"^SAMEORIGIN"),  # weak signal, kept low priority
    ("Laravel",    "set-cookie",     r"laravel_session"),
    ("Ruby",       "server",         r"passenger|puma|unicorn"),
    ("Node.js",    "x-powered-by",   r"node\.js"),
    ("Tomcat",     "server",         r"tomcat|apache-coyote"),
    ("Jetty",      "server",         r"jetty"),
    ("Gunicorn",   "server",         r"gunicorn"),
    ("uWSGI",      "server",         r"uwsgi"),
]

# Web server detection (basic)
SERVER_SIGS = [
    ("nginx",    "server",  r"^nginx"),
    ("Apache",   "server",  r"^apache"),
    ("Microsoft-IIS", "server", r"microsoft-iis|iis/"),
    ("LiteSpeed","server",  r"litespeed"),
    ("OpenResty","server",  r"openresty"),
    ("Caddy",    "server",  r"^caddy"),
    ("Envoy",    "server",  r"envoy"),
]


def _match(sigs, headers_lower: dict) -> list[dict]:
    found = []
    seen = set()
    for entry in sigs:
        label, hkey, pattern = entry[0], entry[1], entry[2]
        if label in seen:
            continue
        val = headers_lower.get(hkey)
        if val and re.search(pattern, str(val), re.IGNORECASE):
            found.append({"name": label, "evidence": f"{hkey}: {val[:120]}"})
            seen.add(label)
    return found


def analyze_headers(headers: dict) -> dict:
    if not headers:
        return {
            "server": None, "cms": [], "frameworks": [], "proxies": [],
            "is_protected": False, "protection_kind": None,
            "missing_critical": CRITICAL_HEADERS.copy(),
            "banner": None,
        }
    hl = {k.lower(): v for k, v in headers.items()}
    proxies = []
    for label, hkey, pattern, category in PROXY_SIGS:
        if any(p["name"] == label for p in proxies):
            continue
        val = hl.get(hkey)
        if val and re.search(pattern, str(val), re.IGNORECASE):
            proxies.append({"name": label, "category": category, "evidence": f"{hkey}: {val[:120]}"})

    server_hits = _match(SERVER_SIGS, hl)
    server = server_hits[0]["name"] if server_hits else (hl.get("server") or None)

    cms = _match(CMS_SIGS, hl)
    frameworks = _match(FRAMEWORK_SIGS, hl)

    missing = [h for h in CRITICAL_HEADERS if h not in hl]

    is_protected = any(p["category"] in ("cdn+waf", "waf") for p in proxies)
    protection_kind = "waf" if any(p["category"] in ("cdn+waf", "waf") for p in proxies) else (
        "cdn" if proxies else None
    )

    return {
        "server": server,
        "cms": cms,
        "frameworks": frameworks,
        "proxies": proxies,
        "is_protected": is_protected,
        "protection_kind": protection_kind,
        "missing_critical": missing,
        "banner": hl.get("server"),
        "powered_by": hl.get("x-powered-by"),
    }


async def _fetch_headers(hostname: str) -> dict | None:
    try:
        async with stealth_httpx_client(hostname, follow_redirects=True, verify=False, timeout=6.0) as client:
            r = await client.get(f"https://{hostname}")
        return dict(r.headers)
    except Exception:
        return None


async def analyze_tech_for_hosts(hosts: list[str], preloaded: dict[str, dict] | None = None) -> list[dict]:
    """Fetch headers per hostname (in parallel, stealth) and produce a tech report."""
    preloaded = preloaded or {}

    async def _one(host: str) -> dict:
        headers = preloaded.get(host)
        if headers is None:
            headers = await _fetch_headers(host)
        analysis = analyze_headers(headers or {})
        return {
            "hostname": host,
            "reachable": headers is not None,
            **analysis,
        }
    return await asyncio.gather(*[_one(h) for h in hosts])

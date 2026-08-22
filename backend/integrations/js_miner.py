"""JS Miner — download and analyze site JavaScript for secrets & hidden endpoints."""
import re
import asyncio
import httpx
import logging
from urllib.parse import urljoin, urlparse

from integrations.stealth import stealth_httpx_client

log = logging.getLogger("js_miner")

MAX_FILES = 12
MAX_FILE_KB = 512
TIMEOUT_S = 6.0

# Secret / token signatures (name → regex)
SIGNATURES = [
    ("aws_access_key",       r"AKIA[0-9A-Z]{16}"),
    ("aws_secret_key",       r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    ("gcp_api_key",          r"AIza[0-9A-Za-z_\-]{35}"),
    ("stripe_live_key",      r"sk_live_[0-9a-zA-Z]{24,}"),
    ("stripe_test_key",      r"sk_test_[0-9a-zA-Z]{24,}"),
    ("stripe_publishable",   r"pk_live_[0-9a-zA-Z]{24,}"),
    ("github_token",         r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("slack_token",          r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("slack_webhook",        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("firebase_url",         r"https?://[a-z0-9\-]+\.firebaseio\.com"),
    ("supabase_key",         r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
    ("jwt_generic",          r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("mailgun_key",          r"key-[0-9a-zA-Z]{32}"),
    ("sendgrid_key",         r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
    ("private_key_pem",      r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
    ("bearer_token",         r"[Bb]earer\s+[A-Za-z0-9\-_\.=]{20,}"),
    ("basic_auth",           r"[Bb]asic\s+[A-Za-z0-9+/=]{20,}"),
]

ENDPOINT_RE = re.compile(r"""["'`](/api/[a-zA-Z0-9_\-/.?=&%{}$]{2,120})["'`]""")
ABS_API_RE  = re.compile(r"""["'`](https?://[a-zA-Z0-9\.\-]+/(api|v\d)/[a-zA-Z0-9_\-/.?=&%{}$]{0,120})["'`]""")
COMMENT_RE  = re.compile(r"//\s*(TODO|FIXME|HACK|BUG|XXX|DEBUG|WIP)[:\s].{2,120}", re.IGNORECASE)
EMAIL_RE    = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


def _severity(kind: str) -> str:
    high = {"aws_access_key", "gcp_api_key", "stripe_live_key", "private_key_pem",
            "github_token", "slack_token", "supabase_key", "sendgrid_key", "mailgun_key",
            "slack_webhook"}
    if kind in high:
        return "critical"
    medium = {"stripe_test_key", "stripe_publishable", "jwt_generic", "bearer_token",
              "basic_auth", "firebase_url", "aws_secret_key"}
    if kind in medium:
        return "high"
    return "medium"


def _snippet(text: str, match_start: int, match_end: int, ctx: int = 60) -> str:
    a = max(0, match_start - ctx)
    b = min(len(text), match_end + ctx)
    return text[a:b].replace("\n", " ").strip()[:220]


async def _fetch(client: httpx.AsyncClient, url: str) -> tuple[str, str] | None:
    try:
        r = await client.get(url, timeout=TIMEOUT_S, follow_redirects=True)
        if r.status_code != 200:
            return None
        if len(r.content) > MAX_FILE_KB * 1024:
            return None
        ct = r.headers.get("content-type", "")
        # Prevent parsing HTML as JS
        return (url, r.text)
    except Exception:
        return None


async def _discover_js(domain: str) -> tuple[list[str], str | None]:
    """Fetch homepage over HTTPS (fallback HTTP), extract JS URLs (inline + external).
    Also probe for common .map source maps alongside each JS URL.
    """
    base_urls = [f"https://{domain}", f"http://{domain}"]
    async with httpx.AsyncClient(timeout=TIMEOUT_S, follow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0 NOCTUA-osint"}) as client:
        for base in base_urls:
            try:
                r = await client.get(base)
                if r.status_code != 200:
                    continue
                html = r.text
                srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html, re.IGNORECASE)
                inline = re.findall(r"<script(?![^>]+src=)[^>]*>([\s\S]*?)</script>", html, re.IGNORECASE)
                js_urls = []
                for s in srcs:
                    if s.startswith("//"):
                        js_urls.append("https:" + s)
                    elif s.startswith("http"):
                        js_urls.append(s)
                    else:
                        js_urls.append(urljoin(base + "/", s))
                # De-duplicate
                seen = set()
                js_urls = [u for u in js_urls if not (u in seen or seen.add(u))]
                js_urls = js_urls[:MAX_FILES]
                # Also add corresponding .map URLs (if not already .map)
                map_urls = []
                for u in js_urls:
                    if u.endswith(".js"):
                        map_urls.append(u + ".map")
                combined = js_urls + map_urls[:MAX_FILES]
                return combined, "\n\n".join(inline)[: MAX_FILE_KB * 1024]
            except Exception:
                continue
        return [], None


def _scan_text(url: str, content: str) -> list[dict]:
    findings = []
    for kind, pattern in SIGNATURES:
        for m in re.finditer(pattern, content):
            findings.append({
                "kind": kind, "severity": _severity(kind),
                "match": m.group(0)[:120], "snippet": _snippet(content, m.start(), m.end()),
                "source": url,
            })
    # Endpoints
    for m in ENDPOINT_RE.finditer(content):
        findings.append({
            "kind": "api_endpoint", "severity": "info",
            "match": m.group(1)[:120], "snippet": _snippet(content, m.start(), m.end()),
            "source": url,
        })
    for m in ABS_API_RE.finditer(content):
        findings.append({
            "kind": "api_endpoint", "severity": "info",
            "match": m.group(1)[:180], "snippet": _snippet(content, m.start(), m.end()),
            "source": url,
        })
    # Comments
    for m in COMMENT_RE.finditer(content):
        findings.append({
            "kind": "dev_comment", "severity": "low",
            "match": m.group(0)[:180], "snippet": m.group(0)[:220],
            "source": url,
        })
    # Emails
    for m in EMAIL_RE.finditer(content):
        # Skip obviously bogus ones
        if "@example" in m.group(0) or "@test" in m.group(0):
            continue
        findings.append({
            "kind": "email", "severity": "low",
            "match": m.group(0)[:120], "snippet": _snippet(content, m.start(), m.end(), 30),
            "source": url,
        })
    return findings


def _dedupe(findings: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for f in findings:
        key = (f["kind"], f["match"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


async def mine(domain: str) -> dict:
    """Main entry — returns categorized findings."""
    js_urls, inline_js = await _discover_js(domain)
    contents = []
    if inline_js:
        contents.append(("inline://homepage", inline_js))
    if js_urls:
        async with stealth_httpx_client(domain, timeout=TIMEOUT_S) as client:
            results = await asyncio.gather(*[_fetch(client, u) for u in js_urls])
            for r in results:
                if r:
                    contents.append(r)

    findings = []
    for url, text in contents:
        try:
            findings.extend(_scan_text(url, text))
        except Exception as e:
            log.warning(f"Scan failed for {url}: {e}")

    findings = _dedupe(findings)

    # Group by kind
    grouped: dict[str, list[dict]] = {}
    for f in findings:
        grouped.setdefault(f["kind"], []).append(f)

    counts_by_severity = {}
    for f in findings:
        counts_by_severity[f["severity"]] = counts_by_severity.get(f["severity"], 0) + 1

    return {
        "domain": domain,
        "js_files_analyzed": len(contents),
        "js_urls_discovered": len(js_urls),
        "sources": [u for u, _ in contents],
        "findings": findings,
        "counts_by_kind": {k: len(v) for k, v in grouped.items()},
        "counts_by_severity": counts_by_severity,
        "total_findings": len(findings),
    }

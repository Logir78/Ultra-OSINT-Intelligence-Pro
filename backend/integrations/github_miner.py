"""GitHub / Gist code miner — search public code for domain mentions & leaked secrets."""
import httpx
import logging
import re
import base64

log = logging.getLogger("github_miner")

# Secret patterns we care about even in external code (subset of js_miner)
QUICK_SECRETS = [
    ("aws_access_key",  re.compile(r"AKIA[0-9A-Z]{16}")),
    ("gcp_api_key",     re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("stripe_live",     re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("github_token",    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack_token",     re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("private_key",     re.compile(r"BEGIN (RSA|EC|OPENSSH) PRIVATE KEY")),
]


async def search_github(domain: str, github_token: str | None = None) -> dict:
    """Query GitHub code search API. Requires auth for search/code endpoint.

    Returns matches + secret hits. Without a token, returns configured=False.
    """
    if not github_token:
        return {"configured": False, "note": "Añade un token de GitHub personal (scope: repo) en Ajustes → API Keys → github para activar esta búsqueda.",
                "total_hits": 0, "results": [], "secret_hits": []}

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "NOCTUA-osint",
    }
    hits = []
    secret_hits = []

    try:
        async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
            # 1) Code search — domain mention
            queries = [
                f'"{domain}"',                    # general mention
                f'"{domain}" password',
                f'"{domain}" api_key',
                f'"{domain}" secret',
            ]
            seen_urls = set()
            for q in queries[:2]:
                r = await client.get("https://api.github.com/search/code",
                                     params={"q": q, "per_page": 30})
                if r.status_code != 200:
                    if r.status_code == 403:
                        return {"configured": True, "error": "Rate limit / token sin scope",
                                "total_hits": 0, "results": [], "secret_hits": []}
                    continue
                data = r.json()
                for item in (data.get("items") or []):
                    url = item.get("html_url")
                    if not url or url in seen_urls:
                        continue
                    seen_urls.add(url)
                    hit = {
                        "html_url": url,
                        "path": item.get("path"),
                        "repository": (item.get("repository") or {}).get("full_name"),
                        "repo_stars": (item.get("repository") or {}).get("stargazers_count"),
                        "query": q,
                    }
                    # Try to fetch a short snippet
                    api_url = item.get("url")
                    if api_url:
                        try:
                            cr = await client.get(api_url, timeout=6.0)
                            if cr.status_code == 200:
                                content_b64 = (cr.json() or {}).get("content", "")
                                if content_b64:
                                    content = base64.b64decode(content_b64, validate=False)[:4096].decode("utf-8", errors="replace")
                                    # Grab a short snippet around the domain mention
                                    idx = content.lower().find(domain.lower())
                                    if idx >= 0:
                                        a = max(0, idx - 80)
                                        b = min(len(content), idx + 200)
                                        hit["snippet"] = content[a:b].replace("\n", " ")[:280]
                                    # Detect secrets in this file
                                    for label, rx in QUICK_SECRETS:
                                        m = rx.search(content)
                                        if m:
                                            secret_hits.append({
                                                "kind": label,
                                                "match": m.group(0)[:80],
                                                "repository": hit["repository"],
                                                "path": hit["path"],
                                                "html_url": url,
                                            })
                        except Exception:
                            pass
                    hits.append(hit)

            # 2) Gist search — public gists mentioning the domain
            try:
                gr = await client.get("https://api.github.com/search/code",
                                       params={"q": f'"{domain}" in:file extension:env', "per_page": 15})
                if gr.status_code == 200:
                    for item in (gr.json() or {}).get("items", [])[:15]:
                        url = item.get("html_url")
                        if url and url not in seen_urls:
                            seen_urls.add(url)
                            hits.append({
                                "html_url": url,
                                "path": item.get("path"),
                                "repository": (item.get("repository") or {}).get("full_name"),
                                "query": ".env file",
                            })
            except Exception:
                pass

    except Exception as e:
        log.warning(f"GitHub search failed: {e}")
        return {"configured": True, "error": str(e), "total_hits": 0, "results": [], "secret_hits": []}

    return {
        "configured": True,
        "total_hits": len(hits),
        "secret_hits_count": len(secret_hits),
        "results": hits[:60],
        "secret_hits": secret_hits[:30],
    }

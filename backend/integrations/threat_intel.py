"""Extended dark-web / OSINT lookups — URLScan (public) + IntelX (user key).

- URLScan.io: free tier w/o API key allows searching public scan history.
  Docs: https://urlscan.io/docs/api/
- IntelX: paid, requires API key from https://intelx.io/account?tab=developer
"""
import httpx
import logging
import os

log = logging.getLogger("threat_intel")

URLSCAN_URL = "https://urlscan.io/api/v1/search/"
INTELX_URL = "https://2.intelx.io"


def urlscan_key() -> str | None:
    return (os.environ.get("URLSCAN_KEY") or "").strip() or None


def intelx_key(user_key: str | None = None) -> str | None:
    return (user_key or "").strip() or (os.environ.get("INTELX_KEY") or "").strip() or None


async def urlscan_search(domain: str, user_key: str | None = None) -> dict:
    """Free public search over URLScan history — no key required for basic queries."""
    headers = {}
    key = (user_key or "").strip() or urlscan_key()
    if key:
        headers["API-Key"] = key
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=headers) as c:
            r = await c.get(URLSCAN_URL, params={"q": f"domain:{domain}", "size": 20})
        if r.status_code != 200:
            return {"provider": "URLScan", "configured": True, "error": f"HTTP {r.status_code}", "results": []}
        d = r.json()
        out = []
        for x in d.get("results", [])[:20]:
            out.append({
                "url": (x.get("page") or {}).get("url"),
                "task_time": (x.get("task") or {}).get("time"),
                "domain": (x.get("page") or {}).get("domain"),
                "verdict": (x.get("verdicts") or {}).get("overall", {}).get("malicious"),
                "score":   (x.get("verdicts") or {}).get("overall", {}).get("score"),
                "screenshot": x.get("screenshot"),
                "result_url": x.get("result"),
            })
        return {"provider": "URLScan", "configured": True, "total": d.get("total", 0), "results": out}
    except Exception as e:
        return {"provider": "URLScan", "configured": True, "error": str(e), "results": []}


async def intelx_search(domain: str, user_key: str | None = None) -> dict:
    key = intelx_key(user_key)
    if not key:
        return {"provider": "IntelX", "configured": False,
                "key_url": "https://intelx.io/account?tab=developer", "results": []}
    try:
        async with httpx.AsyncClient(timeout=20.0) as c:
            r = await c.post(f"{INTELX_URL}/intelligent/search",
                             headers={"x-key": key, "content-type": "application/json"},
                             json={"term": domain, "maxresults": 20, "media": 0, "sort": 4, "terminate": []})
            if r.status_code != 200:
                return {"provider": "IntelX", "configured": True, "error": f"HTTP {r.status_code}", "results": []}
            search_id = r.json().get("id")
            if not search_id:
                return {"provider": "IntelX", "configured": True, "error": "no search id", "results": []}
            # Poll once
            r2 = await c.get(f"{INTELX_URL}/intelligent/search/result",
                             headers={"x-key": key},
                             params={"id": search_id, "limit": 20})
        d = r2.json()
        out = []
        for rec in d.get("records", [])[:20]:
            out.append({
                "name": rec.get("name"),
                "date": rec.get("date"),
                "bucket": rec.get("bucket"),
                "systemid": rec.get("systemid"),
                "media_type": rec.get("mediah"),
            })
        return {"provider": "IntelX", "configured": True, "results": out}
    except Exception as e:
        return {"provider": "IntelX", "configured": True, "error": str(e), "results": []}

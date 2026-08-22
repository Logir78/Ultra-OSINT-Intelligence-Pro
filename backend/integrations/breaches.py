"""Data-breach lookup — Have I Been Pwned + BreachDirectory (via RapidAPI).
- HIBP docs: https://haveibeenpwned.com/API/v3  (paid $3.95/mo)
- BreachDirectory (RapidAPI): https://rapidapi.com/rohan-patra/api/breachdirectory (free tier)
Results from both sources are unified, deduplicated (by name+date) and sorted newest→oldest.
"""
import os
import asyncio
import httpx
import logging
from datetime import datetime

log = logging.getLogger("breaches")

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_KEY_URL = "https://haveibeenpwned.com/API/Key"
RAPIDAPI_KEY_URL = "https://rapidapi.com/rohan-patra/api/breachdirectory"


def _hibp_key() -> str | None:
    k = os.environ.get("HIBP_KEY") or ""
    return k.strip() or None


def _rapidapi_key() -> str | None:
    k = os.environ.get("RAPIDAPI_KEY") or ""
    return k.strip() or None


def providers_status() -> dict:
    return {
        "hibp": {"configured": _hibp_key() is not None, "key_url": HIBP_KEY_URL, "provider": "Have I Been Pwned"},
        "breachdirectory": {"configured": _rapidapi_key() is not None, "key_url": RAPIDAPI_KEY_URL, "provider": "BreachDirectory"},
    }


async def _hibp_breachedaccount(client: httpx.AsyncClient, email: str) -> list[dict]:
    key = _hibp_key()
    if not key:
        return []
    try:
        r = await client.get(
            f"{HIBP_BASE}/breachedaccount/{email}",
            headers={"hibp-api-key": key, "user-agent": "NOCTUA-osint"},
            params={"truncateResponse": "false"}, timeout=12.0,
        )
        if r.status_code == 404:
            return []
        if r.status_code != 200:
            return []
        arr = r.json() or []
        return [{
            "source": "HIBP",
            "name": b.get("Name"),
            "title": b.get("Title"),
            "domain": b.get("Domain"),
            "breach_date": b.get("BreachDate"),
            "added_date": b.get("AddedDate"),
            "pwn_count": b.get("PwnCount"),
            "data_classes": b.get("DataClasses") or [],
            "description": (b.get("Description") or "").strip(),
            "is_verified": b.get("IsVerified"),
            "is_sensitive": b.get("IsSensitive"),
            "logo_path": b.get("LogoPath"),
        } for b in arr]
    except Exception as e:
        log.warning(f"HIBP error: {e}")
        return []


async def _hibp_domain(client: httpx.AsyncClient, domain: str) -> list[dict]:
    """HIBP has no free-form domain search; skip unless mapped elsewhere."""
    return []


async def _breachdirectory_lookup(client: httpx.AsyncClient, query: str) -> list[dict]:
    key = _rapidapi_key()
    if not key:
        return []
    try:
        r = await client.get(
            "https://breachdirectory.p.rapidapi.com/",
            headers={
                "X-RapidAPI-Key": key,
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
            },
            params={"func": "auto", "term": query},
            timeout=15.0,
        )
        if r.status_code != 200:
            return []
        d = r.json() or {}
        results = d.get("result") or []
        out = []
        for r_ in results:
            out.append({
                "source": "BreachDirectory",
                "name": r_.get("sources", [""])[0] if r_.get("sources") else "unknown",
                "title": ", ".join(r_.get("sources") or []) or "Filtración",
                "breach_date": None,  # BreachDirectory doesn't include date reliably
                "data_classes": [k for k in ("email", "password", "hash", "line") if r_.get(k)],
                "description": f"Registro encontrado. Password hash: {r_.get('has_password') or 'N/A'}",
                "email": r_.get("email"),
                "password_masked": _mask(r_.get("password")),
                "hash": r_.get("hash"),
            })
        return out
    except Exception as e:
        log.warning(f"BreachDirectory error: {e}")
        return []


def _mask(pw: str | None) -> str | None:
    if not pw:
        return None
    if len(pw) <= 2:
        return "*" * len(pw)
    return pw[0] + "*" * (len(pw) - 2) + pw[-1]


def _dedup_and_sort(breaches: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for b in breaches:
        key = (b.get("name") or "").lower().strip() + "|" + str(b.get("breach_date") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(b)

    def sort_key(b):
        d = b.get("breach_date") or b.get("added_date") or "0000-00-00"
        try:
            return datetime.strptime(d[:10], "%Y-%m-%d")
        except Exception:
            return datetime(1970, 1, 1)

    out.sort(key=sort_key, reverse=True)
    return out


async def unified_search(query: str, qtype: str, hibp_key: str | None = None, rapidapi_key: str | None = None) -> dict:
    """qtype ∈ {"email", "domain"}. Returns unified deduplicated timeline."""
    query = (query or "").strip().lower()
    if not query:
        return {"query": query, "type": qtype, "breaches": [], "sources": providers_status()}

    hibp = (hibp_key or "").strip() or _hibp_key()
    rapid = (rapidapi_key or "").strip() or _rapidapi_key()

    async with httpx.AsyncClient() as client:
        tasks = []
        if qtype == "email":
            if hibp:
                tasks.append(_hibp_breachedaccount_with(client, query, hibp))
            if rapid:
                tasks.append(_breachdirectory_lookup_with(client, query, rapid))
        else:  # domain
            if rapid:
                tasks.append(_breachdirectory_lookup_with(client, query, rapid))
        results = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []

    combined: list[dict] = []
    for r in results:
        if isinstance(r, list):
            combined.extend(r)

    sources = providers_status()
    if hibp: sources["hibp"]["configured"] = True
    if rapid: sources["breachdirectory"]["configured"] = True
    return {
        "query": query, "type": qtype, "total": len(combined),
        "breaches": _dedup_and_sort(combined), "sources": sources,
    }


async def _hibp_breachedaccount_with(client, email, key):
    try:
        r = await client.get(
            f"{HIBP_BASE}/breachedaccount/{email}",
            headers={"hibp-api-key": key, "user-agent": "NOCTUA-osint"},
            params={"truncateResponse": "false"}, timeout=12.0,
        )
        if r.status_code == 404: return []
        if r.status_code != 200: return []
        arr = r.json() or []
        return [{
            "source": "HIBP", "name": b.get("Name"), "title": b.get("Title"),
            "domain": b.get("Domain"), "breach_date": b.get("BreachDate"),
            "added_date": b.get("AddedDate"), "pwn_count": b.get("PwnCount"),
            "data_classes": b.get("DataClasses") or [],
            "description": (b.get("Description") or "").strip(),
            "is_verified": b.get("IsVerified"), "is_sensitive": b.get("IsSensitive"),
            "logo_path": b.get("LogoPath"),
        } for b in arr]
    except Exception:
        return []


async def _breachdirectory_lookup_with(client, query, key):
    try:
        r = await client.get(
            "https://breachdirectory.p.rapidapi.com/",
            headers={"X-RapidAPI-Key": key, "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"},
            params={"func": "auto", "term": query}, timeout=15.0,
        )
        if r.status_code != 200: return []
        d = r.json() or {}
        results = d.get("result") or []
        out = []
        for r_ in results:
            out.append({
                "source": "BreachDirectory",
                "name": r_.get("sources", [""])[0] if r_.get("sources") else "unknown",
                "title": ", ".join(r_.get("sources") or []) or "Filtración",
                "breach_date": None,
                "data_classes": [k for k in ("email", "password", "hash", "line") if r_.get(k)],
                "description": f"Registro encontrado. Password hash: {r_.get('has_password') or 'N/A'}",
                "email": r_.get("email"), "password_masked": _mask(r_.get("password")),
                "hash": r_.get("hash"),
            })
        return out
    except Exception:
        return []

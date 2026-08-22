"""CVE Feed en tiempo real — filtra novedades de NVD por el tech stack del usuario.

Consulta el feed público de NVD (últimos N días) y filtra las CVEs cuya
descripción/CPE coincida con las tecnologías detectadas en los scans del usuario.
"""
import asyncio
import logging
from datetime import datetime, timezone, timedelta

import httpx

log = logging.getLogger("cve_feed")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Simple in-process cache — refreshed on-demand (1h TTL)
_feed_cache = {"data": None, "fetched_at": None}


async def _fetch_recent_cves(days: int = 3) -> list[dict]:
    """Fetch CVEs published in the last N days from NVD (max 30 days)."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=min(days, 30))
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as c:
            r = await c.get(NVD_API, params=params)
            r.raise_for_status()
            items = (r.json() or {}).get("vulnerabilities", [])
        cves = []
        for it in items:
            cve = it.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss = None
            severity = None
            for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                mlist = metrics.get(mkey, [])
                if mlist:
                    m0 = mlist[0].get("cvssData", {})
                    cvss = m0.get("baseScore")
                    severity = m0.get("baseSeverity") or mlist[0].get("baseSeverity")
                    break
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:400]
                    break
            cves.append({
                "id": cve.get("id"),
                "published": cve.get("published"),
                "cvss": cvss,
                "severity": (severity or "").lower(),
                "description": desc,
            })
        return cves
    except Exception as e:
        log.warning(f"CVE feed fetch failed: {e}")
        return []


async def _user_tech_keywords(db, user_id: str) -> set[str]:
    """Return the set of tech keywords (lowercased) that appear in the user's scans."""
    from integrations.cve_engine import TECH_TO_CPE
    cursor = db.scans.find({"user_id": user_id},
                             {"_id": 0, "result.tech_analysis": 1,
                              "result.ports.open_ports": 1})
    scans = await cursor.to_list(length=200)
    kws: set[str] = set()
    for s in scans:
        for entry in (s.get("result") or {}).get("tech_analysis") or []:
            server = (entry.get("server") or "").lower()
            for kw in TECH_TO_CPE:
                if kw in server:
                    kws.add(kw)
            for pool in ("cms", "frameworks", "proxies"):
                for i in entry.get(pool) or []:
                    name = (i.get("name") if isinstance(i, dict) else str(i) or "").lower()
                    for kw in TECH_TO_CPE:
                        if kw in name:
                            kws.add(kw)
    return kws


async def user_cve_feed(db, user_id: str, days: int = 7) -> dict:
    """Return filtered CVE feed for the user's tech stack."""
    global _feed_cache
    now = datetime.now(timezone.utc)
    # Cache the raw NVD fetch (per days-bucket) — expensive network call
    cache_key = f"days-{days}"
    cache = _feed_cache.get(cache_key)
    if cache and cache["fetched_at"] and (now - cache["fetched_at"]) < timedelta(hours=1):
        cves = cache["data"]
    else:
        cves = await _fetch_recent_cves(days=days)
        _feed_cache[cache_key] = {"data": cves, "fetched_at": now}

    tech_kws = await _user_tech_keywords(db, user_id)
    if not tech_kws:
        return {
            "generated_at": now.isoformat(),
            "tech_stack_detected": [],
            "days_window": days,
            "total_cves_scanned": len(cves),
            "matched": [],
            "reason": "Ningún tech detectado. Lanza un escaneo primero.",
        }

    matched = []
    for cve in cves:
        desc_lower = (cve.get("description") or "").lower()
        for kw in tech_kws:
            if kw in desc_lower:
                matched.append({**cve, "tech": kw})
                break

    matched.sort(key=lambda c: c.get("cvss") or 0, reverse=True)

    return {
        "generated_at": now.isoformat(),
        "tech_stack_detected": sorted(tech_kws),
        "days_window": days,
        "total_cves_scanned": len(cves),
        "matched_count": len(matched),
        "matched": matched[:50],
        "critical_count": sum(1 for c in matched if c.get("severity") == "critical"),
        "high_count": sum(1 for c in matched if c.get("severity") == "high"),
    }

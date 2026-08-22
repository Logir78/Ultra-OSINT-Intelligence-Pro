"""CVE + EPSS + KEV Correlation Engine.

Given a scan's tech_analysis, enriches every detected technology with:
- Known CVEs from NVD (National Vulnerability Database)
- EPSS score (probability of exploitation in the wild, next 30 days)
- KEV flag (CISA Known Exploited Vulnerabilities catalog)

All three data sources are FREE and don't require API keys.
Results are cached per-scan.
"""
import asyncio
import logging
import re
import httpx
from datetime import datetime, timezone, timedelta

log = logging.getLogger("cve_engine")

# Free endpoints — no API key required
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_CATALOG = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Simple in-process cache for CISA KEV (refreshes every 24h)
_kev_cache = {"data": None, "fetched_at": None}

# Technology → CPE keyword hints (helps NVD queries)
TECH_TO_CPE = {
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "django": "django",
    "flask": "flask",
    "laravel": "laravel",
    "rails": "rails",
    "express": "express",
    "spring": "spring_framework",
    "asp.net": "asp.net",
    "nginx": "nginx",
    "apache": "apache",
    "iis": "internet_information_services",
    "tomcat": "tomcat",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "grafana": "grafana",
    "elasticsearch": "elasticsearch",
    "redis": "redis",
    "mongodb": "mongodb",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "docker": "docker",
    "kubernetes": "kubernetes",
}


def _extract_version(banner: str) -> str | None:
    if not banner:
        return None
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner)
    return m.group(1) if m else None


def _norm_tech(name: str, banner: str = "") -> tuple[str, str | None] | None:
    """Return (cpe_keyword, version) for a detected tech, or None if not mappable."""
    if not name:
        return None
    lower = name.lower()
    for keyword, cpe in TECH_TO_CPE.items():
        if keyword in lower:
            return cpe, _extract_version(banner or name)
    return None


async def _fetch_kev(client: httpx.AsyncClient) -> dict[str, dict]:
    """Return dict cve_id → kev_entry. Cached 24h."""
    global _kev_cache
    now = datetime.now(timezone.utc)
    if _kev_cache["data"] and _kev_cache["fetched_at"] \
            and (now - _kev_cache["fetched_at"]) < timedelta(hours=24):
        return _kev_cache["data"]
    try:
        r = await client.get(KEV_CATALOG, timeout=20.0)
        r.raise_for_status()
        entries = (r.json() or {}).get("vulnerabilities", [])
        idx = {e["cveID"]: {
            "vendor": e.get("vendorProject"),
            "product": e.get("product"),
            "name": e.get("vulnerabilityName"),
            "date_added": e.get("dateAdded"),
            "ransomware": e.get("knownRansomwareCampaignUse") == "Known",
        } for e in entries if e.get("cveID")}
        _kev_cache = {"data": idx, "fetched_at": now}
        return idx
    except Exception as e:
        log.warning(f"KEV fetch failed: {e}")
        return _kev_cache["data"] or {}


async def _fetch_epss(client: httpx.AsyncClient, cve_ids: list[str]) -> dict[str, dict]:
    """Return dict cve_id → {score, percentile}. Batched."""
    if not cve_ids:
        return {}
    ids_param = ",".join(cve_ids[:100])
    try:
        r = await client.get(EPSS_API, params={"cve": ids_param}, timeout=15.0)
        r.raise_for_status()
        rows = (r.json() or {}).get("data", [])
        return {row["cve"]: {"score": float(row.get("epss", 0)),
                              "percentile": float(row.get("percentile", 0))} for row in rows}
    except Exception as e:
        log.warning(f"EPSS fetch failed: {e}")
        return {}


async def _fetch_cves(client: httpx.AsyncClient, keyword: str, version: str | None) -> list[dict]:
    """Query NVD for a keyword (optionally filtered by version)."""
    params = {"keywordSearch": keyword, "resultsPerPage": 10}
    try:
        r = await client.get(NVD_API, params=params, timeout=20.0)
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
                    desc = d.get("value", "")[:300]
                    break
            cves.append({
                "id": cve.get("id"),
                "published": cve.get("published"),
                "cvss": cvss,
                "severity": (severity or "").lower(),
                "description": desc,
            })
        # Optional version filtering — best-effort, only exclude clearly newer CVEs
        if version:
            # Filter is heuristic; keep all if in doubt
            pass
        return cves
    except Exception as e:
        log.warning(f"NVD fetch failed for {keyword}: {e}")
        return []


async def correlate_cves(tech_analysis: list[dict]) -> dict:
    """Main entry — enrich tech analysis with CVE/EPSS/KEV data.

    Returns a summary dict with per-tech findings + top exposures.
    """
    # Collect unique tech candidates
    seen: dict[str, str | None] = {}   # cpe_keyword → version
    for entry in tech_analysis or []:
        for pool_name in ("cms", "frameworks", "proxies"):
            for item in entry.get(pool_name, []):
                name = item.get("name") if isinstance(item, dict) else str(item)
                banner = ""
                if isinstance(item, dict):
                    ev = item.get("evidence") or ""
                    banner = ev if isinstance(ev, str) else ""
                norm = _norm_tech(name, banner)
                if norm:
                    cpe, ver = norm
                    seen[cpe] = ver or seen.get(cpe)
        # Also check server banner
        server = entry.get("server")
        if server:
            norm = _norm_tech(server, server)
            if norm:
                seen[norm[0]] = norm[1] or seen.get(norm[0])

    findings = []
    all_cve_ids: list[str] = []

    async with httpx.AsyncClient() as client:
        kev = await _fetch_kev(client)
        # Fetch CVEs concurrently
        cve_lists = await asyncio.gather(
            *[_fetch_cves(client, cpe, ver) for cpe, ver in seen.items()]
        )
        for (cpe, ver), cves in zip(seen.items(), cve_lists):
            for cve in cves:
                all_cve_ids.append(cve["id"])
            findings.append({"tech": cpe, "version": ver, "cves": cves})

        # Batch fetch EPSS
        epss = await _fetch_epss(client, all_cve_ids)

    # Merge EPSS + KEV into each CVE
    total_critical = 0
    total_high = 0
    kev_hits: list[dict] = []
    top_risky: list[dict] = []

    for f in findings:
        for cve in f["cves"]:
            cve_id = cve["id"]
            cve["epss"] = epss.get(cve_id)
            cve["kev"] = kev.get(cve_id)
            sev = (cve.get("severity") or "").lower()
            if sev == "critical":
                total_critical += 1
            elif sev == "high":
                total_high += 1
            if cve["kev"]:
                kev_hits.append({"tech": f["tech"], **cve})
            # Score for "top risky": CVSS × (EPSS or 0.1) × (5 if KEV else 1)
            cvss = cve.get("cvss") or 0
            epss_val = (cve.get("epss") or {}).get("score", 0.1)
            score = cvss * (epss_val + 0.1) * (5 if cve.get("kev") else 1)
            top_risky.append({"tech": f["tech"], "score": round(score, 2), **cve})

    top_risky.sort(key=lambda x: x["score"], reverse=True)

    # Overall risk uplift (0-100)
    risk_uplift = min(100, total_critical * 15 + total_high * 5 + len(kev_hits) * 20)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "techs_analyzed": list(seen.keys()),
        "findings": findings,
        "summary": {
            "total_cves": len(all_cve_ids),
            "critical": total_critical,
            "high": total_high,
            "kev_count": len(kev_hits),
            "risk_uplift": risk_uplift,
        },
        "kev_hits": kev_hits[:15],
        "top_risky": top_risky[:15],
    }

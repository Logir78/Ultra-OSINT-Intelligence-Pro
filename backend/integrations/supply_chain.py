"""Supply Chain Security — cross-check detected libraries against OSV.dev CVE database."""
import asyncio
import httpx
import re
import logging

log = logging.getLogger("supply_chain")

# Map internal library names to OSV ecosystems (best effort)
ECOSYSTEM_MAP = {
    # npm
    "react": "npm", "vue": "npm", "angular": "npm", "jquery": "npm",
    "lodash": "npm", "axios": "npm", "moment": "npm", "next.js": "npm",
    "next": "npm", "nuxt": "npm", "express": "npm", "webpack": "npm",
    # PHP / Packagist
    "wordpress": "Packagist", "drupal": "Packagist", "joomla": "Packagist",
    # RubyGems
    "rails": "RubyGems",
    # PyPI
    "django": "PyPI", "flask": "PyPI",
    # cms (search all)
}


def _extract_libs(scan_result: dict) -> list[dict]:
    libs = []
    for t in (scan_result.get("tech_analysis") or []):
        host = t.get("hostname", "?")
        for group in ("cms", "frameworks", "libraries"):
            for e in (t.get(group) or []):
                name = (e.get("name") or "").strip()
                ver = (e.get("version") or "").strip()
                if not name or not ver:
                    continue
                eco = ECOSYSTEM_MAP.get(name.lower())
                if not eco:
                    continue  # skip unknown ecosystems to avoid noisy OSV lookups
                libs.append({
                    "name": name, "version": ver, "host": host, "group": group,
                    "ecosystem": eco,
                })
    return libs


async def _query_osv(client: httpx.AsyncClient, lib: dict) -> list[dict]:
    """Query OSV.dev for vulnerabilities affecting this specific version."""
    try:
        r = await client.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": lib["name"].lower(), "ecosystem": lib["ecosystem"]},
                  "version": lib["version"]},
            timeout=8.0,
        )
        if r.status_code != 200:
            return []
        data = r.json()
        vulns = []
        for v in (data.get("vulns") or [])[:15]:
            severity = "medium"
            cvss_score = None
            for s in v.get("severity") or []:
                if s.get("type") == "CVSS_V3" and s.get("score"):
                    # Format: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    # Sometimes just the base score
                    try:
                        cvss_score = float(re.findall(r"\d+\.\d+", s["score"])[0])
                    except Exception:
                        pass
            if cvss_score is not None:
                if cvss_score >= 9.0: severity = "critical"
                elif cvss_score >= 7.0: severity = "high"
                elif cvss_score >= 4.0: severity = "medium"
                else: severity = "low"
            aliases = v.get("aliases") or []
            cves = [a for a in aliases if a.startswith("CVE-")]
            vulns.append({
                "id": v.get("id"),
                "cves": cves[:3],
                "summary": (v.get("summary") or "")[:200],
                "cvss_score": cvss_score,
                "severity": severity,
                "published": v.get("published"),
                "references": [ref.get("url") for ref in (v.get("references") or [])[:3]],
            })
        return vulns
    except Exception as e:
        log.warning(f"OSV query failed for {lib['name']}@{lib['version']}: {e}")
        return []


async def audit_supply_chain(scan_result: dict) -> dict:
    libs = _extract_libs(scan_result)
    if not libs:
        return {
            "libraries_analyzed": 0,
            "total_vulnerabilities": 0,
            "counts_by_severity": {},
            "vulnerable_libraries": [],
            "note": "No se detectaron librerías con versión conocida.",
        }

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*[_query_osv(client, lib) for lib in libs])

    vulnerable = []
    all_vulns = []
    for lib, vulns in zip(libs, results):
        if vulns:
            worst = min(vulns, key=lambda v: {"critical": 0, "high": 1, "medium": 2,
                                                "low": 3, "info": 4}.get(v["severity"], 5))
            vulnerable.append({
                "name": lib["name"],
                "version": lib["version"],
                "host": lib["host"],
                "ecosystem": lib["ecosystem"],
                "worst_severity": worst["severity"],
                "vuln_count": len(vulns),
                "vulnerabilities": vulns,
            })
            all_vulns.extend(vulns)

    counts = {}
    for v in all_vulns:
        counts[v["severity"]] = counts.get(v["severity"], 0) + 1

    # Sort vulnerable libs by worst severity
    vulnerable.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2,
                                     "low": 3, "info": 4}.get(x["worst_severity"], 5))

    return {
        "libraries_analyzed": len(libs),
        "libraries_with_vulns": len(vulnerable),
        "total_vulnerabilities": len(all_vulns),
        "counts_by_severity": counts,
        "vulnerable_libraries": vulnerable,
        "source": "osv.dev",
    }

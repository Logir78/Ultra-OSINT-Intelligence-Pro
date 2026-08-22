"""Certificate Transparency Logs — discover historical subdomains via crt.sh."""
import httpx
import logging
import re

log = logging.getLogger("ct_logs")


async def query_crtsh(domain: str) -> list[str]:
    """Query crt.sh for all certificates that mention *.<domain>."""
    url = "https://crt.sh/"
    params = {"q": f"%25.{domain}", "output": "json"}
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as c:
            r = await c.get(url, params=params, headers={"User-Agent": "NOCTUA-osint"})
        if r.status_code != 200:
            return []
        # crt.sh sometimes returns concatenated JSON lines; be tolerant
        try:
            data = r.json()
        except Exception:
            # Try to salvage
            import json as _json
            data = []
            for line in r.text.strip().splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{") and line.endswith("}"):
                    try:
                        data.append(_json.loads(line))
                    except Exception:
                        pass
        subs: set[str] = set()
        for row in data or []:
            name_value = row.get("name_value") or ""
            for name in name_value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if not name or name == domain:
                    continue
                # Must be a subdomain of the target
                if name.endswith("." + domain) and re.match(r"^[a-z0-9.\-_]+$", name):
                    subs.add(name)
        return sorted(subs)
    except Exception as e:
        log.warning(f"crt.sh query failed for {domain}: {e}")
        return []


async def discover_and_crosscheck(domain: str, active_subdomains: list[dict]) -> dict:
    """Query CT logs and cross-check vs already discovered active subdomains.

    Returns categorized subdomains:
      - active: found by DNS and in CT
      - dns_only: found by DNS but not in CT
      - ct_only: in CT but not resolvable (historical / internal)
    """
    ct_subs = await query_crtsh(domain)
    active_set = {s["subdomain"].lower() for s in (active_subdomains or []) if s.get("subdomain")}

    ct_set = set(ct_subs)
    active_only = active_set - ct_set
    ct_only = ct_set - active_set
    both = active_set & ct_set

    return {
        "domain": domain,
        "source": "crt.sh",
        "ct_total": len(ct_set),
        "dns_active_total": len(active_set),
        "counts": {
            "active_and_ct": len(both),
            "dns_only": len(active_only),
            "ct_only": len(ct_only),
            "combined": len(active_set | ct_set),
        },
        "combined_subdomains": [
            {"subdomain": s,
             "source": "both" if s in both else ("ct_only" if s in ct_only else "dns_only")}
            for s in sorted(active_set | ct_set)
        ],
        "ct_only_sample": sorted(ct_only)[:100],
    }

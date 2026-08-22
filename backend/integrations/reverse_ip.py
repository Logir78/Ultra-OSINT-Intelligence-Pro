"""Reverse IP / IP Neighbors — find sibling domains on same IP + ASN neighborhood."""
import httpx
import re
import logging

log = logging.getLogger("reverse_ip")


async def _hackertarget_reverse_ip(ip: str) -> list[str]:
    """HackerTarget free tier: 50 queries/day per IP."""
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(f"https://api.hackertarget.com/reverseiplookup/",
                            params={"q": ip},
                            headers={"User-Agent": "NOCTUA-osint"})
        if r.status_code != 200:
            return []
        text = r.text.strip()
        # HackerTarget returns "error check your search parameter" or "API count exceeded"
        if not text or text.lower().startswith("error") or "api count exceeded" in text.lower():
            return []
        # Otherwise: newline-separated domains
        domains = []
        for line in text.splitlines():
            line = line.strip().lower().lstrip("*.")
            if line and re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", line):
                domains.append(line)
        return sorted(set(domains))
    except Exception as e:
        log.warning(f"HackerTarget reverse-ip failed for {ip}: {e}")
        return []


async def _rdap_asn_info(ip: str) -> dict:
    """Fetch ASN info from ARIN/RIPE RDAP (free)."""
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(f"https://rdap.arin.net/registry/ip/{ip}",
                            headers={"Accept": "application/rdap+json"},
                            follow_redirects=True)
        if r.status_code != 200:
            return {}
        d = r.json()
        return {
            "handle": d.get("handle"),
            "name": d.get("name"),
            "asn": d.get("startAddress") + " - " + d.get("endAddress") if d.get("startAddress") else None,
            "start_address": d.get("startAddress"),
            "end_address": d.get("endAddress"),
            "cidr0_cidrs": d.get("cidr0_cidrs") or [],
            "country": (d.get("country") or ""),
            "entities": [e.get("handle") for e in (d.get("entities") or [])[:5] if e.get("handle")],
        }
    except Exception as e:
        log.warning(f"RDAP failed for {ip}: {e}")
        return {}


async def find_ip_neighbors(domain: str, ip: str | None) -> dict:
    if not ip:
        return {"domain": domain, "ip": None, "reverse_ip_count": 0,
                "reverse_ip_domains": [], "asn": {}, "note": "El dominio no tiene IP resuelta."}

    neighbors = await _hackertarget_reverse_ip(ip)
    asn = await _rdap_asn_info(ip)

    # Exclude the current domain and its subdomains
    neighbors = [n for n in neighbors if n != domain and not n.endswith("." + domain)]

    # Simple classification: dev/staging keyword heuristic
    interesting = []
    for n in neighbors:
        low = n.lower()
        if any(k in low for k in ("dev", "staging", "test", "beta", "internal",
                                    "admin", "portal", "vpn", "old", "backup",
                                    "legacy", "qa")):
            interesting.append(n)

    return {
        "domain": domain,
        "ip": ip,
        "reverse_ip_count": len(neighbors),
        "reverse_ip_domains": neighbors[:200],
        "interesting_neighbors": interesting[:60],
        "interesting_count": len(interesting),
        "asn": asn,
        "source": "hackertarget + arin_rdap",
    }

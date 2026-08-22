"""Digital DNA Fingerprint — build a unique infrastructure signature and find siblings."""
import hashlib
import httpx
import re
import logging
from typing import Optional

log = logging.getLogger("dna_fingerprint")

SIGNAL_HEADERS = [
    "server", "x-powered-by", "x-generator", "x-drupal-cache", "x-varnish",
    "x-aspnet-version", "x-runtime", "cf-ray", "via", "x-served-by",
]


def _hash(items: list[str]) -> str:
    joined = "|".join(sorted([str(x) for x in items if x]))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:24]


def _extract_lib_versions(scan_result: dict) -> list[str]:
    """Concat detected library versions from tech_analysis."""
    tech = scan_result.get("tech_analysis") or []
    versions = []
    for t in tech:
        for group_key in ("cms", "frameworks", "libraries"):
            for entry in t.get(group_key) or []:
                name = entry.get("name")
                ver = entry.get("version") or ""
                if name:
                    versions.append(f"{name}@{ver}")
        if t.get("server"):
            versions.append(f"server:{t['server']}")
        if t.get("powered_by"):
            versions.append(f"pwd:{t['powered_by']}")
    return versions


def _extract_header_pattern(scan_result: dict) -> list[str]:
    hh = (scan_result.get("https_headers") or {}).get("headers") or {}
    ordered = []
    for k in SIGNAL_HEADERS:
        val = hh.get(k) or hh.get(k.title())
        if val:
            ordered.append(f"{k}:{val[:80]}")
    return ordered


def _extract_dns_pattern(scan_result: dict) -> list[str]:
    dns = scan_result.get("dns") or {}
    pattern = []
    # Include record types in the order they appeared and sample content shape
    for rtype, records in dns.items():
        if not records:
            continue
        pattern.append(f"{rtype}:{len(records)}")
        # Include normalized shapes: NS provider names, MX providers
        if rtype in ("NS", "MX"):
            for rec in records[:5]:
                # normalize (last two labels)
                labels = str(rec).strip(". ").split(".")
                if len(labels) >= 2:
                    pattern.append(f"{rtype}:{labels[-2]}.{labels[-1]}")
    return pattern


def build_fingerprint(scan_result: dict) -> dict:
    """Deterministic infrastructure fingerprint."""
    lib_versions = _extract_lib_versions(scan_result)
    header_pattern = _extract_header_pattern(scan_result)
    dns_pattern = _extract_dns_pattern(scan_result)
    ssl_issuer = ((scan_result.get("ssl") or {}).get("issuer") or {}).get("organizationName") or ""
    tls_ver = (scan_result.get("ssl") or {}).get("tls_version") or ""

    components = {
        "libs": lib_versions,
        "headers": header_pattern,
        "dns": dns_pattern,
        "ssl": [ssl_issuer, tls_ver],
    }

    fingerprint_hash = _hash(
        lib_versions + header_pattern + dns_pattern + [ssl_issuer, tls_ver]
    )
    components_hash = {
        "libs": _hash(lib_versions),
        "headers": _hash(header_pattern),
        "dns": _hash(dns_pattern),
        "ssl": _hash([ssl_issuer, tls_ver]),
    }
    return {
        "fingerprint": fingerprint_hash,
        "components": components,
        "components_hash": components_hash,
    }


async def find_siblings(scan_result: dict, shodan_key: Optional[str] = None) -> dict:
    """Search for other assets that share the same fingerprint signals.

    Uses free/passive signals:
      - crt.sh org search: fetch certificates issued to the same organization
      - Shodan http.html_hash / http.title search (if key provided)
    """
    fp = build_fingerprint(scan_result)
    siblings: list[dict] = []
    signals_used: list[str] = []

    # Signal 1: WHOIS org / registrant → crt.sh
    whois = (scan_result.get("whois") or {}).get("data") or {}
    org = None
    for key in ("org", "organization", "registrant_organization", "registrant_name"):
        v = whois.get(key)
        if v:
            org = v[0] if isinstance(v, list) else v
            break
    if org and isinstance(org, str) and len(org) > 3:
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get("https://crt.sh/",
                                params={"q": f"O={org}", "output": "json"},
                                headers={"User-Agent": "NOCTUA-osint"})
            if r.status_code == 200:
                data = r.json()
                seen_domains: set[str] = set()
                own_domain = scan_result.get("domain", "")
                for row in (data or [])[:200]:
                    name = (row.get("name_value") or "").split("\n")[0].strip().lstrip("*.").lower()
                    if not name or name == own_domain:
                        continue
                    if name.endswith("." + own_domain):
                        continue  # subdomain of ourselves
                    if not re.match(r"^[a-z0-9.\-]+$", name):
                        continue
                    if name not in seen_domains:
                        seen_domains.add(name)
                        siblings.append({
                            "asset": name, "kind": "domain",
                            "signal": "same_org_certificate",
                            "evidence": f"O={org[:80]}",
                        })
                signals_used.append(f"crt.sh:O={org[:60]}")
        except Exception as e:
            log.warning(f"crt.sh org search failed: {e}")

    # Signal 2: Shodan http.html_hash — if we have a Shodan key AND main IP has html_hash
    ips = [scan_result.get("ip", {}).get("ip")] if scan_result.get("ip") else []
    if shodan_key and ips[0]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as c:
                # Get the html_hash for our own site first
                r = await c.get(f"https://api.shodan.io/shodan/host/{ips[0]}",
                                params={"key": shodan_key})
                if r.status_code == 200:
                    d = r.json()
                    html_hashes = set()
                    for svc in d.get("data", []) or []:
                        h = (svc.get("http") or {}).get("html_hash")
                        if h:
                            html_hashes.add(h)
                    for h in list(html_hashes)[:2]:
                        s = await c.get("https://api.shodan.io/shodan/host/search",
                                        params={"key": shodan_key, "query": f"http.html_hash:{h}", "limit": 20})
                        if s.status_code == 200:
                            sdata = s.json()
                            for match in sdata.get("matches", [])[:20]:
                                asset_ip = match.get("ip_str")
                                hostnames = match.get("hostnames") or []
                                asset = hostnames[0] if hostnames else asset_ip
                                if not asset or asset == scan_result.get("domain"):
                                    continue
                                siblings.append({
                                    "asset": asset, "kind": "host" if not hostnames else "domain",
                                    "signal": "shodan_html_hash",
                                    "evidence": f"html_hash={h}",
                                })
                        signals_used.append(f"shodan:html_hash={h}")
        except Exception as e:
            log.warning(f"shodan html_hash search failed: {e}")

    # Dedupe siblings
    seen = set()
    unique = []
    for s in siblings:
        k = (s["asset"], s["signal"])
        if k not in seen:
            seen.add(k)
            unique.append(s)

    return {
        "fingerprint": fp["fingerprint"],
        "components_hash": fp["components_hash"],
        "components": {k: v[:15] for k, v in fp["components"].items()},
        "signals_used": signals_used,
        "siblings": unique[:80],
        "sibling_count": len(unique),
    }

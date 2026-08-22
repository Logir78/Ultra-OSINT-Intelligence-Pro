"""Scan Delta — compare two scans of the same domain and highlight changes."""
from datetime import datetime, timezone
import logging

log = logging.getLogger("scan_delta")


def _extract_ports(scan: dict) -> set[int]:
    return {p["port"] for p in ((scan.get("ports") or {}).get("open_ports") or [])}


def _extract_subdomains(scan: dict) -> set[str]:
    return {s["subdomain"] for s in ((scan.get("subdomains") or {}).get("found") or [])}


def _extract_ip(scan: dict) -> str | None:
    return (scan.get("ip") or {}).get("ip")


def _extract_tls(scan: dict) -> str | None:
    return (scan.get("ssl") or {}).get("tls_version")


def _extract_headers(scan: dict) -> dict:
    return (scan.get("https_headers") or {}).get("headers") or {}


def _extract_tech(scan: dict) -> dict[str, str]:
    """{name: version} across all hosts."""
    out = {}
    for t in (scan.get("tech_analysis") or []):
        for group in ("cms", "frameworks", "libraries"):
            for e in (t.get(group) or []):
                name = e.get("name")
                if name:
                    out[name] = e.get("version") or ""
        if t.get("server"):
            out[f"server:{t.get('hostname', '?')}"] = t["server"]
    return out


def compute_diff(previous: dict, current: dict) -> dict:
    """Compute a rich diff between two scan documents.
    Args are the full scan docs from Mongo; result read from doc["result"].
    """
    prev_r = previous.get("result") or {}
    cur_r  = current.get("result") or {}

    # Ports
    prev_ports = _extract_ports(prev_r)
    cur_ports  = _extract_ports(cur_r)
    ports_added   = sorted(cur_ports - prev_ports)
    ports_removed = sorted(prev_ports - cur_ports)

    # Subdomains
    prev_subs = _extract_subdomains(prev_r)
    cur_subs  = _extract_subdomains(cur_r)
    subs_added   = sorted(cur_subs - prev_subs)
    subs_removed = sorted(prev_subs - cur_subs)

    # IP
    ip_change = None
    if _extract_ip(prev_r) != _extract_ip(cur_r):
        ip_change = {"from": _extract_ip(prev_r), "to": _extract_ip(cur_r)}

    # TLS
    tls_change = None
    if _extract_tls(prev_r) != _extract_tls(cur_r):
        tls_change = {"from": _extract_tls(prev_r), "to": _extract_tls(cur_r)}

    # Tech versions
    prev_tech = _extract_tech(prev_r)
    cur_tech  = _extract_tech(cur_r)
    tech_added   = {k: v for k, v in cur_tech.items() if k not in prev_tech}
    tech_removed = {k: v for k, v in prev_tech.items() if k not in cur_tech}
    tech_changed = []
    for k in set(prev_tech) & set(cur_tech):
        if prev_tech[k] != cur_tech[k]:
            tech_changed.append({"name": k, "from": prev_tech[k], "to": cur_tech[k]})

    # Headers — only track presence of critical security headers
    critical_headers = ["strict-transport-security", "content-security-policy",
                        "x-frame-options", "x-content-type-options",
                        "referrer-policy", "permissions-policy"]
    prev_h = {k.lower() for k in _extract_headers(prev_r)}
    cur_h  = {k.lower() for k in _extract_headers(cur_r)}
    headers_lost = sorted([h for h in critical_headers if h in prev_h and h not in cur_h])
    headers_added = sorted([h for h in critical_headers if h in cur_h and h not in prev_h])

    # Severity of the diff overall
    severity = "low"
    if ports_added and any(p in {21, 22, 23, 445, 3306, 3389, 5432, 6379, 9200, 27017} for p in ports_added):
        severity = "critical"
    elif ports_added or subs_added or headers_lost:
        severity = "high"
    elif tech_changed or tls_change:
        severity = "medium"

    changed = any([ports_added, ports_removed, subs_added, subs_removed,
                   tech_added, tech_removed, tech_changed, headers_added,
                   headers_lost, ip_change, tls_change])

    return {
        "previous_scan_id": previous.get("scan_id"),
        "previous_scan_at": previous.get("created_at"),
        "current_scan_id":  current.get("scan_id"),
        "current_scan_at":  current.get("created_at"),
        "domain":           cur_r.get("domain") or prev_r.get("domain"),
        "changed": changed,
        "severity": severity,
        "ports": {"added": ports_added, "removed": ports_removed,
                  "prev_count": len(prev_ports), "current_count": len(cur_ports)},
        "subdomains": {"added": subs_added[:100], "removed": subs_removed[:100],
                       "prev_count": len(prev_subs), "current_count": len(cur_subs)},
        "tech": {"added": tech_added, "removed": tech_removed, "changed": tech_changed},
        "ip_change": ip_change,
        "tls_change": tls_change,
        "security_headers": {"lost": headers_lost, "gained": headers_added},
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

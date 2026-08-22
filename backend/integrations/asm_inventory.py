"""ASM (Attack Surface Management) — Inventory + Drift Detection.

Aggregates all unique assets (subdomains, IPs, ports, technologies) across a
user's scan history to build an authoritative asset inventory. Detects drift
(new/removed/changed assets) between scans of the same domain.
"""
from datetime import datetime, timezone, timedelta
from typing import Any


async def compute_inventory(db, user_id: str) -> dict[str, Any]:
    """Aggregate every unique asset across the user's scans."""
    cursor = db.scans.find(
        {"user_id": user_id},
        {"_id": 0, "scan_id": 1, "domain": 1, "created_at": 1,
         "result.ip.ip": 1, "result.subdomains.found": 1,
         "result.ports.open_ports": 1, "result.tech_analysis": 1},
    ).sort("created_at", -1)
    scans = await cursor.to_list(length=500)

    domains: dict[str, dict] = {}   # domain -> {first_seen, last_seen, scan_ids}
    subdomains: dict[str, dict] = {}
    ips: dict[str, dict] = {}
    ports: dict[tuple, dict] = {}   # (ip, port) -> {...}
    techs: dict[str, dict] = {}

    for s in scans:
        d = s.get("domain")
        sid = s.get("scan_id")
        at = s.get("created_at") or ""
        if not d:
            continue

        slot = domains.setdefault(d, {"asset": d, "kind": "domain",
                                        "first_seen": at, "last_seen": at,
                                        "scan_ids": []})
        slot["scan_ids"] = list({*slot["scan_ids"], sid})[:5]
        slot["first_seen"] = min(slot["first_seen"], at) if slot["first_seen"] else at
        slot["last_seen"] = max(slot["last_seen"], at)

        result = s.get("result") or {}
        # Subdomains
        for sub in ((result.get("subdomains") or {}).get("found") or []):
            host = sub.get("hostname") if isinstance(sub, dict) else str(sub)
            if not host:
                continue
            slot = subdomains.setdefault(host, {"asset": host, "kind": "subdomain",
                                                  "parent": d, "first_seen": at,
                                                  "last_seen": at, "scan_ids": []})
            slot["scan_ids"] = list({*slot["scan_ids"], sid})[:5]
            slot["first_seen"] = min(slot["first_seen"], at)
            slot["last_seen"] = max(slot["last_seen"], at)

        # IPs
        ip = (result.get("ip") or {}).get("ip")
        if ip:
            slot = ips.setdefault(ip, {"asset": ip, "kind": "ip",
                                          "parent": d, "first_seen": at,
                                          "last_seen": at, "scan_ids": []})
            slot["scan_ids"] = list({*slot["scan_ids"], sid})[:5]
            slot["last_seen"] = max(slot["last_seen"], at)

            # Ports on this IP
            for p in (result.get("ports") or {}).get("open_ports") or []:
                port = p.get("p") if isinstance(p, dict) else int(p)
                if not port:
                    continue
                key = (ip, port)
                slot = ports.setdefault(key, {"asset": f"{ip}:{port}", "kind": "port",
                                                "parent": d, "first_seen": at,
                                                "last_seen": at, "scan_ids": []})
                slot["last_seen"] = max(slot["last_seen"], at)

        # Techs
        for entry in result.get("tech_analysis") or []:
            for pool in ("cms", "frameworks", "proxies"):
                for item in entry.get(pool) or []:
                    name = item.get("name") if isinstance(item, dict) else str(item)
                    if not name:
                        continue
                    key = f"{name}@{entry.get('hostname', '?')}"
                    slot = techs.setdefault(key, {"asset": name,
                                                    "kind": "tech",
                                                    "host": entry.get("hostname"),
                                                    "parent": d,
                                                    "first_seen": at,
                                                    "last_seen": at,
                                                    "scan_ids": []})
                    slot["last_seen"] = max(slot["last_seen"], at)

    all_assets = (list(domains.values()) + list(subdomains.values())
                   + list(ips.values()) + list(ports.values()) + list(techs.values()))
    all_assets.sort(key=lambda a: a["last_seen"], reverse=True)

    # New in last 7d
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    new_recent = [a for a in all_assets if a["first_seen"] >= week_ago]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "domains": len(domains),
            "subdomains": len(subdomains),
            "ips": len(ips),
            "open_ports": len(ports),
            "technologies": len(techs),
            "total": len(all_assets),
        },
        "new_in_last_7d": len(new_recent),
        "recently_added": new_recent[:30],
        "all_assets": all_assets[:500],
    }


async def compute_drift(db, user_id: str, domain: str) -> dict[str, Any]:
    """Compare the two most recent scans of the same domain — added/removed subdomains."""
    cursor = db.scans.find(
        {"user_id": user_id, "domain": domain},
        {"_id": 0, "scan_id": 1, "created_at": 1,
         "result.subdomains.found": 1, "result.ports.open_ports": 1,
         "result.tech_analysis": 1},
    ).sort("created_at", -1).limit(2)
    scans = await cursor.to_list(length=2)
    if len(scans) < 2:
        return {"ok": False, "reason": "Necesitas al menos 2 scans del mismo dominio",
                "domain": domain, "scans_available": len(scans)}

    newer, older = scans[0], scans[1]

    def _subs(scan):
        return {s.get("hostname") if isinstance(s, dict) else s
                for s in ((scan.get("result") or {}).get("subdomains") or {}).get("found") or []
                if (s.get("hostname") if isinstance(s, dict) else s)}

    def _ports(scan):
        return {(p.get("p") if isinstance(p, dict) else p)
                for p in ((scan.get("result") or {}).get("ports") or {}).get("open_ports") or []}

    def _techs(scan):
        out = set()
        for e in (scan.get("result") or {}).get("tech_analysis") or []:
            for pool in ("cms", "frameworks", "proxies"):
                for i in e.get(pool) or []:
                    n = i.get("name") if isinstance(i, dict) else str(i)
                    if n:
                        out.add(n)
        return out

    subs_new, subs_old = _subs(newer), _subs(older)
    ports_new, ports_old = _ports(newer), _ports(older)
    techs_new, techs_old = _techs(newer), _techs(older)

    return {
        "ok": True,
        "domain": domain,
        "newer": {"scan_id": newer["scan_id"], "at": newer["created_at"]},
        "older": {"scan_id": older["scan_id"], "at": older["created_at"]},
        "subdomains": {
            "added": sorted(subs_new - subs_old),
            "removed": sorted(subs_old - subs_new),
            "stable": len(subs_new & subs_old),
        },
        "ports": {
            "added": sorted(ports_new - ports_old),
            "removed": sorted(ports_old - ports_new),
        },
        "technologies": {
            "added": sorted(techs_new - techs_old),
            "removed": sorted(techs_old - techs_new),
        },
        "has_changes": bool((subs_new ^ subs_old) or (ports_new ^ ports_old)
                             or (techs_new ^ techs_old)),
    }

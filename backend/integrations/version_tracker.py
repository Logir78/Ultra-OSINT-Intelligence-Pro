"""Version Tracker — detect software rollbacks (old vulnerable version reappears)."""
from datetime import datetime, timezone
import re
import logging

log = logging.getLogger("version_tracker")


def _semver_key(v: str) -> tuple:
    """Parse version string into comparable tuple; returns (0,) if unparseable."""
    if not v:
        return (0,)
    parts = re.findall(r"\d+", v)[:4]
    if not parts:
        return (0,)
    return tuple(int(x) for x in parts)


def _extract_versions(scan_result: dict) -> dict[str, str]:
    """{ 'jquery': '3.6.0', 'wordpress': '6.2.0', 'server:host': 'nginx/1.20.1' }"""
    out = {}
    for t in (scan_result.get("tech_analysis") or []):
        host = t.get("hostname", "?")
        for group in ("cms", "frameworks", "libraries"):
            for e in (t.get(group) or []):
                name = (e.get("name") or "").lower()
                ver = e.get("version") or ""
                if name and ver:
                    out[name] = ver
        if t.get("server"):
            out[f"server:{host}"] = t["server"]
    return out


async def check_rollbacks(db, domain: str, current_scan_id: str,
                          current_result: dict, user_id: str) -> dict:
    """Compare the current scan's software versions against past scans of the same domain.

    Returns:
      - upgrades: version went UP (good)
      - downgrades: version went DOWN (potential ROLLBACK, potentially vulnerable)
      - unchanged: same version detected across scans
    """
    current_versions = _extract_versions(current_result)
    if not current_versions:
        return {"tracked_products": 0, "downgrades": [], "upgrades": [],
                "history_scans": 0, "note": "No se detectaron versiones en el escaneo actual."}

    # Load history for this domain + user
    history = []
    async for prev in db.scans.find(
        {"user_id": user_id, "result.domain": domain, "scan_id": {"$ne": current_scan_id}},
        {"_id": 0, "scan_id": 1, "created_at": 1, "result.tech_analysis": 1},
    ).sort("created_at", -1).limit(20):
        history.append(prev)

    downgrades = []
    upgrades = []

    for name, cur_ver in current_versions.items():
        cur_key = _semver_key(cur_ver)
        # Find the max version observed historically
        max_prev_ver = None
        max_prev_scan = None
        for prev in history:
            prev_versions = _extract_versions({"tech_analysis": prev["result"]["tech_analysis"]})
            pv = prev_versions.get(name)
            if not pv:
                continue
            if max_prev_ver is None or _semver_key(pv) > _semver_key(max_prev_ver):
                max_prev_ver = pv
                max_prev_scan = prev
        if not max_prev_ver:
            continue
        prev_key = _semver_key(max_prev_ver)
        if cur_key < prev_key:
            downgrades.append({
                "product": name,
                "previous_version": max_prev_ver,
                "current_version": cur_ver,
                "previous_scan_at": max_prev_scan.get("created_at") if max_prev_scan else None,
                "severity": "high",
                "note": "Posible ROLLBACK — versión anterior mayor detectada previamente."
            })
        elif cur_key > prev_key:
            upgrades.append({
                "product": name,
                "previous_version": max_prev_ver,
                "current_version": cur_ver,
            })

    return {
        "domain": domain,
        "tracked_products": len(current_versions),
        "history_scans": len(history),
        "downgrades": downgrades,
        "upgrades": upgrades,
        "downgrade_alert": len(downgrades) > 0,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

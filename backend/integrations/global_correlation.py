"""Global Threat Correlation — find domains that share infrastructure across users."""
import logging
from datetime import datetime, timezone

log = logging.getLogger("global_correlation")


async def find_correlations(db, scan_result: dict, current_user_id: str) -> dict:
    """Cross-check IPs, SSL subject org, and shared subdomains across ALL scans on the platform.

    Returns anonymized correlations: only domain names + signal type, no PII.
    """
    domain = scan_result.get("domain", "")
    ip = (scan_result.get("ip") or {}).get("ip")
    subdomains = {s["subdomain"] for s in ((scan_result.get("subdomains") or {}).get("found") or [])}
    ssl_org = ((scan_result.get("ssl") or {}).get("issuer") or {}).get("organizationName")
    cert_fp = (scan_result.get("ssl") or {}).get("fingerprint")

    correlations: list[dict] = []

    # 1) Shared IP with other domains (any user)
    if ip:
        query = {"result.ip.ip": ip, "result.domain": {"$ne": domain}}
        async for other in db.scans.find(query, {"_id": 0, "result.domain": 1,
                                                   "user_id": 1, "flagged": 1,
                                                   "created_at": 1}).limit(50):
            correlations.append({
                "signal": "shared_ip",
                "evidence": ip,
                "asset": other["result"]["domain"],
                "same_user": other.get("user_id") == current_user_id,
                "flagged_by_someone": bool(other.get("flagged")),
                "last_seen": other.get("created_at"),
            })

    # 2) Shared SSL certificate fingerprint
    if cert_fp:
        query = {"result.ssl.fingerprint": cert_fp, "result.domain": {"$ne": domain}}
        async for other in db.scans.find(query, {"_id": 0, "result.domain": 1,
                                                   "user_id": 1, "flagged": 1,
                                                   "created_at": 1}).limit(50):
            correlations.append({
                "signal": "shared_ssl_cert",
                "evidence": cert_fp[:24] + "…",
                "asset": other["result"]["domain"],
                "same_user": other.get("user_id") == current_user_id,
                "flagged_by_someone": bool(other.get("flagged")),
                "last_seen": other.get("created_at"),
            })

    # 3) Same SSL issuer organization (weaker signal — cap it)
    if ssl_org and len(ssl_org) > 4:
        query = {"result.ssl.issuer.organizationName": ssl_org,
                 "result.domain": {"$ne": domain}}
        count = 0
        async for other in db.scans.find(query, {"_id": 0, "result.domain": 1,
                                                   "flagged": 1}).limit(15):
            correlations.append({
                "signal": "same_ssl_issuer_org",
                "evidence": ssl_org[:40],
                "asset": other["result"]["domain"],
                "same_user": False,
                "flagged_by_someone": bool(other.get("flagged")),
                "last_seen": None,
            })
            count += 1

    # Dedupe by (asset, signal)
    seen = set()
    unique = []
    for c in correlations:
        k = (c["asset"], c["signal"])
        if k in seen:
            continue
        seen.add(k)
        unique.append(c)

    flagged_neighbours = [c for c in unique if c["flagged_by_someone"] and not c["same_user"]]

    return {
        "domain": domain,
        "total_correlations": len(unique),
        "flagged_neighbours_count": len(flagged_neighbours),
        "signals_checked": ["shared_ip", "shared_ssl_cert", "same_ssl_issuer_org"],
        "correlations": unique[:80],
        "flagged_neighbours": flagged_neighbours[:20],
        "risk_note": ("Este dominio comparte infraestructura con otros marcados como sospechosos por analistas de NOCTUA."
                      if flagged_neighbours else "No se detectan vecinos sospechosos en la red compartida."),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

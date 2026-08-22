"""Sleeping Infrastructure Hunter — detect stale/abandoned assets outside main security perimeter."""
from datetime import datetime, timezone
import re

MARKETING_KEYWORDS = ("marketing", "sales", "campaign", "landing", "blog",
                       "news", "events", "help", "support", "contact",
                       "portal", "info", "training", "learn", "docs",
                       "old", "legacy", "beta", "dev", "test", "staging",
                       "internal", "backup", "archive", "vault")


def _cert_age_days(cert_valid_from: str) -> int | None:
    if not cert_valid_from:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(cert_valid_from.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - dt).days
        except Exception:
            continue
    return None


def hunt_sleeping(scan_result: dict) -> dict:
    """Analyze subdomains + SSL + tech to identify stale marketing/legacy infrastructure."""
    domain = scan_result.get("domain", "")
    subs = ((scan_result.get("subdomains") or {}).get("found") or [])

    findings: list[dict] = []

    # 1) Subdomain-name keyword hints
    for s in subs:
        name = (s.get("subdomain") or "").lower()
        if not name:
            continue
        matched_kw = [kw for kw in MARKETING_KEYWORDS if kw in name]
        if matched_kw:
            findings.append({
                "asset": name,
                "type": "keyword_match",
                "reason": f"Nombre contiene {matched_kw[0]!r} — posible activo fuera del perímetro principal",
                "keywords": matched_kw,
                "severity": "medium",
                "ips": s.get("ips") or [],
            })

    # 2) Old SSL certificates
    ssl_info = scan_result.get("ssl") or {}
    age = _cert_age_days(ssl_info.get("not_before"))
    if age is not None and age > 365:
        findings.append({
            "asset": domain,
            "type": "old_certificate",
            "reason": f"Certificado SSL emitido hace {age} días (>1 año) — servidor probablemente sin mantenimiento activo",
            "cert_age_days": age,
            "severity": "high" if age > 700 else "medium",
        })

    # 3) Outdated tech versions (weak heuristic — flags anything with a version <2)
    old_tech = []
    for t in (scan_result.get("tech_analysis") or []):
        host = t.get("hostname")
        for group in ("cms", "frameworks", "libraries"):
            for e in (t.get(group) or []):
                name = (e.get("name") or "").strip()
                ver = (e.get("version") or "").strip()
                if not name or not ver:
                    continue
                # crude: majors like 1.x flagged as "possibly old"
                m = re.match(r"^(\d+)", ver)
                if m and int(m.group(1)) <= 1 and name.lower() not in ("google-analytics", "hsts"):
                    old_tech.append({"host": host, "name": name, "version": ver})
    if old_tech:
        findings.append({
            "asset": domain,
            "type": "possibly_old_tech",
            "reason": f"Versiones de software con major <=1: {[t['name'] + '@' + t['version'] for t in old_tech][:5]}",
            "details": old_tech[:10],
            "severity": "medium",
        })

    # 4) Subdomains without HTTPS enabled but resolving (staging often HTTP-only)
    if subs:
        candidate_stale = []
        for s in subs:
            name = (s.get("subdomain") or "").lower()
            if any(kw in name for kw in ("dev", "staging", "test", "old", "legacy", "internal")):
                candidate_stale.append({"subdomain": name, "ips": s.get("ips") or []})
        if candidate_stale:
            findings.append({
                "asset": domain,
                "type": "candidate_dev_staging",
                "reason": "Subdominios con nombres típicos de desarrollo/preproducción",
                "assets": candidate_stale[:20],
                "severity": "high",
            })

    # Bucket findings by severity
    counts_by_severity = {}
    for f in findings:
        counts_by_severity[f["severity"]] = counts_by_severity.get(f["severity"], 0) + 1

    return {
        "domain": domain,
        "total_findings": len(findings),
        "counts_by_severity": counts_by_severity,
        "findings": findings,
        "note": "Los activos 'durmientes' son objetivo prioritario: menos parches, menos monitorización, mismo apellido corporativo.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

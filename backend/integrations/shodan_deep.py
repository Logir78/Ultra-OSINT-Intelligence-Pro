"""Shodan Deep Scan — full TCP/UDP port inventory + CVE tagging + no-auth flags."""
import httpx
import logging

log = logging.getLogger("shodan_deep")

# Services that are catastrophic when exposed without auth
CRITICAL_UNAUTH_SERVICES = {
    "redis":            {"port": 6379,  "flag": "Redis sin AUTH expuesto"},
    "mongodb":          {"port": 27017, "flag": "MongoDB sin authSource expuesto"},
    "elasticsearch":    {"port": 9200,  "flag": "Elasticsearch sin auth expuesto"},
    "memcached":        {"port": 11211, "flag": "Memcached expuesto"},
    "kibana":           {"port": 5601,  "flag": "Kibana sin auth"},
    "docker":           {"port": 2375,  "flag": "Docker API sin TLS expuesto"},
    "vnc":              {"port": 5900,  "flag": "VNC sin password"},
    "rdp":              {"port": 3389,  "flag": "RDP expuesto"},
    "smb":              {"port": 445,   "flag": "SMB expuesto (potencial EternalBlue)"},
    "cassandra":        {"port": 9042,  "flag": "Cassandra sin auth"},
    "influxdb":         {"port": 8086,  "flag": "InfluxDB sin auth"},
    "rethinkdb":        {"port": 28015, "flag": "RethinkDB sin auth"},
    "ftp":              {"port": 21,    "flag": "FTP (protocolo no cifrado)"},
    "telnet":           {"port": 23,    "flag": "Telnet (protocolo no cifrado)"},
}

# Well-known noisy ports (informational)
STANDARD_WEB = {80, 443, 8080, 8443}
STANDARD_MAIL = {25, 465, 587, 993, 995, 143, 110}


def _classify_service(port: int, product: str | None, banner: str) -> tuple[str | None, str | None]:
    """Return (service_key, flag_reason) if the service is critical/notable."""
    banner_low = (banner or "").lower()
    prod_low = (product or "").lower()

    for key, meta in CRITICAL_UNAUTH_SERVICES.items():
        if port == meta["port"]:
            # Look for auth hints in the banner
            if key == "redis" and "noauth" in banner_low.replace(" ", ""):
                return key, "Redis con NOAUTH confirmado (crítico)"
            if key == "mongodb" and ("unauthorized" not in banner_low):
                return key, meta["flag"]
            return key, meta["flag"]
        if key in prod_low:
            return key, meta["flag"]
    return None, None


def _tier(port: int) -> str:
    if port in STANDARD_WEB:
        return "web"
    if port in STANDARD_MAIL:
        return "mail"
    if port in {22}:
        return "admin"
    return "other"


async def _host_lookup(client: httpx.AsyncClient, ip: str, key: str) -> dict:
    try:
        r = await client.get(f"https://api.shodan.io/shodan/host/{ip}",
                             params={"key": key, "minify": False}, timeout=20.0)
        if r.status_code == 404:
            return {"ip": ip, "found": False, "services": [], "ports": [], "vulns": []}
        if r.status_code != 200:
            return {"ip": ip, "found": False, "error": f"HTTP {r.status_code}: {r.text[:120]}"}
        d = r.json()
        services = []
        alerts = []
        for svc in d.get("data", []) or []:
            port = svc.get("port")
            transport = svc.get("transport", "tcp")
            product = svc.get("product")
            version = svc.get("version")
            banner = (svc.get("data") or "")[:400]
            vulns = list((svc.get("vulns") or {}).keys()) if isinstance(svc.get("vulns"), dict) else (svc.get("vulns") or [])
            svc_key, flag = _classify_service(port, product, banner)
            severity = "info"
            if svc_key:
                severity = "critical"
            elif vulns:
                severity = "high"
            services.append({
                "port": port, "transport": transport,
                "product": product, "version": version,
                "banner_sample": banner[:200],
                "tier": _tier(port),
                "service_kind": svc_key,
                "vulns": vulns,
                "severity": severity,
                "unauth_flag": flag,
            })
            if flag:
                alerts.append({"port": port, "service": svc_key, "flag": flag,
                               "severity": "critical", "ip": ip})
            for cve in vulns:
                alerts.append({"port": port, "cve": cve, "product": product,
                               "severity": "high", "ip": ip})
        return {
            "ip": ip, "found": True,
            "hostnames": d.get("hostnames", []),
            "org": d.get("org"), "isp": d.get("isp"),
            "os": d.get("os"), "country_code": d.get("country_code"),
            "last_update": d.get("last_update"),
            "ports": sorted(d.get("ports", []) or []),
            "vulns": list(d.get("vulns", [])) if d.get("vulns") else [],
            "services": services,
            "alerts": alerts,
        }
    except Exception as e:
        return {"ip": ip, "found": False, "error": str(e)}


async def deep_scan(ips: list[str], user_key: str | None) -> dict:
    key = (user_key or "").strip()
    if not key:
        return {"configured": False, "hosts": [], "total_alerts": 0,
                "critical_count": 0, "unique_ports": []}
    if not ips:
        return {"configured": True, "hosts": [], "total_alerts": 0,
                "critical_count": 0, "unique_ports": []}
    async with httpx.AsyncClient() as client:
        hosts = []
        for ip in ips[:5]:  # cap to 5 IPs to be nice with credits
            hosts.append(await _host_lookup(client, ip, key))
    all_alerts = [a for h in hosts for a in (h.get("alerts") or [])]
    critical = [a for a in all_alerts if a.get("severity") == "critical"]
    return {
        "configured": True,
        "hosts": hosts,
        "total_alerts": len(all_alerts),
        "critical_count": len(critical),
        "unique_ports": sorted({p for h in hosts for p in (h.get("ports") or [])}),
    }

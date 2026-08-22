"""IP geolocation using ip-api.com batch endpoint (free, no API key, up to 100 IPs per call)."""
import httpx
import logging

log = logging.getLogger("geoip")

_FIELDS = "status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query"


def _flag_emoji(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        return ""
    return "".join(chr(ord(c.upper()) + 127397) for c in country_code)


async def geolocate_scan(scan_result: dict) -> list[dict]:
    """Extract unique IPs from a scan result and geolocate them all in one batch."""
    ip_map: dict[str, list[str]] = {}
    main_ip = (scan_result.get("ip") or {}).get("ip")
    if main_ip:
        ip_map.setdefault(main_ip, []).append(scan_result.get("domain", "main"))

    for sub in (scan_result.get("subdomains") or {}).get("found", []):
        for ip in sub.get("ips", []):
            ip_map.setdefault(ip, []).append(sub["subdomain"])

    if not ip_map:
        return []

    unique_ips = list(ip_map.keys())[:100]
    payload = [{"query": ip, "fields": _FIELDS} for ip in unique_ips]

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post("http://ip-api.com/batch", json=payload)
            arr = r.json() if r.status_code == 200 else []
    except Exception as e:
        log.warning(f"ip-api.com batch failed: {e}")
        arr = []

    out = []
    for i, item in enumerate(arr):
        ip = item.get("query") or unique_ips[i]
        ok = item.get("status") == "success"
        cc = item.get("countryCode") or ""
        out.append({
            "ip": ip,
            "success": ok,
            "error": None if ok else item.get("message", "lookup failed"),
            "country": item.get("country") if ok else None,
            "country_code": cc if ok else None,
            "region": item.get("regionName") if ok else None,
            "city": item.get("city") if ok else None,
            "latitude": item.get("lat") if ok else None,
            "longitude": item.get("lon") if ok else None,
            "isp": item.get("isp") if ok else None,
            "asn": item.get("as") if ok else None,
            "org": item.get("org") if ok else None,
            "timezone": item.get("timezone") if ok else None,
            "flag": _flag_emoji(cc) if ok else "",
            "hostnames": ip_map.get(ip, []),
        })
    # Fill in any IPs missing from response
    seen = {o["ip"] for o in out}
    for ip in unique_ips:
        if ip not in seen:
            out.append({"ip": ip, "success": False, "error": "no response",
                        "hostnames": ip_map.get(ip, [])})
    return out

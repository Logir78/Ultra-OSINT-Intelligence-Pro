"""AbuseIPDB integration — IP reputation lookup.
Docs: https://docs.abuseipdb.com/#check-endpoint
Free tier: 1,000 checks/day.
"""
import os
import asyncio
import httpx
import logging

log = logging.getLogger("abuseipdb")

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
KEY_URL = "https://www.abuseipdb.com/account/api"


def _key() -> str | None:
    k = os.environ.get("ABUSEIPDB_KEY") or ""
    return k.strip() or None


def is_configured() -> bool:
    return _key() is not None


async def check_ip(client: httpx.AsyncClient, ip: str) -> dict:
    key = _key()
    if not key:
        return {"ip": ip, "configured": False}
    try:
        r = await client.get(
            CHECK_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=10.0,
        )
        if r.status_code != 200:
            return {"ip": ip, "configured": True, "error": f"HTTP {r.status_code}: {r.text[:120]}"}
        d = (r.json() or {}).get("data") or {}
        return {
            "ip": ip,
            "configured": True,
            "abuse_confidence": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "last_reported_at": d.get("lastReportedAt"),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usage_type": d.get("usageType"),
            "is_tor": d.get("isTor", False),
            "is_public": d.get("isPublic", True),
        }
    except Exception as e:
        return {"ip": ip, "configured": True, "error": str(e)}


async def check_ips(ips: list[str], override_key: str | None = None) -> list[dict]:
    if not ips:
        return []
    key = (override_key or "").strip() or _key()
    if not key:
        return [{"ip": ip, "configured": False} for ip in ips]
    async with httpx.AsyncClient() as client:
        return await asyncio.gather(*[_check_ip_with(client, ip, key) for ip in ips])


async def _check_ip_with(client: httpx.AsyncClient, ip: str, key: str) -> dict:
    try:
        r = await client.get(
            CHECK_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=10.0,
        )
        if r.status_code != 200:
            return {"ip": ip, "configured": True, "error": f"HTTP {r.status_code}"}
        d = (r.json() or {}).get("data") or {}
        return {
            "ip": ip, "configured": True,
            "abuse_confidence": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "last_reported_at": d.get("lastReportedAt"),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usage_type": d.get("usageType"),
            "is_tor": d.get("isTor", False),
            "is_public": d.get("isPublic", True),
        }
    except Exception as e:
        return {"ip": ip, "configured": True, "error": str(e)}


def get_hint() -> dict:
    return {
        "configured": is_configured(),
        "key_url": KEY_URL,
        "provider": "AbuseIPDB",
        "free_tier": "1000 checks/day",
    }

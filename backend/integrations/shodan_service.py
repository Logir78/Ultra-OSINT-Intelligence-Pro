"""Shodan integration — host lookup for open ports + known CVEs.
Docs: https://developer.shodan.io/api
Free tier: 100 query credits/month (needs one credit per IP lookup).
"""
import os
import asyncio
import httpx
import logging

log = logging.getLogger("shodan")

HOST_URL = "https://api.shodan.io/shodan/host"
KEY_URL = "https://account.shodan.io/"


def _key() -> str | None:
    k = os.environ.get("SHODAN_KEY") or ""
    return k.strip() or None


def is_configured() -> bool:
    return _key() is not None


async def host_lookup(client: httpx.AsyncClient, ip: str) -> dict:
    key = _key()
    if not key:
        return {"ip": ip, "configured": False}
    try:
        r = await client.get(f"{HOST_URL}/{ip}", params={"key": key}, timeout=15.0)
        if r.status_code == 404:
            return {"ip": ip, "configured": True, "found": False, "ports": [], "vulns": [],
                    "services": []}
        if r.status_code != 200:
            return {"ip": ip, "configured": True, "found": False,
                    "error": f"HTTP {r.status_code}: {r.text[:120]}"}
        d = r.json()
        services = []
        for svc in d.get("data", []) or []:
            services.append({
                "port": svc.get("port"),
                "transport": svc.get("transport"),
                "product": svc.get("product"),
                "version": svc.get("version"),
                "cpe": svc.get("cpe23") or svc.get("cpe"),
                "banner": (svc.get("data") or "")[:220],
                "vulns": list((svc.get("vulns") or {}).keys()) if isinstance(svc.get("vulns"), dict) else (svc.get("vulns") or []),
            })
        return {
            "ip": ip,
            "configured": True,
            "found": True,
            "hostnames": d.get("hostnames", []),
            "country_code": d.get("country_code"),
            "org": d.get("org"),
            "isp": d.get("isp"),
            "os": d.get("os"),
            "last_update": d.get("last_update"),
            "ports": d.get("ports", []),
            "vulns": list(d.get("vulns", [])) if d.get("vulns") else [],
            "services": services,
        }
    except Exception as e:
        return {"ip": ip, "configured": True, "found": False, "error": str(e)}


async def lookup_ips(ips: list[str], override_key: str | None = None) -> list[dict]:
    if not ips:
        return []
    key = (override_key or "").strip() or _key()
    if not key:
        return [{"ip": ip, "configured": False} for ip in ips]
    async with httpx.AsyncClient() as client:
        return await asyncio.gather(*[_host_lookup_with(client, ip, key) for ip in ips])


async def _host_lookup_with(client: httpx.AsyncClient, ip: str, key: str) -> dict:
    try:
        r = await client.get(f"{HOST_URL}/{ip}", params={"key": key}, timeout=15.0)
        if r.status_code == 404:
            return {"ip": ip, "configured": True, "found": False, "ports": [], "vulns": [], "services": []}
        if r.status_code != 200:
            return {"ip": ip, "configured": True, "found": False, "error": f"HTTP {r.status_code}"}
        d = r.json()
        services = []
        for svc in d.get("data", []) or []:
            services.append({
                "port": svc.get("port"), "transport": svc.get("transport"),
                "product": svc.get("product"), "version": svc.get("version"),
                "cpe": svc.get("cpe23") or svc.get("cpe"),
                "banner": (svc.get("data") or "")[:220],
                "vulns": list((svc.get("vulns") or {}).keys()) if isinstance(svc.get("vulns"), dict) else (svc.get("vulns") or []),
            })
        return {
            "ip": ip, "configured": True, "found": True,
            "hostnames": d.get("hostnames", []),
            "country_code": d.get("country_code"), "org": d.get("org"),
            "isp": d.get("isp"), "os": d.get("os"),
            "last_update": d.get("last_update"),
            "ports": d.get("ports", []),
            "vulns": list(d.get("vulns", [])) if d.get("vulns") else [],
            "services": services,
        }
    except Exception as e:
        return {"ip": ip, "configured": True, "found": False, "error": str(e)}


def get_hint() -> dict:
    return {
        "configured": is_configured(),
        "key_url": KEY_URL,
        "provider": "Shodan",
        "free_tier": "100 créditos/mes",
    }

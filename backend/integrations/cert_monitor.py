"""SSL/TLS Certificate Expiration Monitor.

Extracts certificate expiry dates from the existing SSL scan data + probes
subdomains and returns per-host expiry with severity flags:
- expired (past date)
- critical (< 7 days)
- warning (< 30 days)
- ok (>= 30 days)
"""
import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Iterable

log = logging.getLogger("cert_monitor")


def _parse_expiry(cert_dict: dict) -> datetime | None:
    """Parse SSL cert notAfter string into UTC datetime."""
    if not cert_dict:
        return None
    raw = cert_dict.get("notAfter") or cert_dict.get("not_after") or cert_dict.get("expires")
    if not raw:
        return None
    # Common formats seen in stdlib output
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _classify(expiry: datetime) -> tuple[str, int]:
    """Return (severity, days_remaining)."""
    now = datetime.now(timezone.utc)
    delta = expiry - now
    days = delta.days
    if days < 0:
        return "expired", days
    if days <= 7:
        return "critical", days
    if days <= 30:
        return "warning", days
    return "ok", days


def _sync_probe(host: str, port: int = 443, timeout: float = 5.0) -> dict | None:
    """Synchronous cert probe (runs in thread executor)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as sslsock:
                cert = sslsock.getpeercert()
                return cert
    except Exception:
        return None


async def probe_host(host: str) -> dict:
    loop = asyncio.get_event_loop()
    cert = await loop.run_in_executor(None, _sync_probe, host, 443, 5.0)
    if not cert:
        return {"host": host, "reachable": False}
    expiry = _parse_expiry(cert)
    if not expiry:
        return {"host": host, "reachable": True, "expiry": None}
    severity, days = _classify(expiry)
    issuer = ""
    subject = ""
    try:
        for tup in cert.get("issuer", ()):
            for k, v in tup:
                if k == "organizationName":
                    issuer = v
                    break
        for tup in cert.get("subject", ()):
            for k, v in tup:
                if k == "commonName":
                    subject = v
                    break
    except Exception:
        pass
    return {
        "host": host,
        "reachable": True,
        "expiry": expiry.isoformat(),
        "days_remaining": days,
        "severity": severity,
        "issuer": issuer,
        "subject": subject,
    }


async def monitor_hosts(hosts: Iterable[str], concurrency: int = 15) -> dict:
    """Probe SSL certs for a list of hosts concurrently."""
    hosts = list(set(h.strip() for h in hosts if h and h.strip()))
    sem = asyncio.Semaphore(concurrency)

    async def _one(h: str) -> dict:
        async with sem:
            return await probe_host(h)

    results = await asyncio.gather(*[_one(h) for h in hosts])
    reachable = [r for r in results if r.get("reachable") and r.get("expiry")]
    # Bucket by severity
    buckets = {"expired": [], "critical": [], "warning": [], "ok": []}
    for r in reachable:
        buckets[r["severity"]].append(r)
    # Sort each bucket by days remaining (ascending)
    for k in buckets:
        buckets[k].sort(key=lambda r: r["days_remaining"])
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts_probed": len(hosts),
        "hosts_reachable": len(reachable),
        "buckets": buckets,
        "counts": {k: len(v) for k, v in buckets.items()},
        "next_expiration": buckets["expired"][:1] + buckets["critical"][:1] + buckets["warning"][:1],
    }

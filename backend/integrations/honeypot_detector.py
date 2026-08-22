"""Honeypot Detector — detect signs a target is a trap/decoy server."""
import re
import logging
import httpx
from datetime import datetime, timezone

from integrations.stealth import stealth_httpx_client

log = logging.getLogger("honeypot")

# Suspicious response patterns
HONEYPOT_SIGNATURES = [
    ("known_honeypot_banner", re.compile(r"cowrie|kippo|dionaea|glastopf|conpot|honeytrap|snare-honeypot", re.IGNORECASE), "critical"),
    ("suspicious_headers", re.compile(r"x-honeypot|x-canary", re.IGNORECASE), "critical"),
    ("perfectly_open_services", None, "high"),   # heuristic below
    ("uniform_response_time", None, "medium"),   # heuristic below
    ("fake_login_generic", re.compile(r"admin/admin|root:toor|password:1234", re.IGNORECASE), "medium"),
]


async def _probe_ports(ip: str, ports: list[int]) -> dict:
    """Rough banner grab on a few ports — many honeypots respond to ALL ports."""
    import asyncio
    async def _one(p):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, p), timeout=2.0)
            try:
                writer.write(b"\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(200), timeout=1.5)
                return {"port": p, "open": True, "banner": banner.decode("utf-8", errors="replace")[:120]}
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            return {"port": p, "open": False}

    results = await asyncio.gather(*[_one(p) for p in ports], return_exceptions=False)
    return {r["port"]: r for r in results}


async def detect_honeypot(domain: str, ip: str | None) -> dict:
    """Run several heuristics against the target and score the honeypot likelihood."""
    reasons: list[dict] = []
    suspicion_score = 0

    # 1) HTTP headers + banner check
    async with stealth_httpx_client(domain, timeout=6.0, follow_redirects=True) as c:
        try:
            r = await c.get(f"https://{domain}")
            headers = dict(r.headers)
            body = r.text[:20_000]
            server = headers.get("server", "").lower()
            xhp = headers.get("x-honeypot") or headers.get("x-canary")
            if xhp:
                reasons.append({"signal": "honeypot_header",
                                 "detail": f"Cabecera sospechosa: {xhp}", "severity": "critical"})
                suspicion_score += 60
            if re.search(HONEYPOT_SIGNATURES[0][1], body) or re.search(HONEYPOT_SIGNATURES[0][1], server):
                reasons.append({"signal": "known_honeypot_banner",
                                 "detail": "Banner conocido de honeypot en respuesta HTTP",
                                 "severity": "critical"})
                suspicion_score += 70
            if re.search(HONEYPOT_SIGNATURES[4][1], body):
                reasons.append({"signal": "fake_credential_hint",
                                 "detail": "Credenciales por defecto explícitas en la página",
                                 "severity": "medium"})
                suspicion_score += 20
            # Unusual "welcome" responses
            if any(k in body.lower() for k in ("welcome to my honeypot", "trap engaged", "canary triggered")):
                reasons.append({"signal": "explicit_trap_msg", "detail": "Texto explícito de trampa",
                                 "severity": "critical"})
                suspicion_score += 80
        except Exception:
            pass

    # 2) Port banner uniformity heuristic (many honeypots open EVERY port)
    if ip:
        # Probe a set of common + weird ports
        ports_to_check = [21, 22, 23, 25, 80, 110, 143, 443, 1723, 3389, 5900, 8080, 9999, 31337, 12345, 54321]
        results = await _probe_ports(ip, ports_to_check)
        open_ports = [p for p, r in results.items() if r["open"]]
        # If >70% of these random ports are open → suspicious (real servers rarely open 31337, 54321…)
        if len(open_ports) >= 10:
            reasons.append({"signal": "too_many_open_ports",
                             "detail": f"{len(open_ports)}/{len(ports_to_check)} puertos abiertos — un servidor real casi nunca expone tantos",
                             "severity": "high"})
            suspicion_score += 40
        # Banner similarity: if 3+ ports return identical banners → honeypot
        banners = [r["banner"] for r in results.values() if r.get("banner")]
        if len(banners) >= 3:
            uniq = set(banners)
            if len(uniq) == 1:
                reasons.append({"signal": "uniform_banners",
                                 "detail": "Todos los puertos abiertos devuelven exactamente el mismo banner",
                                 "severity": "high"})
                suspicion_score += 35
        # Weird high ports open (31337, 12345, 54321) are honeypot classics
        weird = [p for p in (31337, 12345, 54321, 9999) if results.get(p, {}).get("open")]
        if weird:
            reasons.append({"signal": "classic_honeypot_ports",
                             "detail": f"Puertos clásicos de honeypot abiertos: {weird}",
                             "severity": "high"})
            suspicion_score += 30

    suspicion_score = min(100, suspicion_score)
    if suspicion_score >= 60:
        verdict = "TRAMPA DETECTADA con alta confianza — evita continuar"
        risk = "critical"
    elif suspicion_score >= 30:
        verdict = "Comportamiento sospechoso — proceder con cautela"
        risk = "high"
    else:
        verdict = "No se detectan señales evidentes de honeypot"
        risk = "low"

    return {
        "domain": domain,
        "ip": ip,
        "suspicion_score": suspicion_score,
        "risk": risk,
        "verdict": verdict,
        "signals_detected": reasons,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

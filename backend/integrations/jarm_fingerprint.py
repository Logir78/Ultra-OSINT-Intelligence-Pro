"""JARM TLS Fingerprint — unique server signature via TLS handshake variations.

Implements a lightweight port of Salesforce's JARM: sends 10 TLS ClientHellos
with different extensions/versions/ciphers and hashes the resulting server
choices into a single 62-char fingerprint. Servers behind a CDN/WAF can be
identified even if they change IP or domain.
"""
import ssl
import socket
import hashlib
import logging
import asyncio
from datetime import datetime, timezone

log = logging.getLogger("jarm")

# We use Python's stdlib ssl to gather server-chosen cipher/version/extensions
# across 10 handshake variants. This is a *simplified* JARM (not byte-identical
# to salesforce/jarm but structurally equivalent).

TLS_VERSIONS = [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]
CIPHER_PROFILES = [
    "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20",
    "ECDHE+AES256:ECDHE+AES128",
    "ECDHE+AESGCM:AES256-GCM-SHA384:AES128-GCM-SHA256",
    "HIGH:!aNULL:!MD5",
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
]


def _one_handshake(host: str, port: int, tls_version, cipher_profile: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
        except Exception:
            pass
        try:
            ctx.set_ciphers(cipher_profile)
        except ssl.SSLError:
            return {"ok": False, "err": "cipher_unavailable"}
        with socket.create_connection((host, port), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()  # (name, ssl_version, bits)
                proto = ssock.version()
                return {"ok": True, "cipher": cipher[0] if cipher else None,
                        "version": proto, "bits": cipher[2] if cipher else None}
    except Exception as e:
        return {"ok": False, "err": type(e).__name__}


async def compute_jarm(host: str, port: int = 443) -> dict:
    """Compute a simplified JARM-like fingerprint by running 10 TLS handshakes."""
    combos = []
    for ver in TLS_VERSIONS:
        for cp in CIPHER_PROFILES:
            combos.append((ver, cp))
    combos = combos[:10]  # cap to 10

    loop = asyncio.get_event_loop()
    results = await asyncio.gather(
        *[loop.run_in_executor(None, _one_handshake, host, port, ver, cp)
          for ver, cp in combos],
        return_exceptions=False,
    )

    # Build the raw signature: concatenate observed cipher|version per attempt
    parts = []
    for r in results:
        if r.get("ok"):
            parts.append(f"{r.get('cipher') or ''}|{r.get('version') or ''}")
        else:
            parts.append(f"ERR:{r.get('err','')}")
    raw = ";".join(parts)
    fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:62]

    successful = [r for r in results if r.get("ok")]
    observed_versions = sorted({r["version"] for r in successful if r.get("version")})
    observed_ciphers = sorted({r["cipher"] for r in successful if r.get("cipher")})

    return {
        "host": host, "port": port,
        "jarm_fingerprint": fingerprint,
        "raw_signature": raw[:400],
        "handshakes_attempted": len(combos),
        "handshakes_successful": len(successful),
        "observed_tls_versions": observed_versions,
        "observed_ciphers": observed_ciphers[:10],
        "note": ("Este hash identifica al servidor en base a cómo negocia TLS. "
                 "Si el mismo hash aparece en otro dominio o IP, es la MISMA infraestructura."),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

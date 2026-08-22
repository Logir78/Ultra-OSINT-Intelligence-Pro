"""Security helpers for NOCTUA — SSRF guard + security-headers middleware.

Added in the "Pro" hardening pass. Everything here is *additive*: importing this
module changes nothing until you wire the middleware / call the validator.

Wiring (see IMPROVEMENTS.md):

    from security import SecurityHeadersMiddleware, assert_public_host
    app.add_middleware(SecurityHeadersMiddleware)

    # In the scan entrypoint, before making requests to a user-supplied domain:
    assert_public_host(domain)   # raises ValueError if it resolves to internal IPs
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

_DEFAULT_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # HSTS only makes sense behind HTTPS; enable via env when you terminate TLS.
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds a small set of hardening response headers to every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for key, value in _DEFAULT_HEADERS.items():
            response.headers.setdefault(key, value)
        if os.environ.get("ENABLE_HSTS", "0") == "1":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not a valid IP → treat as unsafe
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local      # includes 169.254.0.0/16 (cloud metadata)
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def is_safe_public_host(host: str) -> bool:
    """Return True only if `host` resolves exclusively to public IP addresses.

    Guards against pointing the scanner at localhost, private ranges, link-local
    (cloud metadata at 169.254.169.254), etc. Fails closed on resolution errors.
    """
    if not host:
        return False

    # Accept a bare hostname or a full URL
    parsed = urlparse(host if "://" in host else f"//{host}")
    hostname = parsed.hostname or host
    hostname = hostname.strip().strip(".")
    if not hostname:
        return False

    # A literal IP address
    try:
        ipaddress.ip_address(hostname)
        return not _is_blocked_ip(hostname)
    except ValueError:
        pass

    # Resolve the hostname; every resolved address must be public
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    resolved = {info[4][0] for info in infos}
    if not resolved:
        return False
    return all(not _is_blocked_ip(ip) for ip in resolved)


def assert_public_host(host: str) -> None:
    """Raise ValueError if `host` is not a safe public target.

    Honors the SSRF_GUARD env flag (default on). Set SSRF_GUARD=0 to disable.
    """
    if os.environ.get("SSRF_GUARD", "1") != "1":
        return
    if not is_safe_public_host(host):
        raise ValueError(
            f"Refusing to scan '{host}': resolves to a non-public/internal address."
        )

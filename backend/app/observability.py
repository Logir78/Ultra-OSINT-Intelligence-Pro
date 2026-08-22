"""Observability & abuse-protection for the NOCTUA backend (Fase 2).

Additive: nothing here changes existing behavior until wired in server.py.

Provides:
  - setup_logging()  -> structured JSON logs (or plain), level from env
  - install(app)     -> request-id + access logging, a global IP rate limiter,
                        and a catch-all 500 handler

The rate limiter is a self-contained in-memory fixed-window limiter applied as
ASGI middleware, so it works regardless of endpoint signatures or nested
routers (unlike slowapi's default_limits, which need a `request` arg per route).
For multi-process / multi-instance deployments, back it with Redis instead.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from collections import defaultdict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key in ("request_id", "path", "method", "status", "duration_ms", "client"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging() -> None:
    """Configure root logging. LOG_FORMAT=json|plain, LOG_LEVEL=INFO by default."""
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    fmt = os.environ.get("LOG_FORMAT", "plain").lower()
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers = [handler]
        lg.propagate = False


# ---------------------------------------------------------------------------
# Rate limiting (in-memory fixed window per client IP)
# ---------------------------------------------------------------------------
def _parse_limit(spec: str) -> tuple[int, int]:
    """'240/minute' -> (240, 60). Supports second|minute|hour|day."""
    try:
        count, _, period = spec.partition("/")
        n = int(count)
        seconds = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}[
            period.strip().rstrip("s") or "minute"
        ]
        return n, seconds
    except Exception:
        return 240, 60


_RATE_LIMIT, _RATE_WINDOW = _parse_limit(os.environ.get("RATE_LIMIT_DEFAULT", "240/minute"))
_RATE_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "1") == "1"
_EXEMPT_PATHS = {"/api/health", "/docs", "/openapi.json", "/redoc", "/docs/oauth2-redirect"}
_buckets: dict[str, list[float]] = defaultdict(list)


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_ok(ip: str) -> tuple[bool, int]:
    """Return (allowed, retry_after_seconds)."""
    now = time.time()
    bucket = _buckets[ip]
    bucket[:] = [t for t in bucket if now - t < _RATE_WINDOW]
    if len(bucket) >= _RATE_LIMIT:
        retry = int(_RATE_WINDOW - (now - bucket[0])) + 1
        return False, retry
    bucket.append(now)
    return True, 0


# ---------------------------------------------------------------------------
# Middleware + handlers
# ---------------------------------------------------------------------------
async def request_context_middleware(request: Request, call_next):
    rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    log = logging.getLogger("noctua.access")
    ip = _client_ip(request)

    # Global rate limit (skip health/docs and CORS preflight)
    if _RATE_ENABLED and request.method != "OPTIONS" and request.url.path not in _EXEMPT_PATHS:
        allowed, retry = _rate_ok(ip)
        if not allowed:
            log.warning(
                "rate_limited",
                extra={"request_id": rid, "path": request.url.path,
                       "method": request.method, "status": 429, "client": ip},
            )
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limited", "retry_after_seconds": retry},
                headers={"Retry-After": str(retry), "X-Request-ID": rid},
            )

    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        dur = (time.perf_counter() - start) * 1000
        log.exception(
            "unhandled error",
            extra={"request_id": rid, "path": request.url.path, "method": request.method,
                   "status": 500, "duration_ms": round(dur, 1), "client": ip},
        )
        raise
    dur = (time.perf_counter() - start) * 1000
    response.headers["X-Request-ID"] = rid
    log.info(
        "request",
        extra={"request_id": rid, "path": request.url.path, "method": request.method,
               "status": response.status_code, "duration_ms": round(dur, 1), "client": ip},
    )
    return response


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logging.getLogger("noctua").exception("Unhandled exception on %s", request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error",
                 "detail": "An unexpected error occurred. Please try again later."},
    )


def install(app: FastAPI) -> None:
    """Wire the request/rate-limit middleware and the catch-all handler into `app`."""
    app.middleware("http")(request_context_middleware)
    app.add_exception_handler(Exception, unhandled_exception_handler)
    if _RATE_ENABLED:
        logging.getLogger("noctua").info(
            "Rate limiting enabled: %s req / %ss per IP", _RATE_LIMIT, _RATE_WINDOW
        )

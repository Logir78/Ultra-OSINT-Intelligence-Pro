"""Shared foundation for the NOCTUA backend: DB client, auth dependency,
LLM helpers and small utilities used across routers.

Extracted from the original monolithic server.py (see IMPROVEMENTS.md).
"""
import os
import uuid
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from fastapi import HTTPException, Request, Header
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")

# ---- Database -------------------------------------------------------------
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

# ---- Logging --------------------------------------------------------------
logger = logging.getLogger("noctua")

# ---- Config ---------------------------------------------------------------
EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY", "")

# ---- Public rate-limit + stats (in-memory) --------------------------------
_public_rate_bucket: dict[str, list[float]] = {}
PUBLIC_RATE_LIMIT = 5          # requests
PUBLIC_RATE_WINDOW = 3600      # per hour

_stats_cache: dict = {"at": None, "data": None}
_STATS_TTL = 300  # seconds


async def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> dict:
    token = request.cookies.get("session_token")
    bearer = None
    if authorization and authorization.startswith("Bearer "):
        bearer = authorization.split(" ", 1)[1]

    # --- API key path (programmatic access) ---
    api_key = request.headers.get("x-api-key")
    if not api_key and bearer and bearer.startswith("nk_"):
        api_key = bearer
    if api_key:
        from app.apikeys import verify_api_key
        key_user = await verify_api_key(db, api_key)
        if not key_user:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return key_user

    # --- Session path (browser) ---
    if not token and bearer:
        token = bearer
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    expires_at = session["expires_at"]
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session expired")

    user = await db.users.find_one({"user_id": session["user_id"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def _generate_ai_summary(analysis: dict) -> str:
    if not EMERGENT_LLM_KEY and not os.environ.get("DEFAULT_LLM_PROVIDER"):
        return "AI summary no disponible (configura DEFAULT_LLM_* o EMERGENT_LLM_KEY)."
    security = analysis.get("security", {})
    open_ports = analysis.get("ports", {}).get("open_ports", [])
    subs = analysis.get("subdomains", {}).get("found", [])
    ssl_info = analysis.get("ssl", {})
    prompt = f"""Actúa como analista senior de ciberseguridad. Analiza los siguientes resultados de un escaneo OSINT del dominio "{analysis['domain']}" y produce:

1. **Resumen ejecutivo** (2-3 líneas)
2. **Riesgos detectados** (lista priorizada: Crítico / Alto / Medio / Bajo)
3. **Recomendaciones accionables** (máximo 6, en bullets)

Datos:
- IP: {analysis.get('ip', {}).get('ip')}
- SSL válido: {ssl_info.get('success')} — Emisor: {ssl_info.get('issuer', {}).get('organizationName', 'N/A')} — TLS: {ssl_info.get('tls_version')}
- Puertos abiertos: {[p['port'] for p in open_ports]}
- Subdominios encontrados: {len(subs)}
- Seguridad básica: {security.get('basic', {}).get('score')}%
- Seguridad media: {security.get('medium', {}).get('score')}%
- Seguridad avanzada: {security.get('advanced', {}).get('score')}%
- Checks fallados (medium): {[i['check'] for i in security.get('medium', {}).get('items', []) if i['status'] != 'pass']}
- Checks fallados (advanced): {[i['check'] for i in security.get('advanced', {}).get('items', []) if i['status'] != 'pass']}

Responde en español, usa formato markdown, sé conciso y directo."""
    from app.llm import complete
    return await complete(
        prompt, "Eres un analista senior de ciberseguridad experto en OSINT."
    )


def _collect_scan_ips(scan_doc: dict) -> list[str]:
    result = scan_doc.get("result") or {}
    ips = set()
    main_ip = (result.get("ip") or {}).get("ip")
    if main_ip:
        ips.add(main_ip)
    for sub in (result.get("subdomains") or {}).get("found", []):
        for ip in sub.get("ips", []):
            ips.add(ip)
    return list(ips)[:20]  # cap to keep API credits reasonable


def _is_admin(user: dict) -> bool:
    """Admin = first email in AUTHORIZED_EMAILS (owner)."""
    authorized_raw = os.environ.get("AUTHORIZED_EMAILS", "").strip()
    if not authorized_raw:
        return False
    first = authorized_raw.split(",")[0].strip().lower()
    return (user.get("email") or "").lower() == first


async def _load_scan(scan_id: str, user: dict):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    return doc


def _user_ai(user):
    from user_settings import get_ai_config
    ai = get_ai_config(user)
    return ai["provider"], ai["key"], ai["mode"]


def _rate_limit_check(request: Request):
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "unknown")
    now_ts = datetime.now(timezone.utc).timestamp()
    bucket = _public_rate_bucket.setdefault(ip, [])
    bucket[:] = [t for t in bucket if now_ts - t < PUBLIC_RATE_WINDOW]
    if len(bucket) >= PUBLIC_RATE_LIMIT:
        retry_after = int(PUBLIC_RATE_WINDOW - (now_ts - bucket[0]))
        raise HTTPException(429, detail={"error": "rate_limited", "retry_after_seconds": retry_after})
    bucket.append(now_ts)
    return ip

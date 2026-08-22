"""OSINT Scanner backend - FastAPI + MongoDB + Emergent Google Auth + Claude AI summary."""
from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends, Header
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import uuid
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone, timedelta
import httpx

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from osint_engine import analyze_domain
from emergentintegrations.llm.chat import LlmChat, UserMessage
import asyncio
import payments as payments_mod
import schedules as schedules_mod
import telegram_bot as telegram_bot_mod
from security import SecurityHeadersMiddleware, assert_public_host

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI(title="OSINT Scanner API")
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY", "")


# ----------------- MODELS -----------------
class ScanRequest(BaseModel):
    domain: str
    extended_ports: bool = False
    ai_summary: bool = True


class User(BaseModel):
    user_id: str
    email: str
    name: str
    picture: Optional[str] = None
    created_at: datetime


# ----------------- AUTH -----------------
# REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH

async def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> dict:
    token = request.cookies.get("session_token")
    if not token and authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
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


@api_router.post("/auth/session")
async def create_session(request: Request, response: Response):
    body = await request.json()
    session_id = body.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")

    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(
            "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
            headers={"X-Session-ID": session_id},
        )
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid session_id")
    data = r.json()

    email = (data.get("email") or "").lower().strip()

    # ── ACCESS WHITELIST (private-access mode) ─────────────────────────
    authorized_raw = os.environ.get("AUTHORIZED_EMAILS", "").strip()
    if authorized_raw:
        allowed = {e.strip().lower() for e in authorized_raw.split(",") if e.strip()}
        if email not in allowed:
            # Log the attempt for security audit
            client_ip = "unknown"
            try:
                client_ip = (request.headers.get("x-forwarded-for") or
                             request.headers.get("x-real-ip") or
                             (request.client.host if request.client else "unknown"))
                if client_ip and "," in client_ip:
                    client_ip = client_ip.split(",")[0].strip()
                await db.access_attempts.insert_one({
                    "email": email or "unknown",
                    "name": data.get("name"),
                    "ip": client_ip or "unknown",
                    "user_agent": (request.headers.get("user-agent") or "")[:400],
                    "reason": "not_in_whitelist",
                    "attempted_at": datetime.now(timezone.utc).isoformat(),
                })
            except Exception:
                logger.exception("access_attempts insert failed")

            # Notify admin via Telegram (if admin has telegram configured)
            admin_email = authorized_raw.split(",")[0].strip().lower()
            admin_user = await db.users.find_one({"email": admin_email}, {"_id": 0}) or {}
            try:
                tg = admin_user.get("telegram") or {}
                if tg.get("bot_token") and tg.get("chat_id"):
                    import httpx as _httpx
                    text = (f"🚨 *ALERTA DE ACCESO*\n"
                            f"Intento de entrada bloqueado.\n"
                            f"*Email:* `{email or 'unknown'}`\n"
                            f"*IP:* `{client_ip or 'unknown'}`\n"
                            f"*Cuando:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
                    async with _httpx.AsyncClient(timeout=6.0) as tc:
                        await tc.post(
                            f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage",
                            json={"chat_id": tg["chat_id"], "text": text,
                                  "parse_mode": "Markdown",
                                  "disable_web_page_preview": True})
            except Exception:
                logger.exception("telegram access-alert failed")

            # Notify admin via Email (Resend) if configured
            try:
                email_cfg = admin_user.get("email_alerts") or {}
                if email_cfg.get("enabled") and email_cfg.get("address"):
                    from emailer import send_blocked_login_email
                    await send_blocked_login_email(
                        email_cfg["address"],
                        email or "unknown",
                        client_ip or "unknown",
                        request.headers.get("user-agent") or "",
                    )
            except Exception:
                logger.exception("email access-alert failed")

            raise HTTPException(
                status_code=403,
                detail={"error": "private_access",
                        "message": "Esta app está en modo Acceso Privado. Tu correo no está autorizado.",
                        "email": email},
            )
    # ────────────────────────────────────────────────────────────────────

    existing = await db.users.find_one({"email": email}, {"_id": 0})
    if existing:
        user_id = existing["user_id"]
        await db.users.update_one(
            {"user_id": user_id},
            {"$set": {"name": data["name"], "picture": data.get("picture")}},
        )
    else:
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        await db.users.insert_one({
            "user_id": user_id,
            "email": email,
            "name": data["name"],
            "picture": data.get("picture"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    session_token = data["session_token"]
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    await db.user_sessions.insert_one({
        "user_id": user_id,
        "session_token": session_token,
        "expires_at": expires_at.isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
        max_age=7 * 24 * 60 * 60,
    )
    return {
        "user_id": user_id,
        "email": email,
        "name": data["name"],
        "picture": data.get("picture"),
    }


@api_router.get("/auth/me")
async def auth_me(user=Depends(get_current_user)):
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "name": user["name"],
        "picture": user.get("picture"),
        "plan": user.get("plan", "free"),
        "slack_webhook_url": user.get("slack_webhook_url"),
    }


@api_router.post("/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("session_token")
    if token:
        await db.user_sessions.delete_one({"session_token": token})
    response.delete_cookie("session_token", path="/", samesite="none", secure=True)
    return {"ok": True}


# ----------------- AI SUMMARY -----------------
async def _generate_ai_summary(analysis: dict) -> str:
    if not EMERGENT_LLM_KEY:
        return "AI summary no disponible (falta EMERGENT_LLM_KEY)."
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
    try:
        from claude_models import resolve_claude_model
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"osint-{uuid.uuid4().hex[:8]}",
            system_message="Eres un analista senior de ciberseguridad experto en OSINT.",
        ).with_model("anthropic", resolve_claude_model())
        msg = UserMessage(text=prompt)
        result = await chat.send_message(msg)
        return str(result)
    except Exception as e:
        logging.exception("AI summary failed")
        return f"Error generando resumen IA: {str(e)}"


# ----------------- SCAN ENDPOINTS -----------------
@api_router.post("/scan")
async def scan(req: ScanRequest, user=Depends(get_current_user)):
    if not req.domain or len(req.domain.strip()) < 3:
        raise HTTPException(status_code=400, detail="Dominio inválido")
    try:
        assert_public_host(req.domain)  # anti-SSRF guard (SSRF_GUARD env, default on)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        analysis = await analyze_domain(req.domain, extended_ports=req.extended_ports)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en escaneo: {str(e)}")

    if req.ai_summary:
        analysis["ai_summary"] = await _generate_ai_summary(analysis)
    else:
        analysis["ai_summary"] = None

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    doc = {
        "scan_id": scan_id,
        "user_id": user["user_id"],
        "domain": analysis["domain"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "extended_ports": req.extended_ports,
        "result": analysis,
    }
    await db.scans.insert_one(doc)
    return {"scan_id": scan_id, "result": analysis}


@api_router.get("/scans")
async def list_scans(user=Depends(get_current_user)):
    cursor = db.scans.find(
        {"user_id": user["user_id"]},
        {"_id": 0, "scan_id": 1, "domain": 1, "created_at": 1, "tags": 1,
         "primary_category": 1, "flagged": 1,
         "result.security": 1, "result.ip.ip": 1, "result.ports.open_ports": 1},
    ).sort("created_at", -1).limit(100)
    items = await cursor.to_list(length=100)
    for it in items:
        r = it.get("result", {})
        sec = r.get("security", {})
        it["overview"] = {
            "ip": r.get("ip", {}).get("ip"),
            "open_ports": len(r.get("ports", {}).get("open_ports", [])),
            "score_basic": sec.get("basic", {}).get("score"),
            "score_medium": sec.get("medium", {}).get("score"),
            "score_advanced": sec.get("advanced", {}).get("score"),
        }
        it.pop("result", None)
    return items


@api_router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]},
        {"_id": 0},
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    return doc


@api_router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, user=Depends(get_current_user)):
    res = await db.scans.delete_one({"scan_id": scan_id, "user_id": user["user_id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"ok": True}


@api_router.get("/scans/{scan_id}/geoip")
async def scan_geoip(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("geoip"):
        return {"geoip": doc["geoip"], "cached": True}
    from geoip import geolocate_scan
    geoip = await geolocate_scan(doc["result"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"geoip": geoip}})
    return {"geoip": geoip, "cached": False}


@api_router.get("/scans/{scan_id}/wayback")
async def scan_wayback(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("wayback"):
        return {"wayback": doc["wayback"], "cached": True}
    from wayback import get_wayback_timeline
    domain = doc["result"]["domain"]
    timeline = await get_wayback_timeline(domain, count=5)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"wayback": timeline}})
    return {"wayback": timeline, "cached": False}


@api_router.get("/scans/{scan_id}/intel")
async def scan_intel(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("intel"):
        return {"intel": doc["intel"], "cached": True}
    # Ensure we have wayback + reputation in the result for enrichment
    result = doc["result"]
    if not result.get("wayback") and doc.get("wayback"):
        result = {**result, "wayback": doc["wayback"]}
    if doc.get("reputation"):
        result = {**result, "_abuse_worst_score": doc["reputation"].get("worst_score", 0)}
    if doc.get("takeover"):
        result = {**result, "_takeover_vulns": doc["takeover"].get("vulnerable_count", 0)}
    from intel import generate_intel_summary
    from user_settings import get_ai_config
    ai = get_ai_config(user)
    intel = await generate_intel_summary(
        result, EMERGENT_LLM_KEY,
        ai_provider=ai["provider"], ai_key=ai["key"], ai_mode=ai["mode"],
        claude_tier=(user.get("preferences") or {}).get("claude_tier"),
        ollama_url=ai.get("ollama_url"), ollama_model=ai.get("ollama_model"),
    )
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"intel": intel}})
    return {"intel": intel, "cached": False}


@api_router.get("/scans/{scan_id}/pdf")
async def scan_pdf(scan_id: str, user=Depends(get_current_user)):
    from fastapi.responses import Response as FResponse
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")

    intel = doc.get("intel")
    if not intel:
        result = doc["result"]
        if not result.get("wayback") and doc.get("wayback"):
            result = {**result, "wayback": doc["wayback"]}
        from intel import generate_intel_summary
        from user_settings import get_ai_config
        ai = get_ai_config(user)
        intel = await generate_intel_summary(
            result, EMERGENT_LLM_KEY,
            ai_provider=ai["provider"], ai_key=ai["key"], ai_mode=ai["mode"],
            claude_tier=(user.get("preferences") or {}).get("claude_tier"),
            ollama_url=ai.get("ollama_url"), ollama_model=ai.get("ollama_model"),
        )
        await db.scans.update_one({"scan_id": scan_id}, {"$set": {"intel": intel}})

    from pdf_export import build_pdf
    pdf_bytes = build_pdf(doc, intel)
    filename = f"noctua_{doc['result']['domain']}_{scan_id}.pdf".replace("/", "_")
    return FResponse(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
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


@api_router.get("/scans/{scan_id}/reputation")
async def scan_reputation(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("reputation"):
        return {"reputation": doc["reputation"], "cached": True}
    from integrations import reputation
    from user_settings import get_user_key
    ips = _collect_scan_ips(doc)
    checks = await reputation.check_ips(ips, override_key=get_user_key(user, "abuseipdb"))
    payload = {
        "provider": reputation.get_hint(),
        "checks": checks,
        "worst_score": max((c.get("abuse_confidence") or 0) for c in checks) if checks else 0,
    }
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"reputation": payload}})
    return {"reputation": payload, "cached": False}


@api_router.get("/scans/{scan_id}/shodan")
async def scan_shodan(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("shodan"):
        return {"shodan": doc["shodan"], "cached": True}
    from integrations import shodan_service
    from user_settings import get_user_key
    ips = _collect_scan_ips(doc)
    hosts = await shodan_service.lookup_ips(ips, override_key=get_user_key(user, "shodan"))
    all_vulns = []
    for h in hosts:
        for v in (h.get("vulns") or []):
            all_vulns.append({"cve": v, "ip": h["ip"]})
        for svc in h.get("services") or []:
            for v in svc.get("vulns") or []:
                all_vulns.append({"cve": v, "ip": h["ip"], "port": svc.get("port"), "product": svc.get("product")})
    payload = {
        "provider": shodan_service.get_hint(),
        "hosts": hosts,
        "total_vulns": len(all_vulns),
        "vulns": all_vulns[:200],
    }
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"shodan": payload}})
    return {"shodan": payload, "cached": False}


@api_router.post("/breaches/lookup")
async def breaches_lookup(request: Request, user=Depends(get_current_user)):
    body = await request.json()
    query = (body.get("query") or "").strip()
    qtype = (body.get("type") or "email").strip().lower()
    if qtype not in ("email", "domain"):
        raise HTTPException(400, "type must be 'email' or 'domain'")
    if not query or len(query) < 3:
        raise HTTPException(400, "query too short")
    from integrations import breaches
    from user_settings import get_user_key
    result = await breaches.unified_search(
        query, qtype,
        hibp_key=get_user_key(user, "hibp"),
        rapidapi_key=get_user_key(user, "rapidapi"),
    )
    # Log the lookup for user history (no PII beyond what they typed)
    await db.breach_lookups.insert_one({
        "user_id": user["user_id"],
        "query": query,
        "type": qtype,
        "total": result["total"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return result


@api_router.get("/breaches/history")
async def breaches_history(user=Depends(get_current_user)):
    cursor = db.breach_lookups.find(
        {"user_id": user["user_id"]}, {"_id": 0}
    ).sort("created_at", -1).limit(30)
    return await cursor.to_list(length=30)


# --------- USER SETTINGS: API KEYS + AI CONFIG ---------

@api_router.get("/settings/keys")
async def get_settings(user=Depends(get_current_user)):
    from user_settings import mask_key, get_ai_config, PROVIDERS
    keys = (user.get("api_keys") or {})
    usage = user.get("api_usage") or {}
    history = user.get("test_history") or {}
    return {
        "api_keys": {p: {
            "set": bool((keys.get(p) or "").strip()),
            "masked": mask_key(keys.get(p)),
            "usage": usage.get(p),
            "last_test": (history.get(p) or [{}])[-1] if history.get(p) else None,
            "history": (history.get(p) or [])[-5:],
        } for p in PROVIDERS},
        "ai_config": {
            **get_ai_config(user),
            "key_set": bool((user.get("ai_config") or {}).get("key")),
            "key_masked": mask_key((user.get("ai_config") or {}).get("key")),
            "last_test": (history.get(f"ai:{get_ai_config(user)['provider']}") or [{}])[-1] if history.get(f"ai:{get_ai_config(user)['provider']}") else None,
        },
    }


@api_router.post("/settings/test-key")
async def test_key(request: Request, user=Depends(get_current_user)):
    from user_settings import TEST_FUNCS, test_ai_provider, AI_PROVIDERS
    body = await request.json()
    provider = (body.get("provider") or "").strip()
    key = (body.get("key") or "").strip()
    if not key:
        raise HTTPException(400, "Key vacía")

    if provider in TEST_FUNCS:
        result = await TEST_FUNCS[provider](key)
    elif provider.startswith("ai:"):
        p = provider.split(":", 1)[1]
        if p not in AI_PROVIDERS:
            raise HTTPException(400, "Provider AI desconocido")
        result = await test_ai_provider(p, key)
    else:
        raise HTTPException(400, "Provider desconocido")

    # Persist test history and usage
    entry = {
        "ok": result["ok"],
        "detail": result.get("detail", "")[:220],
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    updates = {f"test_history.{provider}": {"$each": [entry], "$slice": -10}}
    set_updates = {}
    if result.get("usage"):
        set_updates[f"api_usage.{provider}"] = {**result["usage"], "checked_at": entry["checked_at"]}

    ops = {"$push": updates}
    if set_updates:
        ops["$set"] = set_updates
    await db.users.update_one({"user_id": user["user_id"]}, ops)
    return result


@api_router.get("/settings/export")
async def export_ai_config(user=Depends(get_current_user)):
    """Return YAML with the AI engine configuration (provider + mode) — no keys."""
    from fastapi.responses import Response as FResponse
    from user_settings import get_ai_config
    import yaml
    ai = get_ai_config(user)
    payload = {
        "noctua_ai_engine": {
            "provider": ai["provider"],
            "mode": ai["mode"],
            "exported_by": user.get("email"),
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "note": "La API key NO se incluye por seguridad. Añádela manualmente en /settings.",
        }
    }
    text = "# NOCTUA.osint · AI engine configuration\n" + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    return FResponse(
        content=text, media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="noctua_ai_engine.yaml"'},
    )


@api_router.post("/settings/keys")
async def save_keys(request: Request, user=Depends(get_current_user)):
    from user_settings import TEST_FUNCS, PROVIDERS
    body = await request.json()
    new_keys = body.get("api_keys") or {}
    # Validate all provided keys before saving
    validated = {}
    errors = {}
    for p in PROVIDERS:
        v = (new_keys.get(p) or "").strip()
        if not v:
            continue
        # Only re-validate if it's a fresh key (client marks changed=True)
        if (new_keys.get(f"{p}_changed") if isinstance(new_keys, dict) else False) is False:
            # unchanged keys are trusted (already saved once)
            validated[p] = v
            continue
        res = await TEST_FUNCS[p](v)
        if not res["ok"]:
            errors[p] = res["detail"]
            continue
        validated[p] = v
    if errors:
        raise HTTPException(400, {"validation_failed": errors})
    await db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"api_keys": validated}},
    )
    return {"ok": True, "saved": list(validated.keys())}


@api_router.post("/settings/ai")
async def save_ai(request: Request, user=Depends(get_current_user)):
    from user_settings import AI_PROVIDERS, AI_MODES, test_ai_provider
    body = await request.json()
    provider = (body.get("provider") or "emergent").strip()
    mode = (body.get("mode") or "precision").strip()
    key = (body.get("key") or "").strip()
    changed = bool(body.get("key_changed"))
    ollama_url = (body.get("ollama_url") or "").strip()
    ollama_model = (body.get("ollama_model") or "").strip()

    if provider not in AI_PROVIDERS:
        raise HTTPException(400, "Provider AI inválido")
    if mode not in AI_MODES:
        raise HTTPException(400, "Modo inválido")

    if provider == "ollama":
        # For ollama, `key` is unused; ollama_url + ollama_model are the "credentials"
        if not ollama_url:
            raise HTTPException(400, "Falta la URL pública de Ollama")
        if not ollama_url.startswith(("http://", "https://")):
            raise HTTPException(400, "La URL de Ollama debe empezar por http:// o https://")
        if not ollama_model:
            raise HTTPException(400, "Especifica un modelo (ej: llama3.1, mistral, phi3)")
        prev = user.get("ai_config") or {}
        url_changed = ollama_url != prev.get("ollama_url")
        if changed or url_changed:
            r = await test_ai_provider("ollama", ollama_url)
            if not r["ok"]:
                raise HTTPException(400, {"validation_failed": r["detail"]})
        await db.users.update_one(
            {"user_id": user["user_id"]},
            {"$set": {"ai_config": {
                "provider": "ollama", "mode": mode, "key": None,
                "ollama_url": ollama_url, "ollama_model": ollama_model,
            }}},
        )
        return {"ok": True, "provider": "ollama", "mode": mode,
                "ollama_url": ollama_url, "ollama_model": ollama_model}

    if provider != "emergent":
        if not key and not (user.get("ai_config") or {}).get("key"):
            raise HTTPException(400, "Falta la key para el provider seleccionado")
        # Test only if the key changed OR the user is switching provider
        prev = (user.get("ai_config") or {})
        must_test = changed or (prev.get("provider") != provider and key)
        if must_test and key:
            r = await test_ai_provider(provider, key)
            if not r["ok"]:
                raise HTTPException(400, {"validation_failed": r["detail"]})
        elif not key:
            key = prev.get("key")  # keep existing

    await db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"ai_config": {"provider": provider, "mode": mode,
                                "key": key if provider != "emergent" else None}}},
    )
    return {"ok": True, "provider": provider, "mode": mode}


class UserPrefs(BaseModel):
    risk_threshold: Optional[int] = None   # 0-100
    notes: Optional[str] = None            # free-form context passed to AI


@api_router.get("/settings/preferences")
async def get_prefs(user=Depends(get_current_user)):
    p = user.get("preferences") or {}
    return {
        "risk_threshold": p.get("risk_threshold", 50),
        "notes": p.get("notes", ""),
    }


def _is_admin(user: dict) -> bool:
    """Admin = first email in AUTHORIZED_EMAILS (owner)."""
    authorized_raw = os.environ.get("AUTHORIZED_EMAILS", "").strip()
    if not authorized_raw:
        return False
    first = authorized_raw.split(",")[0].strip().lower()
    return (user.get("email") or "").lower() == first


@api_router.get("/settings/access-whitelist")
async def get_access_whitelist_status(user=Depends(get_current_user)):
    """Returns whitelist config (masked) — visible only to admin."""
    authorized_raw = os.environ.get("AUTHORIZED_EMAILS", "").strip()
    enabled = bool(authorized_raw)
    if not _is_admin(user):
        return {"enabled": enabled, "you_are_admin": False}
    emails = [e.strip().lower() for e in authorized_raw.split(",") if e.strip()]
    return {
        "enabled": enabled,
        "you_are_admin": True,
        "authorized_count": len(emails),
        "authorized_emails": emails,
        "admin_email": emails[0] if emails else None,
    }


@api_router.get("/settings/security-log")
async def get_security_log(user=Depends(get_current_user),
                            limit: int = 100):
    """Read the access-attempts audit log. Admin-only."""
    if not _is_admin(user):
        raise HTTPException(403, "Solo el administrador puede ver el registro de seguridad")
    limit = max(1, min(500, limit))
    cursor = db.access_attempts.find({}, {"_id": 0}).sort("attempted_at", -1).limit(limit)
    attempts = await cursor.to_list(limit)
    # Aggregate distinct emails + IPs
    unique_emails = len({a.get("email") for a in attempts})
    unique_ips = len({a.get("ip") for a in attempts})
    return {
        "total_attempts": len(attempts),
        "unique_rejected_emails": unique_emails,
        "unique_rejected_ips": unique_ips,
        "attempts": attempts,
        "note": "Registro de intentos de acceso rechazados por la lista blanca.",
    }


@api_router.post("/settings/preferences")
async def set_prefs(prefs: UserPrefs, user=Depends(get_current_user)):
    updates = {}
    if prefs.risk_threshold is not None:
        rt = max(0, min(100, int(prefs.risk_threshold)))
        updates["preferences.risk_threshold"] = rt
    if prefs.notes is not None:
        updates["preferences.notes"] = prefs.notes[:2000]
    if updates:
        await db.users.update_one({"user_id": user["user_id"]}, {"$set": updates})
    return {"ok": True}


# ─── CLAUDE MODEL TIER ────────────────────────────────────────────────
class ClaudeTierPref(BaseModel):
    tier: str  # fast | balanced | deep


@api_router.get("/settings/claude")
async def get_claude_tier(user=Depends(get_current_user)):
    from claude_models import CLAUDE_TIER_META, DEFAULT_TIER
    active = ((user.get("preferences") or {}).get("claude_tier")) or DEFAULT_TIER
    return {
        "active": active,
        "default": DEFAULT_TIER,
        "tiers": CLAUDE_TIER_META,
    }


@api_router.post("/settings/claude")
async def set_claude_tier(payload: ClaudeTierPref, user=Depends(get_current_user)):
    from claude_models import CLAUDE_TIERS
    if payload.tier not in CLAUDE_TIERS:
        raise HTTPException(400, f"Tier inválido. Usa uno de: {list(CLAUDE_TIERS)}")
    await db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"preferences.claude_tier": payload.tier}},
    )
    return {"active": payload.tier, "model": CLAUDE_TIERS[payload.tier]}


# ─── EMAIL NOTIFICATIONS (RESEND) ─────────────────────────────────────
class EmailPrefs(BaseModel):
    enabled: bool = False
    address: Optional[str] = None


@api_router.get("/settings/email")
async def get_email_prefs(user=Depends(get_current_user)):
    from emailer import is_configured, SENDER_EMAIL
    cfg = user.get("email_alerts") or {}
    return {
        "enabled": bool(cfg.get("enabled")),
        "address": cfg.get("address") or user.get("email"),
        "resend_configured": is_configured(),
        "sender": SENDER_EMAIL,
    }


@api_router.post("/settings/email")
async def set_email_prefs(payload: EmailPrefs, user=Depends(get_current_user)):
    addr = (payload.address or "").strip().lower() or user.get("email")
    if addr and ("@" not in addr or "." not in addr.split("@")[-1]):
        raise HTTPException(400, "Dirección de email inválida")
    await db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"email_alerts": {"enabled": bool(payload.enabled), "address": addr}}},
    )
    return {"enabled": bool(payload.enabled), "address": addr}


@api_router.post("/settings/email/test")
async def test_email_send(user=Depends(get_current_user)):
    from emailer import is_configured, send_email, _html_wrapper
    if not is_configured():
        raise HTTPException(400, "Resend no está configurado (falta RESEND_API_KEY en el servidor)")
    cfg = user.get("email_alerts") or {}
    addr = (cfg.get("address") or user.get("email") or "").strip()
    if not addr:
        raise HTTPException(400, "Configura una dirección de email primero")
    html = _html_wrapper(
        "✅ Notificaciones activas",
        f'<p>Tu integración de email con NOCTUA.osint está funcionando correctamente.</p>'
        f'<p>Recibirás aquí las alertas de:</p>'
        f'<ul><li>Escaneos completados por encima del umbral de riesgo</li>'
        f'<li>Cambios detectados por escaneos programados</li>'
        f'<li>Intentos de acceso bloqueados por Acceso Privado</li></ul>'
    )
    result = await send_email(addr, "[NOCTUA] Test de notificaciones", html)
    if not result.get("ok"):
        raise HTTPException(502, f"Fallo al enviar: {result.get('error')}")
    return {"ok": True, "sent_to": addr, "email_id": result.get("id")}


@api_router.get("/scans/{scan_id}/cloud")
async def scan_cloud(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("cloud"):
        return {"cloud": doc["cloud"], "cached": True}
    from integrations.cloud_scanner import scan_cloud_storage
    cloud = await scan_cloud_storage(doc["result"]["domain"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"cloud": cloud}})
    return {"cloud": cloud, "cached": False}


@api_router.get("/scans/{scan_id}/metadata")
async def scan_metadata(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("metadata"):
        return {"metadata": doc["metadata"], "cached": True}
    from integrations.metadata import extract_domain_docs
    md = await extract_domain_docs(doc["result"]["domain"], max_docs=10)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"metadata": md}})
    return {"metadata": md, "cached": False}


@api_router.get("/scans/{scan_id}/takeover")
async def scan_takeover(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("takeover"):
        return {"takeover": doc["takeover"], "cached": True}
    from integrations.takeover_scanner import scan_takeovers
    result = doc["result"]
    subs = [s["subdomain"] for s in (result.get("subdomains") or {}).get("found", [])]
    takeover = await scan_takeovers(subs, result["domain"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"takeover": takeover}})
    return {"takeover": takeover, "cached": False}


@api_router.get("/scans/{scan_id}/pastes")
async def scan_pastes(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("pastes"):
        return {"pastes": doc["pastes"], "cached": True}
    from integrations.paste_search import search_paste_mentions
    result = doc["result"]
    ips = _collect_scan_ips(doc)
    pastes = await search_paste_mentions(result["domain"], ips)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"pastes": pastes}})
    return {"pastes": pastes, "cached": False}


@api_router.get("/scans/{scan_id}/threat-intel")
async def scan_threat_intel(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("threat_intel"):
        return {"threat_intel": doc["threat_intel"], "cached": True}
    from integrations.threat_intel import urlscan_search, intelx_search
    from user_settings import get_user_key
    domain = doc["result"]["domain"]
    intelx_user_key = (user.get("api_keys") or {}).get("intelx")
    urlscan_user_key = (user.get("api_keys") or {}).get("urlscan")
    urls, ix = await asyncio.gather(
        urlscan_search(domain, user_key=urlscan_user_key),
        intelx_search(domain, user_key=intelx_user_key),
    )
    ti = {"urlscan": urls, "intelx": ix}
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"threat_intel": ti}})
    return {"threat_intel": ti, "cached": False}


# ---------- NEW ADVANCED MODULES ----------

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


@api_router.get("/scans/{scan_id}/js-miner")
async def scan_js_miner(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("js_miner"):
        return {"js_miner": doc["js_miner"], "cached": True}
    from integrations.js_miner import mine
    data = await mine(doc["result"]["domain"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"js_miner": data}})
    return {"js_miner": data, "cached": False}


@api_router.get("/scans/{scan_id}/ct-logs")
async def scan_ct_logs(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("ct_logs"):
        return {"ct_logs": doc["ct_logs"], "cached": True}
    from integrations.ct_logs import discover_and_crosscheck
    active = (doc["result"].get("subdomains") or {}).get("found", [])
    data = await discover_and_crosscheck(doc["result"]["domain"], active)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"ct_logs": data}})
    return {"ct_logs": data, "cached": False}


@api_router.get("/scans/{scan_id}/shodan-deep")
async def scan_shodan_deep(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("shodan_deep"):
        return {"shodan_deep": doc["shodan_deep"], "cached": True}
    from integrations.shodan_deep import deep_scan
    from user_settings import get_user_key
    ips = _collect_scan_ips(doc)
    key = get_user_key(user, "shodan")
    data = await deep_scan(ips, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"shodan_deep": data}})
    return {"shodan_deep": data, "cached": False}


@api_router.get("/scans/{scan_id}/dna")
async def scan_dna(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("dna"):
        return {"dna": doc["dna"], "cached": True}
    from integrations.dna_fingerprint import find_siblings
    from user_settings import get_user_key
    shodan_key = get_user_key(user, "shodan")
    data = await find_siblings(doc["result"], shodan_key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"dna": data}})
    return {"dna": data, "cached": False}


@api_router.get("/scans/{scan_id}/risk-oracle")
async def scan_risk_oracle(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("risk_oracle"):
        return {"risk_oracle": doc["risk_oracle"], "cached": True}
    from integrations.risk_oracle import predict_breach
    provider, key, mode = _user_ai(user)
    data = await predict_breach(doc["result"], EMERGENT_LLM_KEY, provider, key, mode)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"risk_oracle": data}})
    return {"risk_oracle": data, "cached": False}


@api_router.get("/scans/{scan_id}/brand-guardian")
async def scan_brand_guardian(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("brand_guardian"):
        return {"brand_guardian": doc["brand_guardian"], "cached": True}
    from integrations.brand_guardian import scan_typosquats
    provider, key, _ = _user_ai(user)
    data = await scan_typosquats(doc["result"]["domain"], EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"brand_guardian": data}})
    return {"brand_guardian": data, "cached": False}


@api_router.post("/scans/{scan_id}/phishing-sim")
async def scan_phishing_sim(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if user.get("plan") != "pro":
        raise HTTPException(status_code=402, detail="Pro plan required")
    from integrations.phishing_sim import generate_simulation
    provider, key, _ = _user_ai(user)
    # Always regenerate — user may want variants
    data = await generate_simulation(doc["result"], EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"phishing_sim": data}})
    return {"phishing_sim": data, "cached": False}


class AttackPathBody(BaseModel):
    apt_persona: Optional[str] = "none"
    regenerate: Optional[bool] = False


@api_router.post("/scans/{scan_id}/attack-path")
async def scan_attack_path(scan_id: str, body: AttackPathBody, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    cache_key = f"attack_path_{body.apt_persona or 'none'}"
    cached = (doc.get("attack_paths") or {}).get(cache_key)
    if cached and not body.regenerate:
        return {"attack_path": cached, "cached": True}
    from integrations.attack_path import build_attack_path
    provider, key, mode = _user_ai(user)
    data = await build_attack_path(doc["result"], EMERGENT_LLM_KEY, provider, key,
                                    apt_persona=body.apt_persona or "none", ai_mode=mode)
    await db.scans.update_one(
        {"scan_id": scan_id},
        {"$set": {f"attack_paths.{cache_key}": data}},
    )
    return {"attack_path": data, "cached": False}


@api_router.get("/scans/{scan_id}/poc")
async def scan_poc(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("poc"):
        return {"poc": doc["poc"], "cached": True}
    from integrations.poc_generator import generate_pocs
    provider, key, _ = _user_ai(user)
    data = await generate_pocs(doc["result"], EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"poc": data}})
    return {"poc": data, "cached": False}


@api_router.get("/apt-personas")
async def list_apt_personas():
    from integrations.attack_path import APT_PROFILES
    return {"personas": [{"id": k, "description": v} for k, v in APT_PROFILES.items()]}


# ─── BUG BOUNTY TOOLKIT ───────────────────────────────────────────────────────

@api_router.get("/scans/{scan_id}/param-miner")
async def scan_param_miner(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("param_miner"):
        return {"param_miner": doc["param_miner"], "cached": True}
    from integrations.param_miner import mine_params
    js_sources = ((doc.get("js_miner") or {}).get("sources") or [])
    data = await mine_params(doc["result"]["domain"], js_sources)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"param_miner": data}})
    return {"param_miner": data, "cached": False}


@api_router.get("/scans/{scan_id}/cloud-config")
async def scan_cloud_config(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("cloud_config"):
        return {"cloud_config": doc["cloud_config"], "cached": True}
    from integrations.cloud_config import hunt_configs
    subs = [s["subdomain"] for s in ((doc["result"].get("subdomains") or {}).get("found") or [])]
    data = await hunt_configs(doc["result"]["domain"], subs)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"cloud_config": data}})
    return {"cloud_config": data, "cached": False}


@api_router.get("/scans/{scan_id}/api-audit")
async def scan_api_audit(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("api_audit"):
        return {"api_audit": doc["api_audit"], "cached": True}
    from integrations.api_auditor import audit_apis
    data = await audit_apis(doc["result"]["domain"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"api_audit": data}})
    return {"api_audit": data, "cached": False}


@api_router.get("/scans/{scan_id}/idor")
async def scan_idor(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("idor"):
        return {"idor": doc["idor"], "cached": True}
    # Merge accumulated modules into a shallow view for analysis
    merged = dict(doc.get("result") or {})
    for k in ("js_miner", "api_audit", "param_miner"):
        if doc.get(k):
            merged[k] = doc[k]
    from integrations.idor_analyzer import analyze_idor
    provider, key, _ = _user_ai(user)
    data = await analyze_idor(merged, EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"idor": data}})
    return {"idor": data, "cached": False}


@api_router.get("/scans/{scan_id}/supply-chain")
async def scan_supply_chain(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("supply_chain"):
        return {"supply_chain": doc["supply_chain"], "cached": True}
    from integrations.supply_chain import audit_supply_chain
    data = await audit_supply_chain(doc["result"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"supply_chain": data}})
    return {"supply_chain": data, "cached": False}


@api_router.get("/scans/{scan_id}/logic-flow")
async def scan_logic_flow(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("logic_flow"):
        return {"logic_flow": doc["logic_flow"], "cached": True}
    merged = dict(doc.get("result") or {})
    for k in ("js_miner", "api_audit"):
        if doc.get(k):
            merged[k] = doc[k]
    from integrations.logic_flow import analyze_logic_flows
    provider, key, mode = _user_ai(user)
    data = await analyze_logic_flows(merged, EMERGENT_LLM_KEY, provider, key, mode)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"logic_flow": data}})
    return {"logic_flow": data, "cached": False}


@api_router.get("/scans/{scan_id}/reverse-ip")
async def scan_reverse_ip(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("reverse_ip"):
        return {"reverse_ip": doc["reverse_ip"], "cached": True}
    from integrations.reverse_ip import find_ip_neighbors
    ip = (doc["result"].get("ip") or {}).get("ip")
    data = await find_ip_neighbors(doc["result"]["domain"], ip)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"reverse_ip": data}})
    return {"reverse_ip": data, "cached": False}


@api_router.get("/scans/{scan_id}/github-miner")
async def scan_github_miner(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("github_miner"):
        return {"github_miner": doc["github_miner"], "cached": True}
    from integrations.github_miner import search_github
    from user_settings import get_user_key
    gh_key = get_user_key(user, "github")
    data = await search_github(doc["result"]["domain"], gh_key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"github_miner": data}})
    return {"github_miner": data, "cached": False}


@api_router.get("/scans/{scan_id}/bot-resistance")
async def scan_bot_resistance(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("bot_resistance"):
        return {"bot_resistance": doc["bot_resistance"], "cached": True}
    from integrations.bot_resistance import evaluate
    data = await evaluate(doc["result"]["domain"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"bot_resistance": data}})
    return {"bot_resistance": data, "cached": False}


# ─── PROJECT GENESIS ─────────────────────────────────────────────────────────

@api_router.get("/stealth/status")
async def get_stealth_status():
    from integrations.stealth import stealth_status
    return stealth_status()


# ─── CVE + EPSS + KEV CORRELATION ─────────────────────────────────────
@api_router.post("/scans/{scan_id}/cve-correlate")
async def scan_cve_correlate(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.cve_engine import correlate_cves
    tech = (doc.get("result") or {}).get("tech_analysis") or []
    data = await correlate_cves(tech)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"cve_correlation": data}})
    return {"cve_correlation": data, "cached": False}


@api_router.get("/scans/{scan_id}/cve-correlate")
async def scan_cve_get(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    return {"cve_correlation": doc.get("cve_correlation"), "cached": True}


# ─── TYPOSQUATTING HUNTER ─────────────────────────────────────────────
@api_router.post("/scans/{scan_id}/typosquat")
async def scan_typosquat(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.typosquat import probe_variants
    domain = (doc.get("result") or {}).get("domain") or doc.get("domain")
    if not domain:
        raise HTTPException(400, "Scan sin dominio")
    data = await probe_variants(domain)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"typosquat": data}})
    return {"typosquat": data, "cached": False}


@api_router.get("/scans/{scan_id}/typosquat")
async def scan_typosquat_get(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    return {"typosquat": doc.get("typosquat"), "cached": True}


# ─── MITRE ATT&CK MAPPING ─────────────────────────────────────────────
@api_router.get("/scans/{scan_id}/attack-mapping")
async def scan_attack_mapping(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.attack_mapping import map_scan_to_attack
    data = map_scan_to_attack(doc)
    return {"attack_mapping": data}


@api_router.get("/scans/{scan_id}/attack-navigator")
async def scan_attack_navigator(scan_id: str, user=Depends(get_current_user)):
    """Return an ATT&CK Navigator layer JSON (for import in mitre-attack.github.io/attack-navigator)."""
    from fastapi.responses import Response as FResponse
    doc = await _load_scan(scan_id, user)
    from integrations.attack_mapping import map_scan_to_attack, to_stix_layer
    mapping = map_scan_to_attack(doc)
    target = (doc.get("result") or {}).get("domain") or doc.get("domain") or "target"
    layer = to_stix_layer(mapping, target)
    import json
    return FResponse(
        content=json.dumps(layer, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="noctua_{target}_attack_layer.json"'},
    )


# ─── CERT EXPIRATION MONITOR ──────────────────────────────────────────
@api_router.post("/scans/{scan_id}/cert-monitor")
async def scan_cert_monitor(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.cert_monitor import monitor_hosts
    domain = (doc.get("result") or {}).get("domain") or doc.get("domain")
    subs = ((doc.get("result") or {}).get("subdomains") or {}).get("found") or []
    hosts = [domain] + [s.get("hostname") for s in subs
                         if isinstance(s, dict) and s.get("hostname")][:40]
    hosts = [h for h in hosts if h]
    data = await monitor_hosts(hosts)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"cert_monitor": data}})
    return {"cert_monitor": data, "cached": False}


@api_router.get("/scans/{scan_id}/cert-monitor")
async def scan_cert_monitor_get(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    return {"cert_monitor": doc.get("cert_monitor"), "cached": True}


# ─── AI COPILOT ───────────────────────────────────────────────────────
class CopilotChat(BaseModel):
    message: str
    session_id: Optional[str] = None


@api_router.post("/copilot/chat")
async def copilot_chat(payload: CopilotChat, user=Depends(get_current_user)):
    from copilot import chat as copilot_chat_fn
    if not (payload.message or "").strip():
        raise HTTPException(400, "Mensaje vacío")
    if len(payload.message) > 4000:
        raise HTTPException(400, "Mensaje demasiado largo (max 4000 chars)")
    result = await copilot_chat_fn(db, user, payload.message, EMERGENT_LLM_KEY,
                                     session_id=payload.session_id)
    if not result.get("ok"):
        raise HTTPException(502, result.get("error") or "Copilot no respondió")
    return result


@api_router.get("/copilot/history")
async def copilot_history(session_id: str, user=Depends(get_current_user)):
    from copilot import get_history
    msgs = await get_history(db, user["user_id"], session_id)
    return {"session_id": session_id, "messages": msgs}


@api_router.get("/copilot/sessions")
async def copilot_sessions(user=Depends(get_current_user)):
    from copilot import list_sessions
    return {"sessions": await list_sessions(db, user["user_id"])}


# ─── COMPLIANCE SCORECARD ────────────────────────────────────────────
@api_router.get("/scans/{scan_id}/compliance")
async def scan_compliance(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.compliance import compute_scorecard
    return {"compliance": compute_scorecard(doc)}


# ─── ASM INVENTORY + DRIFT ───────────────────────────────────────────
@api_router.get("/asm/inventory")
async def asm_inventory(user=Depends(get_current_user)):
    from integrations.asm_inventory import compute_inventory
    return await compute_inventory(db, user["user_id"])


@api_router.get("/asm/drift")
async def asm_drift(domain: str, user=Depends(get_current_user)):
    from integrations.asm_inventory import compute_drift
    return await compute_drift(db, user["user_id"], domain.lower())


# ─── CVE FEED (real-time) ────────────────────────────────────────────
@api_router.get("/cve-feed")
async def cve_feed(days: int = 7, user=Depends(get_current_user)):
    from integrations.cve_feed import user_cve_feed
    days = max(1, min(days, 30))
    return await user_cve_feed(db, user["user_id"], days=days)


# ─── STRIPE MARKETPLACE ──────────────────────────────────────────────
@api_router.get("/marketplace/products")
async def marketplace_products(user=Depends(get_current_user)):
    from marketplace import MARKETPLACE_CATALOG, is_unlocked
    return {
        "products": [{**p, "unlocked": is_unlocked(user, p["modules_unlocked"][0])}
                      for p in MARKETPLACE_CATALOG],
        "plan": user.get("plan", "free"),
        "unlocks": user.get("unlocks") or [],
    }


class MarketplaceCheckout(BaseModel):
    product_id: str


@api_router.post("/marketplace/checkout")
async def marketplace_checkout(payload: MarketplaceCheckout, user=Depends(get_current_user)):
    import stripe
    from marketplace import get_product
    prod = get_product(payload.product_id)
    if not prod:
        raise HTTPException(404, "Producto desconocido")
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    if not base:
        raise HTTPException(500, "Falta PUBLIC_BASE_URL")

    session_kwargs = dict(
        line_items=[{
            "price_data": {
                "currency": "usd",
                "unit_amount": prod["price_usd"] * 100,
                "product_data": {"name": f"NOCTUA · {prod['name']}",
                                  "description": prod["description"]},
            },
            "quantity": 1,
        }],
        mode="payment",
        success_url=f"{base}/marketplace/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{base}/marketplace",
        metadata={"user_id": user["user_id"], "product_id": prod["id"],
                   "kind": "marketplace"},
    )
    try:
        session = stripe.checkout.Session.create(
            **session_kwargs, managed_payments={"enabled": True})
    except Exception:
        session = stripe.checkout.Session.create(
            **session_kwargs, billing_address_collection="required")

    await db.payment_transactions.insert_one({
        "session_id": session.id,
        "user_id": user["user_id"],
        "kind": "marketplace",
        "product_id": prod["id"],
        "amount": prod["price_usd"] * 100,
        "currency": "usd",
        "status": "initiated",
        "payment_status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"session_id": session.id, "url": session.url,
            "product": prod["name"], "amount": prod["price_usd"]}


@api_router.get("/scans/{scan_id}/waf-bypass")
async def scan_waf_bypass(scan_id: str, use_ai: bool = True,
                           user=Depends(get_current_user)):
    """Suggest WAF bypass tactics for the target based on detected proxies/WAF fingerprints.
    Optional AI narrative (Emergent LLM). Cache result on scan doc.
    """
    doc = await _load_scan(scan_id, user)
    if doc.get("waf_bypass") and not use_ai:
        return {"waf_bypass": doc["waf_bypass"], "cached": True}
    from integrations.waf_bypass import suggest_bypass, ai_summary
    tech = (doc.get("result") or {}).get("tech_analysis") or []
    domain = doc.get("result", {}).get("domain", "")
    data = suggest_bypass(tech, domain)
    if use_ai:
        data["ai_summary"] = await ai_summary(data)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"waf_bypass": data}})
    return {"waf_bypass": data, "cached": False}


@api_router.get("/scans/{scan_id}/jarm")
async def scan_jarm(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("jarm"):
        return {"jarm": doc["jarm"], "cached": True}
    from integrations.jarm_fingerprint import compute_jarm
    data = await compute_jarm(doc["result"]["domain"], 443)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"jarm": data}})
    return {"jarm": data, "cached": False}


@api_router.get("/scans/{scan_id}/honeypot")
async def scan_honeypot(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("honeypot"):
        return {"honeypot": doc["honeypot"], "cached": True}
    from integrations.honeypot_detector import detect_honeypot
    ip = (doc["result"].get("ip") or {}).get("ip")
    data = await detect_honeypot(doc["result"]["domain"], ip)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"honeypot": data}})
    return {"honeypot": data, "cached": False}


@api_router.get("/scans/{scan_id}/evidence-seal")
async def scan_evidence_seal(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.evidence_seal import seal_scan_evidence
    # Always recompute so the seal reflects the current state (deterministic)
    data = seal_scan_evidence(doc)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"evidence": data}})
    return {"evidence": data, "cached": False}


@api_router.post("/scans/{scan_id}/evidence-seal/timestamp")
async def scan_evidence_timestamp(scan_id: str, user=Depends(get_current_user)):
    """Request a real RFC3161 signed timestamp for this scan's chain_hash from FreeTSA."""
    doc = await _load_scan(scan_id, user)
    evidence = doc.get("evidence")
    if not evidence or not evidence.get("chain_hash"):
        # Compute the seal first
        from integrations.evidence_seal import seal_scan_evidence
        evidence = seal_scan_evidence(doc)
        await db.scans.update_one({"scan_id": scan_id}, {"$set": {"evidence": evidence}})
    from integrations.evidence_seal import request_rfc3161_timestamp
    tsr = await request_rfc3161_timestamp(evidence["chain_hash"])
    await db.scans.update_one(
        {"scan_id": scan_id},
        {"$set": {"evidence.rfc3161_timestamp": tsr}})
    return {"chain_hash": evidence["chain_hash"], "rfc3161": tsr}


@api_router.get("/scans/{scan_id}/sleeping-infra")
async def scan_sleeping_infra(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("sleeping_infra"):
        return {"sleeping_infra": doc["sleeping_infra"], "cached": True}
    from integrations.sleeping_infra import hunt_sleeping
    data = hunt_sleeping(doc["result"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"sleeping_infra": data}})
    return {"sleeping_infra": data, "cached": False}


@api_router.get("/scans/{scan_id}/org-map")
async def scan_org_map(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("org_map"):
        return {"org_map": doc["org_map"], "cached": True}
    merged = dict(doc.get("result") or {})
    for k in ("breaches", "metadata", "github_miner"):
        if doc.get(k):
            merged[k] = doc[k]
    from integrations.org_mapping import map_organization
    provider, key, _ = _user_ai(user)
    data = await map_organization(merged, EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"org_map": data}})
    return {"org_map": data, "cached": False}


@api_router.get("/scans/{scan_id}/dev-profile")
async def scan_dev_profile(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("dev_profile"):
        return {"dev_profile": doc["dev_profile"], "cached": True}
    merged = dict(doc.get("result") or {})
    for k in ("js_miner", "api_audit", "cloud_config", "supply_chain"):
        if doc.get(k):
            merged[k] = doc[k]
    from integrations.dev_profile import profile_dev_team
    provider, key, _ = _user_ai(user)
    data = await profile_dev_team(merged, EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"dev_profile": data}})
    return {"dev_profile": data, "cached": False}


# ─── TIME-TRAVEL DIFF ─────────────────────────────────────────────────────────

@api_router.get("/scans/{scan_id}/diff")
async def scan_diff(scan_id: str, vs: Optional[str] = None,
                    user=Depends(get_current_user)):
    """Compare two scans of the same domain. If `vs` omitted, uses the immediately previous scan."""
    current = await _load_scan(scan_id, user)
    domain = current["result"]["domain"]

    if vs:
        previous = await db.scans.find_one(
            {"scan_id": vs, "user_id": user["user_id"]}, {"_id": 0})
        if not previous:
            raise HTTPException(404, "Previous scan not found")
        if (previous.get("result") or {}).get("domain") != domain:
            raise HTTPException(400, "Los dos escaneos deben ser del mismo dominio")
    else:
        previous = await db.scans.find_one(
            {"user_id": user["user_id"],
             "result.domain": domain,
             "scan_id": {"$ne": scan_id},
             "created_at": {"$lt": current.get("created_at") or ""}},
            {"_id": 0}, sort=[("created_at", -1)])
        if not previous:
            return {"available": False,
                    "reason": "No hay escaneo anterior del mismo dominio para comparar."}

    from integrations.scan_delta import compute_diff
    diff = compute_diff(previous, current)
    return {"available": True, "diff": diff}


@api_router.get("/scans/history/{domain}")
async def scan_history_for_domain(domain: str, user=Depends(get_current_user)):
    """List all scans of a given domain by the user (for diff picker)."""
    cursor = db.scans.find(
        {"user_id": user["user_id"], "result.domain": domain.lower()},
        {"_id": 0, "scan_id": 1, "created_at": 1,
         "tags": 1}).sort("created_at", -1)
    scans = await cursor.to_list(200)
    return {"domain": domain, "count": len(scans), "scans": scans}


# ─── AUTO-TAGS ────────────────────────────────────────────────────────────────

@api_router.post("/scans/{scan_id}/auto-tag")
async def scan_auto_tag(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("tags") and doc.get("tag_meta"):
        return {"tags": doc["tags"], "tag_meta": doc["tag_meta"], "cached": True}
    from integrations.auto_tags import suggest_tags
    provider, key, _ = _user_ai(user)
    result = await suggest_tags(doc["result"], EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one(
        {"scan_id": scan_id},
        {"$set": {"tags": result["tags"],
                  "primary_category": result.get("primary_category"),
                  "tag_meta": {
                      "reasoning": result.get("reasoning"),
                      "confidence": result.get("confidence"),
                      "heuristic_tags": result.get("heuristic_tags"),
                      "ai_tags": result.get("ai_tags"),
                  }}})
    return {"tags": result["tags"], "tag_meta": result, "cached": False}


class ManualTagsBody(BaseModel):
    tags: list[str]


@api_router.post("/scans/{scan_id}/tags")
async def scan_manual_tags(scan_id: str, body: ManualTagsBody,
                           user=Depends(get_current_user)):
    from integrations.auto_tags import TAG_ONTOLOGY
    tags = [t for t in body.tags if t in TAG_ONTOLOGY][:12]
    doc = await _load_scan(scan_id, user)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"tags": tags}})
    return {"tags": tags}


# ─── GLOBAL THREAT CORRELATION ────────────────────────────────────────────────

@api_router.get("/scans/{scan_id}/correlate")
async def scan_correlate(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("correlation"):
        return {"correlation": doc["correlation"], "cached": True}
    from integrations.global_correlation import find_correlations
    data = await find_correlations(db, doc["result"], user["user_id"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"correlation": data}})
    return {"correlation": data, "cached": False}


class FlagScanBody(BaseModel):
    flagged: bool
    reason: Optional[str] = None


@api_router.post("/scans/{scan_id}/flag")
async def scan_flag(scan_id: str, body: FlagScanBody,
                    user=Depends(get_current_user)):
    """Flag a scan as suspicious/malicious. Feeds the Global Threat Graph anonymously."""
    doc = await _load_scan(scan_id, user)
    await db.scans.update_one(
        {"scan_id": scan_id},
        {"$set": {"flagged": bool(body.flagged),
                  "flag_reason": (body.reason or "")[:200] if body.flagged else None,
                  "flagged_at": datetime.now(timezone.utc).isoformat() if body.flagged else None}})
    return {"ok": True, "flagged": body.flagged}


# ─── VERSION TRACKING (rollback detector) ─────────────────────────────────────

@api_router.get("/scans/{scan_id}/version-track")
async def scan_version_track(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("version_track"):
        return {"version_track": doc["version_track"], "cached": True}
    from integrations.version_tracker import check_rollbacks
    data = await check_rollbacks(db, doc["result"]["domain"], scan_id,
                                  doc["result"], user["user_id"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"version_track": data}})
    return {"version_track": data, "cached": False}


# ─── BUG BOUNTY REPORT MANAGER ────────────────────────────────────────────────

class BountyReportBody(BaseModel):
    scan_id: str
    finding_key: str            # e.g. "takeover:foo.example.com" or "js_miner:aws_access_key"
    program: Optional[str] = None
    report_id: Optional[str] = None
    status: str = "submitted"   # submitted|duplicate|accepted|informative|rejected
    notes: Optional[str] = None
    severity: Optional[str] = None


@api_router.post("/bounty/reports")
async def create_bounty_report(body: BountyReportBody, user=Depends(get_current_user)):
    if body.status not in {"submitted", "duplicate", "accepted", "informative", "rejected", "triaged"}:
        raise HTTPException(400, "status inválido")
    # Ownership check on the scan
    scan = await db.scans.find_one(
        {"scan_id": body.scan_id, "user_id": user["user_id"]}, {"_id": 0, "scan_id": 1,
                                                                 "result.domain": 1})
    if not scan:
        raise HTTPException(404, "Scan not found")
    doc = {
        "user_id": user["user_id"],
        "scan_id": body.scan_id,
        "domain": (scan.get("result") or {}).get("domain"),
        "finding_key": body.finding_key,
        "program": body.program,
        "report_id": body.report_id,
        "status": body.status,
        "severity": body.severity,
        "notes": (body.notes or "")[:1000],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    result = await db.bounty_reports.insert_one(doc)
    doc["id"] = str(result.inserted_id)
    doc.pop("_id", None)
    return doc


@api_router.get("/bounty/reports")
async def list_bounty_reports(user=Depends(get_current_user),
                              domain: Optional[str] = None,
                              status: Optional[str] = None):
    q = {"user_id": user["user_id"]}
    if domain:
        q["domain"] = domain.lower()
    if status:
        q["status"] = status
    cursor = db.bounty_reports.find(q, {"_id": 0}).sort("created_at", -1)
    items = await cursor.to_list(500)
    return {"count": len(items), "reports": items}


class BountyReportUpdate(BaseModel):
    status: Optional[str] = None
    report_id: Optional[str] = None
    program: Optional[str] = None
    notes: Optional[str] = None
    severity: Optional[str] = None


@api_router.patch("/bounty/reports/{finding_key}")
async def update_bounty_report(finding_key: str, body: BountyReportUpdate,
                                user=Depends(get_current_user),
                                scan_id: Optional[str] = None):
    q = {"user_id": user["user_id"], "finding_key": finding_key}
    if scan_id:
        q["scan_id"] = scan_id
    updates = {"updated_at": datetime.now(timezone.utc).isoformat()}
    for f in ("status", "report_id", "program", "notes", "severity"):
        v = getattr(body, f)
        if v is not None:
            updates[f] = v[:1000] if isinstance(v, str) else v
    r = await db.bounty_reports.update_one(q, {"$set": updates})
    if r.matched_count == 0:
        raise HTTPException(404, "Report not found")
    return {"updated": r.modified_count}


@api_router.delete("/bounty/reports/{finding_key}")
async def delete_bounty_report(finding_key: str, user=Depends(get_current_user),
                                scan_id: Optional[str] = None):
    q = {"user_id": user["user_id"], "finding_key": finding_key}
    if scan_id:
        q["scan_id"] = scan_id
    r = await db.bounty_reports.delete_one(q)
    if r.deleted_count == 0:
        raise HTTPException(404, "Report not found")
    return {"deleted": True}


@api_router.post("/scans/{scan_id}/predict")
async def scan_predict_all(scan_id: str, user=Depends(get_current_user)):
    """Run all IA-heavy predictive modules in parallel and cache each result."""
    doc = await _load_scan(scan_id, user)
    from integrations.risk_oracle import predict_breach
    from integrations.brand_guardian import scan_typosquats
    from integrations.attack_path import build_attack_path
    from integrations.dna_fingerprint import find_siblings
    from user_settings import get_user_key
    provider, key, mode = _user_ai(user)
    shodan_key = get_user_key(user, "shodan")

    oracle, brand, attack, dna = await asyncio.gather(
        predict_breach(doc["result"], EMERGENT_LLM_KEY, provider, key, mode),
        scan_typosquats(doc["result"]["domain"], EMERGENT_LLM_KEY, provider, key),
        build_attack_path(doc["result"], EMERGENT_LLM_KEY, provider, key,
                          apt_persona="none", ai_mode=mode),
        find_siblings(doc["result"], shodan_key),
        return_exceptions=True,
    )

    def _safe(x):
        return {"error": str(x)} if isinstance(x, Exception) else x

    payload = {
        "risk_oracle": _safe(oracle),
        "brand_guardian": _safe(brand),
        "dna": _safe(dna),
    }
    ap_res = _safe(attack)
    await db.scans.update_one(
        {"scan_id": scan_id},
        {"$set": {
            "risk_oracle": payload["risk_oracle"],
            "brand_guardian": payload["brand_guardian"],
            "dna": payload["dna"],
            "attack_paths.attack_path_none": ap_res,
        }},
    )
    payload["attack_path"] = ap_res
    return payload


# ---------- PUBLIC (no auth) endpoints — rate-limited ----------
_public_rate_bucket: dict[str, list[float]] = {}
PUBLIC_RATE_LIMIT = 5          # requests
PUBLIC_RATE_WINDOW = 3600      # per hour


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


@app.get("/api/public/takeover-check")
async def public_takeover_check(request: Request, domain: str):
    """Free public tier: quick takeover scan for a single domain.
    Rate-limited to 5 requests / hour per IP. Preview mode — full report requires Pro.
    """
    _rate_limit_check(request)
    domain = (domain or "").strip().lower()
    if not domain or len(domain) < 4 or "." not in domain:
        raise HTTPException(400, "Dominio inválido")
    try:
        assert_public_host(domain)  # anti-SSRF guard on the public/unauthenticated tier
    except ValueError as e:
        raise HTTPException(400, str(e))

    from integrations.takeover_scanner import scan_takeovers
    from osint_engine import find_subdomains
    # Use only a small subset of subdomains to keep it fast for the free tier
    subs_info = await find_subdomains(domain)
    subs = [s["subdomain"] for s in (subs_info.get("found") or [])][:15]
    result = await scan_takeovers(subs, domain)

    # Track the public scan for the live global counter
    try:
        await db.public_scans.insert_one({
            "domain": domain,
            "checked_subdomains": result.get("checked", 0),
            "vulnerable_count": result.get("vulnerable_count", 0),
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:
        logger.exception("public_scans insert failed")

    return {
        "tier": "free_public",
        "domain": domain,
        "checked_subdomains": result["checked"],
        "with_cname": result["with_cname"],
        "vulnerable_count": result["vulnerable_count"],
        "results": result["results"][:20],  # cap output
        "explanation": result["explanation"],
        "upsell": {
            "message": "Escaneo básico. Consigue el reporte completo con NOCTUA Pro: fingerprint de tecnologías, "
                       "geolocalización, Shodan + AbuseIPDB, resumen IA, PDF exportable y monitorización continua.",
            "cta_url": "https://noctua.osint/pricing",
            "features_locked": [
                "Análisis IA de riesgos con Claude Sonnet 4.5",
                "Reputación IP con AbuseIPDB",
                "Shodan CVEs + puertos indexados",
                "Cloud storage enumeration (S3/Azure/GCS)",
                "Extractor de metadatos de documentos",
                "Mapa de red interactivo",
                "PDF ejecutivo con portada de riesgo",
                "Escaneos programados + alertas Slack",
            ],
        },
    }


@api_router.get("/")
async def root():
    return {"service": "OSINT Scanner API", "status": "ok"}


@api_router.get("/health")
async def health():
    """Liveness/readiness probe: checks MongoDB connectivity."""
    db_ok = True
    try:
        await db.command("ping")
    except Exception:
        db_ok = False
    return {"status": "ok" if db_ok else "degraded", "db": db_ok}


# ---------- PUBLIC STATS (no auth, cached) ----------
_stats_cache: dict = {"at": None, "data": None}
_STATS_TTL = 300  # seconds


@app.get("/api/public/stats")
async def public_stats():
    """Aggregated NOCTUA stats for the landing page. Cached for 5 minutes."""
    now_ts = datetime.now(timezone.utc).timestamp()
    if _stats_cache["at"] and (now_ts - _stats_cache["at"]) < _STATS_TTL and _stats_cache["data"]:
        return {**_stats_cache["data"], "cached": True}

    month_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    try:
        public_scans_month = await db.public_scans.count_documents({"created_at": {"$gte": month_ago}})
    except Exception:
        public_scans_month = 0
    try:
        auth_scans_month = await db.scans.count_documents({"created_at": {"$gte": month_ago}})
    except Exception:
        auth_scans_month = 0
    try:
        total_scans = await db.scans.estimated_document_count() + await db.public_scans.estimated_document_count()
    except Exception:
        total_scans = 0
    try:
        # Sum vulnerable_count from public_scans
        pipeline = [{"$group": {"_id": None, "n": {"$sum": "$vulnerable_count"}}}]
        agg = await db.public_scans.aggregate(pipeline).to_list(1)
        takeovers_found = int(agg[0]["n"]) if agg else 0
    except Exception:
        takeovers_found = 0
    try:
        active_users = await db.users.estimated_document_count()
    except Exception:
        active_users = 0

    data = {
        "scans_this_month": public_scans_month + auth_scans_month,
        "public_scans_this_month": public_scans_month,
        "total_scans": total_scans,
        "takeovers_detected": takeovers_found,
        "active_users": active_users,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    _stats_cache["at"] = now_ts
    _stats_cache["data"] = data
    return {**data, "cached": False}



app.include_router(api_router)
app.include_router(payments_mod.build_router(db, get_current_user))
app.include_router(schedules_mod.build_router(db, get_current_user))
app.include_router(telegram_bot_mod.build_router(db, get_current_user))

# CORS: prefer an explicit allowlist. Combining allow_credentials=True with a
# wildcard origin is unsafe, so we no longer default to "*".
_cors_env = os.environ.get('CORS_ORIGINS', '').strip()
if _cors_env:
    _cors_origins = [o.strip() for o in _cors_env.split(',') if o.strip()]
else:
    _cors_origins = ['http://localhost:3000']
    logger.warning(
        "CORS_ORIGINS not set — defaulting to %s. Set an explicit allowlist in production.",
        _cors_origins,
    )

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Adds hardening response headers (X-Content-Type-Options, X-Frame-Options, ...).
app.add_middleware(SecurityHeadersMiddleware)


_scheduler_task = None


@app.on_event("startup")
async def start_scheduler():
    global _scheduler_task
    _scheduler_task = asyncio.create_task(schedules_mod.scheduler_loop(db, interval_seconds=60))
    logger.info("Scheduler task started")


@app.on_event("shutdown")
async def shutdown_db_client():
    global _scheduler_task
    if _scheduler_task:
        _scheduler_task.cancel()
    client.close()

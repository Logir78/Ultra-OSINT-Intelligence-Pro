"""Routes: auth. Extracted from server.py."""
from fastapi import APIRouter, HTTPException, Request, Response, Depends, Header
from fastapi.responses import JSONResponse
from typing import Optional
from datetime import datetime, timezone, timedelta
import os
import uuid
import asyncio
import httpx
from osint_engine import analyze_domain
from security import assert_public_host
from app.core import (
    db, client, logger, EMERGENT_LLM_KEY, get_current_user,
    _generate_ai_summary, _collect_scan_ips, _is_admin, _load_scan, _user_ai,
    _rate_limit_check, _public_rate_bucket, PUBLIC_RATE_LIMIT, PUBLIC_RATE_WINDOW,
    _stats_cache, _STATS_TTL,
)

router = APIRouter()


@router.post("/auth/session")
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


@router.get("/auth/me")
async def auth_me(user=Depends(get_current_user)):
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "name": user["name"],
        "picture": user.get("picture"),
        "plan": user.get("plan", "free"),
        "slack_webhook_url": user.get("slack_webhook_url"),
    }


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("session_token")
    if token:
        await db.user_sessions.delete_one({"session_token": token})
    response.delete_cookie("session_token", path="/", samesite="none", secure=True)
    return {"ok": True}

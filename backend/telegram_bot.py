"""Telegram Bot handler — /start welcome + conversational onboarding for the admin.

Implements a webhook endpoint that receives updates from Telegram and:
1. Responds to /start with the Project Genesis welcome banner (admin only).
2. Only sends welcome messages to the configured admin Chat ID; other chats
   receive a discreet "Este bot es privado. Tu Chat ID es: ..." reply so
   the admin can register them if desired.
3. Provides admin endpoints to set/remove the webhook URL.
4. Conversational commands for the admin:
   /scan <domain> — trigger an OSINT scan and reply with the risk summary
   /scans          — list the last 5 scans with clickable links
   /subscribe      — return Stripe Checkout URL for Pro
   /pricing        — same as /subscribe
   /help           — show command list
"""
import asyncio
import logging
import os
import re
import uuid
import httpx
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel

log = logging.getLogger("telegram_bot")

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")

WELCOME_MESSAGE = (
    "🛰️ *PROJECT GENESIS: NODO OPERATIVO ACTIVADO*\n\n"
    "*Estado del Sistema:* ONLINE\n"
    "*Nivel de Enlace:* Encriptado\n"
    "*Protocolo de Alerta:* ACTIVO\n\n"
    "Bienvenido al centro de notificaciones de Project Genesis. "
    "Desde este canal recibirás inteligencia en tiempo real sobre:\n\n"
    "🛡️ Detección de vulnerabilidades críticas.\n"
    "📡 Nuevos activos y subdominios descubiertos.\n"
    "🚨 Intentos de acceso no autorizados al Dashboard.\n"
    "📊 Resúmenes ejecutivos de IA.\n\n"
    "_Esperando transmisiones..._\n\n"
    "Escribe /help para ver los comandos disponibles."
)

HELP_MESSAGE = (
    "🎯 *NOCTUA · Comandos operativos*\n\n"
    "`/scan example.com` — Lanza un escaneo OSINT y devuelve el resumen.\n"
    "`/scans` — Muestra los últimos 5 escaneos.\n"
    "`/pricing` — Enlace de suscripción Pro.\n"
    "`/status` — Estado del nodo.\n"
    "`/id` — Muestra tu Chat ID.\n"
    "`/help` — Este menú.\n\n"
    "_Solo el admin (Chat ID autorizado) puede lanzar escaneos y ver el historial._"
)

CHAT_ID_HINT = (
    "🔒 *NOCTUA · Este bot es privado.*\n\n"
    "Tu acceso no está autorizado en este canal, pero tu identificador es:\n\n"
    "`{chat_id}`\n\n"
    "Si eres el operador, copia este *Chat ID* y pégalo en:\n"
    "_NOCTUA · Ajustes → Telegram → Chat ID_ para vincular este canal."
)


async def send_message(bot_token: str, chat_id: str, text: str,
                       parse_mode: str = "Markdown") -> dict:
    """Send a message via the Telegram Bot API. Returns {ok, error?}"""
    if not bot_token or not chat_id:
        return {"ok": False, "error": "missing bot_token or chat_id"}
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": parse_mode,
                    "disable_web_page_preview": True,
                },
            )
        if r.status_code == 200:
            return {"ok": True}
        try:
            desc = r.json().get("description", "")
        except Exception:
            desc = r.text[:120]
        return {"ok": False, "error": f"HTTP {r.status_code}: {desc}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def _find_admin_user(db) -> Optional[dict]:
    """Return the primary admin user (owner of AUTHORIZED_EMAILS[0]) if configured."""
    authorized_raw = os.environ.get("AUTHORIZED_EMAILS", "").strip()
    if not authorized_raw:
        return None
    admin_email = authorized_raw.split(",")[0].strip().lower()
    if not admin_email:
        return None
    return await db.users.find_one({"email": admin_email}, {"_id": 0})


# ─── Conversational command helpers ──────────────────────────────────
def _risk_from_scan(analysis: dict) -> int:
    """Estimate a 0-100 risk score from a scan analysis (mirrors intel logic)."""
    sec = (analysis or {}).get("security") or {}
    # Score = 100 - avg(basic, medium, advanced)
    scores = []
    for k in ("basic", "medium", "advanced"):
        v = (sec.get(k) or {}).get("score")
        if isinstance(v, int):
            scores.append(v)
    posture = sum(scores) / len(scores) if scores else 50
    open_ports = len(((analysis or {}).get("ports") or {}).get("open_ports") or [])
    port_penalty = min(open_ports * 3, 20)
    return int(max(0, min(100, (100 - posture) + port_penalty)))


async def _run_scan_and_reply(db, admin_user: dict, bot_token: str, chat_id: str, domain: str):
    """Execute a scan and send a summary back via Telegram."""
    try:
        from osint_engine import analyze_domain
        analysis = await analyze_domain(domain, extended_ports=False)
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        doc = {
            "scan_id": scan_id,
            "user_id": admin_user["user_id"],
            "domain": analysis["domain"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "extended_ports": False,
            "result": analysis,
            "source": "telegram_bot",
        }
        await db.scans.insert_one(doc)

        risk = _risk_from_scan(analysis)
        ip = (analysis.get("ip") or {}).get("ip") or "N/A"
        open_ports = len((analysis.get("ports") or {}).get("open_ports") or [])
        subs = len((analysis.get("subdomains") or {}).get("found") or [])
        base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
        scan_url = f"{base}/scan/{scan_id}" if base else ""

        risk_emoji = "🔴" if risk >= 70 else "🟡" if risk >= 40 else "🟢"
        msg = (
            f"{risk_emoji} *Escaneo completado · `{domain}`*\n\n"
            f"*Riesgo estimado:* `{risk}/100`\n"
            f"*IP:* `{ip}`\n"
            f"*Puertos abiertos:* {open_ports}\n"
            f"*Subdominios detectados:* {subs}\n"
        )
        if scan_url:
            msg += f"\n[Ver informe completo]({scan_url})"
        await send_message(bot_token, chat_id, msg)
    except Exception as e:
        log.exception("telegram scan failed")
        await send_message(bot_token, chat_id,
            f"❌ Fallo al escanear `{domain}`: {str(e)[:120]}")


async def _reply_recent_scans(db, admin_user: dict, bot_token: str, chat_id: str):
    cursor = db.scans.find(
        {"user_id": admin_user["user_id"]},
        {"_id": 0, "scan_id": 1, "domain": 1, "created_at": 1},
    ).sort("created_at", -1).limit(5)
    items = await cursor.to_list(length=5)
    if not items:
        await send_message(bot_token, chat_id,
            "📭 No hay escaneos aún. Prueba `/scan example.com` para empezar.")
        return
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    lines = ["📋 *Últimos escaneos*\n"]
    for it in items:
        d = it.get("domain", "?")
        sid = it.get("scan_id", "")
        ts = (it.get("created_at") or "")[:16].replace("T", " ")
        if base:
            lines.append(f"• [{d}]({base}/scan/{sid}) · _{ts}_")
        else:
            lines.append(f"• *{d}* · `{sid}` · _{ts}_")
    await send_message(bot_token, chat_id, "\n".join(lines))


async def _reply_pricing_link(db, admin_user: dict, bot_token: str, chat_id: str):
    """Create a Stripe Checkout session for the admin and reply with the URL."""
    try:
        import stripe
        base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
        if not base:
            await send_message(bot_token, chat_id,
                "⚠️ No hay URL pública configurada. Configura `PUBLIC_BASE_URL`.")
            return
        prices = stripe.Price.list(lookup_keys=["pro_monthly"], active=True, limit=1).data
        if not prices:
            await send_message(bot_token, chat_id, "⚠️ El plan Pro no está configurado en Stripe todavía.")
            return
        price = prices[0]
        kwargs = dict(
            line_items=[{"price": price.id, "quantity": 1}],
            mode="subscription" if price.recurring else "payment",
            success_url=f"{base}/payment/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{base}/payment/cancel",
            metadata={"user_id": admin_user["user_id"], "lookup_key": "pro_monthly",
                       "source": "telegram_bot"},
        )
        try:
            session = stripe.checkout.Session.create(**kwargs, managed_payments={"enabled": True})
        except Exception:
            session = stripe.checkout.Session.create(
                **kwargs, automatic_tax={"enabled": True}, billing_address_collection="required")

        amount = (price.unit_amount or 0) / 100
        currency = (price.currency or "usd").upper()
        msg = (
            "🚀 *NOCTUA · Plan Pro*\n\n"
            f"*Precio:* {amount:.2f} {currency} / mes\n\n"
            "Desbloquea:\n"
            "• Escaneos ilimitados con scheduler\n"
            "• Alertas Slack + Telegram + Email\n"
            "• Predictive Intelligence completa\n"
            "• Bug Bounty Toolkit sin límites\n"
            "• PDF Executive Reports\n\n"
            f"[Suscribirse ahora]({session.url})"
        )
        await send_message(bot_token, chat_id, msg)

        await db.payment_transactions.insert_one({
            "session_id": session.id,
            "user_id": admin_user["user_id"],
            "lookup_key": "pro_monthly",
            "amount": price.unit_amount or 0,
            "currency": price.currency,
            "status": "initiated",
            "payment_status": "pending",
            "source": "telegram_bot",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        log.exception("telegram pricing failed")
        await send_message(bot_token, chat_id,
            f"❌ Fallo al generar checkout: {str(e)[:120]}")


def build_router(db, get_current_user):
    router = APIRouter(prefix="/api/telegram")

    class WebhookConfig(BaseModel):
        webhook_secret: Optional[str] = None  # optional secret path segment

    # ─── Public webhook endpoint (called by Telegram) ────────────────────
    @router.post("/webhook/{secret}")
    async def telegram_webhook(secret: str, request: Request):
        """Receive an update from Telegram. `secret` must match the admin's bot_token
        (last 12 chars) to prevent unauthorized posts."""
        payload = await request.json()

        admin_user = await _find_admin_user(db)
        if not admin_user:
            return {"ok": True}  # silently drop — no admin configured
        tg = admin_user.get("telegram") or {}
        bot_token = (tg.get("bot_token") or "").strip()
        admin_chat_id = str((tg.get("chat_id") or "")).strip()

        if not bot_token:
            return {"ok": True}

        # Validate secret path (use last 12 chars of token as URL secret)
        expected = bot_token.split(":", 1)[-1][-12:]
        if secret != expected:
            log.warning("telegram webhook: bad secret")
            raise HTTPException(status_code=403, detail="forbidden")

        message = payload.get("message") or payload.get("edited_message") or {}
        chat = message.get("chat") or {}
        chat_id = str(chat.get("id") or "").strip()
        text = (message.get("text") or "").strip()
        sender_name = (chat.get("first_name") or chat.get("username") or "").strip()

        if not chat_id:
            return {"ok": True}

        # /start handler
        if text.startswith("/start"):
            if chat_id == admin_chat_id:
                # Authorized — send full welcome
                await send_message(bot_token, chat_id, WELCOME_MESSAGE)
                # Log it
                await db.telegram_events.insert_one({
                    "type": "start_welcome",
                    "chat_id": chat_id,
                    "user": sender_name,
                    "at": datetime.now(timezone.utc).isoformat(),
                })
            else:
                # Unauthorized chat — hint the Chat ID so the admin can register it
                await send_message(bot_token, chat_id,
                                    CHAT_ID_HINT.format(chat_id=chat_id))
                await db.telegram_events.insert_one({
                    "type": "start_unauthorized",
                    "chat_id": chat_id,
                    "user": sender_name,
                    "at": datetime.now(timezone.utc).isoformat(),
                })
        elif text.startswith("/chatid") or text.startswith("/id"):
            # Utility: reply with the caller's chat ID (safe — sent only back to them)
            await send_message(bot_token, chat_id,
                                f"Tu *Chat ID* es: `{chat_id}`")
        elif text.startswith("/status"):
            # Only the admin sees status
            if chat_id == admin_chat_id:
                await send_message(bot_token, chat_id,
                                    "🟢 *NOCTUA · Nodo operativo*\nSistema online. Canal encriptado. En escucha.")
        elif text.startswith("/help"):
            if chat_id == admin_chat_id:
                await send_message(bot_token, chat_id, HELP_MESSAGE)
        elif text.startswith("/scan"):
            if chat_id != admin_chat_id:
                return {"ok": True}  # silent for unauthorized
            parts = text.split(maxsplit=1)
            if len(parts) < 2 or not DOMAIN_RE.match(parts[1].strip().lower()):
                await send_message(bot_token, chat_id,
                    "❌ Uso: `/scan example.com`\nEl dominio debe ser válido (ej: `github.com`).")
                return {"ok": True}
            domain = parts[1].strip().lower()
            # Ack immediately
            await send_message(bot_token, chat_id,
                f"🎯 Iniciando escaneo de `{domain}`\nEsto puede tardar 20-40s...")
            # Fire the scan in the background so we don't hold the webhook
            asyncio.create_task(_run_scan_and_reply(db, admin_user, bot_token, chat_id, domain))
        elif text.startswith("/scans") or text.startswith("/list"):
            if chat_id != admin_chat_id:
                return {"ok": True}
            await _reply_recent_scans(db, admin_user, bot_token, chat_id)
        elif text.startswith("/pricing") or text.startswith("/subscribe") or text.startswith("/pro"):
            if chat_id != admin_chat_id:
                return {"ok": True}
            await _reply_pricing_link(db, admin_user, bot_token, chat_id)
        else:
            # For unauthorized chats we don't respond to arbitrary messages
            # For the admin chat we ignore other messages silently
            pass

        return {"ok": True}

    # ─── Admin: setup webhook URL on Telegram ────────────────────────────
    def _require_admin(user: dict):
        authorized_raw = os.environ.get("AUTHORIZED_EMAILS", "").strip()
        if not authorized_raw:
            return
        emails = {e.strip().lower() for e in authorized_raw.split(",") if e.strip()}
        if user.get("email", "").lower() not in emails:
            raise HTTPException(403, "Solo el administrador puede configurar el bot")

    @router.post("/webhook/setup")
    async def setup_webhook(user=Depends(get_current_user)):
        """Register the webhook URL with Telegram so the bot receives updates."""
        _require_admin(user)
        tg = user.get("telegram") or {}
        bot_token = (tg.get("bot_token") or "").strip()
        if not bot_token:
            raise HTTPException(400, "Configura primero el Bot Token en Ajustes → Telegram")

        # Compute public webhook URL (uses REACT_APP_BACKEND_URL from frontend env)
        base = os.environ.get("PUBLIC_BASE_URL") or ""
        if not base:
            # Try to reconstruct from the caller's request would require passing request; use fallback
            raise HTTPException(500,
                "Falta PUBLIC_BASE_URL en el entorno. Configúrala con la URL pública del backend.")

        secret = bot_token.split(":", 1)[-1][-12:]
        webhook_url = f"{base.rstrip('/')}/api/telegram/webhook/{secret}"

        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.post(
                f"https://api.telegram.org/bot{bot_token}/setWebhook",
                json={"url": webhook_url,
                       "allowed_updates": ["message", "edited_message"],
                       "drop_pending_updates": True},
            )
        if r.status_code != 200 or not (r.json() or {}).get("ok"):
            raise HTTPException(502, f"Telegram rechazó setWebhook: {r.text[:200]}")

        await db.users.update_one(
            {"user_id": user["user_id"]},
            {"$set": {"telegram.webhook_url": webhook_url,
                       "telegram.webhook_set_at": datetime.now(timezone.utc).isoformat()}},
        )
        return {"ok": True, "webhook_url": webhook_url}

    @router.post("/webhook/delete")
    async def delete_webhook(user=Depends(get_current_user)):
        _require_admin(user)
        tg = user.get("telegram") or {}
        bot_token = (tg.get("bot_token") or "").strip()
        if not bot_token:
            raise HTTPException(400, "No hay bot configurado")
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.post(f"https://api.telegram.org/bot{bot_token}/deleteWebhook",
                              json={"drop_pending_updates": True})
        await db.users.update_one(
            {"user_id": user["user_id"]},
            {"$unset": {"telegram.webhook_url": "", "telegram.webhook_set_at": ""}},
        )
        return {"ok": r.status_code == 200}

    @router.get("/webhook/status")
    async def webhook_status(user=Depends(get_current_user)):
        _require_admin(user)
        tg = user.get("telegram") or {}
        bot_token = (tg.get("bot_token") or "").strip()
        if not bot_token:
            return {"configured": False}
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(f"https://api.telegram.org/bot{bot_token}/getWebhookInfo")
        info = (r.json() or {}).get("result") or {}
        return {
            "configured": bool(info.get("url")),
            "url": info.get("url"),
            "pending_update_count": info.get("pending_update_count", 0),
            "last_error_message": info.get("last_error_message"),
            "stored_webhook_url": tg.get("webhook_url"),
            "stored_webhook_set_at": tg.get("webhook_set_at"),
        }

    @router.post("/send-welcome")
    async def send_welcome_now(user=Depends(get_current_user)):
        """Manually trigger the welcome banner to the admin's Chat ID.
        Useful when the admin doesn't want to use /start."""
        _require_admin(user)
        tg = user.get("telegram") or {}
        bot_token = (tg.get("bot_token") or "").strip()
        chat_id = str((tg.get("chat_id") or "")).strip()
        if not bot_token or not chat_id:
            raise HTTPException(400, "Configura Bot Token y Chat ID en Ajustes → Telegram")
        result = await send_message(bot_token, chat_id, WELCOME_MESSAGE)
        if not result.get("ok"):
            raise HTTPException(502, f"Fallo Telegram: {result.get('error')}")
        return {"ok": True, "sent_to": chat_id}

    return router

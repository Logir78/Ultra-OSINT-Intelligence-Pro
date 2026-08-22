"""Routes: settings. Extracted from server.py."""
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
from app.models import UserPrefs, ClaudeTierPref, EmailPrefs

router = APIRouter()


@router.get("/settings/keys")
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


@router.post("/settings/test-key")
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


@router.get("/settings/export")
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


@router.post("/settings/keys")
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


@router.post("/settings/ai")
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


@router.get("/settings/preferences")
async def get_prefs(user=Depends(get_current_user)):
    p = user.get("preferences") or {}
    return {
        "risk_threshold": p.get("risk_threshold", 50),
        "notes": p.get("notes", ""),
    }


@router.get("/settings/access-whitelist")
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


@router.get("/settings/security-log")
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


@router.post("/settings/preferences")
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


@router.get("/settings/claude")
async def get_claude_tier(user=Depends(get_current_user)):
    from claude_models import CLAUDE_TIER_META, DEFAULT_TIER
    active = ((user.get("preferences") or {}).get("claude_tier")) or DEFAULT_TIER
    return {
        "active": active,
        "default": DEFAULT_TIER,
        "tiers": CLAUDE_TIER_META,
    }


@router.post("/settings/claude")
async def set_claude_tier(payload: ClaudeTierPref, user=Depends(get_current_user)):
    from claude_models import CLAUDE_TIERS
    if payload.tier not in CLAUDE_TIERS:
        raise HTTPException(400, f"Tier inválido. Usa uno de: {list(CLAUDE_TIERS)}")
    await db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"preferences.claude_tier": payload.tier}},
    )
    return {"active": payload.tier, "model": CLAUDE_TIERS[payload.tier]}


@router.get("/settings/email")
async def get_email_prefs(user=Depends(get_current_user)):
    from emailer import is_configured, SENDER_EMAIL
    cfg = user.get("email_alerts") or {}
    return {
        "enabled": bool(cfg.get("enabled")),
        "address": cfg.get("address") or user.get("email"),
        "resend_configured": is_configured(),
        "sender": SENDER_EMAIL,
    }


@router.post("/settings/email")
async def set_email_prefs(payload: EmailPrefs, user=Depends(get_current_user)):
    addr = (payload.address or "").strip().lower() or user.get("email")
    if addr and ("@" not in addr or "." not in addr.split("@")[-1]):
        raise HTTPException(400, "Dirección de email inválida")
    await db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"email_alerts": {"enabled": bool(payload.enabled), "address": addr}}},
    )
    return {"enabled": bool(payload.enabled), "address": addr}


@router.post("/settings/email/test")
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

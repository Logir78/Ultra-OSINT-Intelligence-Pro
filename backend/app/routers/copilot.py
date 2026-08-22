"""Routes: copilot. Extracted from server.py."""
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
from app.models import CopilotChat

router = APIRouter()


@router.post("/copilot/chat")
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


@router.get("/copilot/history")
async def copilot_history(session_id: str, user=Depends(get_current_user)):
    from copilot import get_history
    msgs = await get_history(db, user["user_id"], session_id)
    return {"session_id": session_id, "messages": msgs}


@router.get("/copilot/sessions")
async def copilot_sessions(user=Depends(get_current_user)):
    from copilot import list_sessions
    return {"sessions": await list_sessions(db, user["user_id"])}

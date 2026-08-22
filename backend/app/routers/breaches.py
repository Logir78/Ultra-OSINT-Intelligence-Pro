"""Routes: breaches. Extracted from server.py."""
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


@router.post("/breaches/lookup")
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


@router.get("/breaches/history")
async def breaches_history(user=Depends(get_current_user)):
    cursor = db.breach_lookups.find(
        {"user_id": user["user_id"]}, {"_id": 0}
    ).sort("created_at", -1).limit(30)
    return await cursor.to_list(length=30)

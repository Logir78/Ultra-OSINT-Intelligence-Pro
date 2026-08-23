"""Usage metering + plan limits (P1 · negocio).

Cuenta los escaneos por usuario y mes, y aplica el límite de su plan. Es lo que
convierte la API en un producto con tiers (free / pro / enterprise).

Límites configurables por entorno:
    FREE_SCAN_LIMIT (def. 20) · PRO_SCAN_LIMIT (def. 500) · ENTERPRISE = ilimitado
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import HTTPException

COLLECTION = "usage"


def plan_limits() -> dict:
    return {
        "free": int(os.environ.get("FREE_SCAN_LIMIT", "20")),
        "pro": int(os.environ.get("PRO_SCAN_LIMIT", "500")),
        "enterprise": -1,  # ilimitado
    }


def plan_of(user: dict) -> str:
    p = (user.get("plan") or "free").lower()
    return p if p in plan_limits() else "free"


def limit_for(plan: str) -> int:
    return plan_limits().get(plan, plan_limits()["free"])


def _period() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


async def get_usage(db, user: dict) -> dict:
    plan = plan_of(user)
    limit = limit_for(plan)
    period = _period()
    rec = await db[COLLECTION].find_one(
        {"user_id": user["user_id"], "period": period}, {"_id": 0})
    used = (rec or {}).get("scans", 0)
    remaining = -1 if limit < 0 else max(0, limit - used)
    return {
        "plan": plan,
        "period": period,
        "used": used,
        "limit": limit,           # -1 = ilimitado
        "remaining": remaining,   # -1 = ilimitado
    }


async def check_and_increment(db, user: dict) -> dict:
    """Suma un escaneo si queda cuota; si no, lanza 402 (mejora tu plan)."""
    plan = plan_of(user)
    limit = limit_for(plan)
    period = _period()

    if limit >= 0:
        rec = await db[COLLECTION].find_one(
            {"user_id": user["user_id"], "period": period}, {"_id": 0})
        used = (rec or {}).get("scans", 0)
        if used >= limit:
            raise HTTPException(
                status_code=402,
                detail={
                    "error": "quota_exceeded",
                    "plan": plan,
                    "limit": limit,
                    "used": used,
                    "message": f"Has alcanzado el límite de {limit} escaneos de tu plan '{plan}' este mes. "
                               f"Mejora a Pro para más.",
                },
            )

    await db[COLLECTION].update_one(
        {"user_id": user["user_id"], "period": period},
        {"$inc": {"scans": 1},
         "$setOnInsert": {"user_id": user["user_id"], "period": period}},
        upsert=True,
    )
    return await get_usage(db, user)

"""API keys — acceso programático a la API (P1 · crecimiento).

Permite integrar el motor de NOCTUA desde scripts/otros productos con una clave,
sin cookies de sesión. La clave se muestra UNA sola vez al crearla; solo guardamos
su hash SHA-256. Cada endpoint que use `get_current_user` acepta la clave
automáticamente (vía cabecera `X-API-Key` o `Authorization: Bearer nk_...`).
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone

COLLECTION = "api_keys"
PREFIX = "nk_"  # NOCTUA key


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def create_api_key(db, user_id: str, name: str) -> dict:
    """Create a key. Returns the PLAINTEXT key once (never stored)."""
    secret = PREFIX + secrets.token_hex(20)      # nk_ + 40 hex chars
    key_id = f"key_{uuid.uuid4().hex[:12]}"
    display_prefix = secret[:11]                 # nk_ + 8 chars, for identification
    await db[COLLECTION].insert_one({
        "key_id": key_id,
        "user_id": user_id,
        "name": name,
        "key_hash": _hash(secret),
        "prefix": display_prefix,
        "created_at": _now(),
        "last_used_at": None,
        "revoked": False,
    })
    return {"key_id": key_id, "name": name, "prefix": display_prefix, "api_key": secret,
            "warning": "Guarda esta clave ahora — no se volverá a mostrar."}


async def list_api_keys(db, user_id: str) -> list[dict]:
    cur = db[COLLECTION].find(
        {"user_id": user_id, "revoked": {"$ne": True}},
        {"_id": 0, "key_hash": 0},
    ).sort("created_at", -1)
    return await cur.to_list(100)


async def revoke_api_key(db, user_id: str, key_id: str) -> bool:
    res = await db[COLLECTION].update_one(
        {"key_id": key_id, "user_id": user_id},
        {"$set": {"revoked": True, "revoked_at": _now()}},
    )
    return getattr(res, "modified_count", 1) != 0


async def verify_api_key(db, presented: str):
    """Return the owning user doc for a valid key, else None. Updates last_used."""
    if not presented or not presented.startswith(PREFIX):
        return None
    rec = await db[COLLECTION].find_one({"key_hash": _hash(presented)}, {"_id": 0})
    if not rec or rec.get("revoked"):
        return None
    # best-effort usage stamp
    try:
        await db[COLLECTION].update_one({"key_id": rec["key_id"]},
                                        {"$set": {"last_used_at": _now()}})
    except Exception:
        pass
    return await db.users.find_one({"user_id": rec["user_id"]}, {"_id": 0})

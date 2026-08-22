"""Native email + password authentication (Fase 4 — decoupling from Emergent).

The app already uses self-hosted, server-side sessions (an opaque token stored
in `db.user_sessions`, read by `get_current_user`). Only the OAuth *login* step
depended on `demobackend.emergentagent.com`. This module adds a native login that
creates the exact same user + session records, so nothing else has to change and
sessions remain revocable server-side (more robust than a stateless JWT).

Passwords are hashed with bcrypt (passlib). Existing OAuth users simply have no
`password_hash` and keep using the Emergent flow.
"""
from __future__ import annotations

import os
import secrets
import uuid
from datetime import datetime, timezone, timedelta

import bcrypt

from app.core import db

SESSION_DAYS = int(os.environ.get("SESSION_DAYS", "7"))
# In production cookies must be Secure+SameSite=None (cross-site). For local
# http testing set COOKIE_SECURE=0.
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"


def hash_password(password: str) -> str:
    # bcrypt only considers the first 72 bytes; slice to avoid backend errors.
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:72], hashed.encode("utf-8"))
    except Exception:
        return False


def email_allowed(email: str) -> bool:
    """Honor the same AUTHORIZED_EMAILS allowlist the OAuth flow uses."""
    raw = os.environ.get("AUTHORIZED_EMAILS", "").strip()
    if not raw:
        return True
    allowed = {e.strip().lower() for e in raw.split(",") if e.strip()}
    return email.lower() in allowed


async def create_session(user_id: str) -> str:
    """Create a server-side session row and return its opaque token."""
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    await db.user_sessions.insert_one({
        "user_id": user_id,
        "session_token": token,
        "expires_at": (now + timedelta(days=SESSION_DAYS)).isoformat(),
        "created_at": now.isoformat(),
    })
    return token


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="none" if COOKIE_SECURE else "lax",
        path="/",
        max_age=SESSION_DAYS * 24 * 60 * 60,
    )


async def register_user(email: str, password: str, name: str) -> dict:
    """Create a new user with a hashed password. Returns the user doc."""
    email = email.lower().strip()
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    await db.users.insert_one({
        "user_id": user_id,
        "email": email,
        "name": name,
        "picture": None,
        "password_hash": hash_password(password),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"user_id": user_id, "email": email, "name": name}

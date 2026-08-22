"""Native auth routes: register + login with email & password (Fase 4).

Coexists with the Emergent OAuth flow in `auth.py` — this does not remove it.
Enable/disable with AUTH_NATIVE_ENABLED (default on).
"""
import os

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, EmailStr, Field

from app.core import db
from app.auth_native import (
    verify_password, email_allowed, create_session, set_session_cookie, register_user,
)

router = APIRouter()

_ENABLED = os.environ.get("AUTH_NATIVE_ENABLED", "1") == "1"


class RegisterBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: str = Field(min_length=1, max_length=120)


class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


def _guard():
    if not _ENABLED:
        raise HTTPException(status_code=404, detail="Native auth disabled")


@router.post("/auth/register")
async def register(body: RegisterBody, response: Response):
    _guard()
    email = body.email.lower().strip()
    if not email_allowed(email):
        raise HTTPException(status_code=403, detail="Email no autorizado")
    if await db.users.find_one({"email": email}, {"_id": 0}):
        raise HTTPException(status_code=409, detail="Ese email ya está registrado")
    user = await register_user(email, body.password, body.name)
    token = await create_session(user["user_id"])
    set_session_cookie(response, token)
    return {**user, "picture": None}


@router.post("/auth/login")
async def login(body: LoginBody, response: Response):
    _guard()
    email = body.email.lower().strip()
    user = await db.users.find_one({"email": email}, {"_id": 0})
    # Uniform error + no user enumeration; also blocks OAuth-only accounts.
    if not user or not user.get("password_hash") or not verify_password(
        body.password, user["password_hash"]
    ):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    if not email_allowed(email):
        raise HTTPException(status_code=403, detail="Email no autorizado")
    token = await create_session(user["user_id"])
    set_session_cookie(response, token)
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "name": user.get("name"),
        "picture": user.get("picture"),
    }

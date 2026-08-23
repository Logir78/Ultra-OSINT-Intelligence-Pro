"""Routes: uso y cuota del plan (P1 · negocio)."""
from fastapi import APIRouter, Depends

from app.core import db, get_current_user
from app import usage as usage_mod

router = APIRouter()


@router.get("/usage")
async def my_usage(user=Depends(get_current_user)):
    """Uso del mes actual, límite del plan y cuota restante."""
    return await usage_mod.get_usage(db, user)

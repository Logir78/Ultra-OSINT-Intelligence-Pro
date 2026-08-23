"""Routes: gestión de API keys (P1 · API pública)."""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from app.core import db, get_current_user
from app import apikeys

router = APIRouter()


class KeyBody(BaseModel):
    name: str = Field(min_length=1, max_length=80)


@router.post("/apikeys")
async def create_key(body: KeyBody, user=Depends(get_current_user)):
    """Crea una API key. Devuelve la clave en claro UNA sola vez."""
    return await apikeys.create_api_key(db, user["user_id"], body.name)


@router.get("/apikeys")
async def list_keys(user=Depends(get_current_user)):
    items = await apikeys.list_api_keys(db, user["user_id"])
    return {"count": len(items), "keys": items}


@router.delete("/apikeys/{key_id}")
async def revoke_key(key_id: str, user=Depends(get_current_user)):
    ok = await apikeys.revoke_api_key(db, user["user_id"], key_id)
    if not ok:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"revoked": key_id}

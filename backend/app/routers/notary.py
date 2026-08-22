"""Routes: notarized evidence (Diferenciador #2).

Persistent, re-verifiable chain of custody on top of the existing evidence seal.
All routes are user-scoped. Notarizations are append-only (immutable records).
"""
from fastapi import APIRouter, HTTPException, Depends

from app.core import db, get_current_user, _load_scan
from app import notary

router = APIRouter()


@router.post("/scans/{scan_id}/notarize")
async def create_notarization(scan_id: str, user=Depends(get_current_user)):
    """Seal + RFC3161-timestamp the scan's findings and store an immutable record."""
    doc = await _load_scan(scan_id, user)
    return await notary.notarize(doc, user["user_id"], db)


@router.get("/scans/{scan_id}/notarizations")
async def list_notarizations(scan_id: str, user=Depends(get_current_user)):
    """Immutable history of notarizations for this scan (newest first)."""
    await _load_scan(scan_id, user)  # ownership check
    cur = db[notary.COLLECTION].find(
        {"scan_id": scan_id, "user_id": user["user_id"]},
        {"_id": 0, "sealed_findings": 0},  # summary view
    ).sort("created_at", -1)
    items = await cur.to_list(100)
    return {"scan_id": scan_id, "count": len(items), "notarizations": items}


async def _load_notarization(notary_id: str, user: dict) -> dict:
    rec = await db[notary.COLLECTION].find_one(
        {"notary_id": notary_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not rec:
        raise HTTPException(status_code=404, detail="Notarization not found")
    return rec


@router.get("/notary/{notary_id}")
async def get_notarization(notary_id: str, user=Depends(get_current_user)):
    return await _load_notarization(notary_id, user)


@router.get("/notary/{notary_id}/verify")
async def verify_notarization(notary_id: str, user=Depends(get_current_user)):
    """Re-derive every hash and report INTACT or TAMPERED."""
    rec = await _load_notarization(notary_id, user)
    return notary.verify(rec)


@router.get("/notary/{notary_id}/bundle")
async def download_bundle(notary_id: str, user=Depends(get_current_user)):
    """Self-contained evidence bundle for independent verification / disputes."""
    rec = await _load_notarization(notary_id, user)
    return notary.build_bundle(rec)

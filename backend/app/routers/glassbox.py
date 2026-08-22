"""Routes: glass-box explainable AI (Diferenciador #5)."""
from fastapi import APIRouter, Depends

from app.core import db, get_current_user, _load_scan
from app import glassbox

router = APIRouter()


@router.get("/scans/{scan_id}/explain")
async def explain_scan(scan_id: str, user=Depends(get_current_user)):
    """Evidence-grounded AI conclusions with confidence + hallucination flags."""
    doc = await _load_scan(scan_id, user)
    result = await glassbox.explain(doc)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"glassbox": result}})
    return result

"""Routes: Bug Bounty "First-to-Find" (Diferenciador #3).

Scope awareness + platform-ready report generation, weaving in the
exploitability verdict (#1) and notarized evidence (#2).
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from app.core import db, get_current_user, _load_scan
from app import bounty_scope, bounty_report, notary

router = APIRouter()

_SCOPES = "bounty_scopes"


class ScopeBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scope_text: str = Field(min_length=1, max_length=20000)


class ScopeCheckBody(BaseModel):
    scope_text: str | None = None
    scope_id: str | None = None


class ReportBody(BaseModel):
    finding: dict
    platform: str = "hackerone"
    include_notarization: bool = True


@router.post("/bounty/scope")
async def save_scope(body: ScopeBody, user=Depends(get_current_user)):
    parsed = bounty_scope.parse_scope(body.scope_text)
    doc = {
        "scope_id": f"sc_{uuid.uuid4().hex[:12]}",
        "user_id": user["user_id"],
        "name": body.name,
        "raw": body.scope_text,
        "parsed": parsed,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db[_SCOPES].insert_one(dict(doc))
    doc.pop("_id", None)
    return {"scope_id": doc["scope_id"], "name": doc["name"], "parsed": parsed}


@router.get("/bounty/scopes")
async def list_scopes(user=Depends(get_current_user)):
    cur = db[_SCOPES].find({"user_id": user["user_id"]}, {"_id": 0}).sort("created_at", -1)
    items = await cur.to_list(100)
    return {"count": len(items), "scopes": items}


async def _resolve_scope(body: ScopeCheckBody, user: dict) -> dict:
    if body.scope_text:
        return bounty_scope.parse_scope(body.scope_text)
    if body.scope_id:
        rec = await db[_SCOPES].find_one(
            {"scope_id": body.scope_id, "user_id": user["user_id"]}, {"_id": 0})
        if not rec:
            raise HTTPException(status_code=404, detail="Scope not found")
        return rec["parsed"]
    raise HTTPException(status_code=400, detail="Provide scope_text or scope_id")


@router.post("/scans/{scan_id}/scope-check")
async def scope_check(scan_id: str, body: ScopeCheckBody, user=Depends(get_current_user)):
    """Classify every asset of the scan as in-scope / out-of-scope / unknown."""
    doc = await _load_scan(scan_id, user)
    scope = await _resolve_scope(body, user)
    return bounty_scope.classify_scan_assets(doc, scope)


@router.post("/scans/{scan_id}/bounty-report")
async def bounty_report_gen(scan_id: str, body: ReportBody, user=Depends(get_current_user)):
    """Generate a submittable HackerOne/Bugcrowd report for a finding."""
    doc = await _load_scan(scan_id, user)
    exploit = doc.get("exploitability")
    notarization = None
    if body.include_notarization:
        rec = await db[notary.COLLECTION].find_one(
            {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0})
        notarization = rec
    return bounty_report.build_report(
        body.finding, doc,
        exploitability=exploit, notarization=notarization, platform=body.platform,
    )

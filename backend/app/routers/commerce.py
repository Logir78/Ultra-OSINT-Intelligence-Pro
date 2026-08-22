"""Routes: commerce. Extracted from server.py."""
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
from app.models import MarketplaceCheckout, BountyReportBody, BountyReportUpdate

router = APIRouter()


@router.get("/apt-personas")
async def list_apt_personas():
    from integrations.attack_path import APT_PROFILES
    return {"personas": [{"id": k, "description": v} for k, v in APT_PROFILES.items()]}


@router.get("/asm/inventory")
async def asm_inventory(user=Depends(get_current_user)):
    from integrations.asm_inventory import compute_inventory
    return await compute_inventory(db, user["user_id"])


@router.get("/asm/drift")
async def asm_drift(domain: str, user=Depends(get_current_user)):
    from integrations.asm_inventory import compute_drift
    return await compute_drift(db, user["user_id"], domain.lower())


@router.get("/cve-feed")
async def cve_feed(days: int = 7, user=Depends(get_current_user)):
    from integrations.cve_feed import user_cve_feed
    days = max(1, min(days, 30))
    return await user_cve_feed(db, user["user_id"], days=days)


@router.get("/marketplace/products")
async def marketplace_products(user=Depends(get_current_user)):
    from marketplace import MARKETPLACE_CATALOG, is_unlocked
    return {
        "products": [{**p, "unlocked": is_unlocked(user, p["modules_unlocked"][0])}
                      for p in MARKETPLACE_CATALOG],
        "plan": user.get("plan", "free"),
        "unlocks": user.get("unlocks") or [],
    }


@router.post("/marketplace/checkout")
async def marketplace_checkout(payload: MarketplaceCheckout, user=Depends(get_current_user)):
    import stripe
    from marketplace import get_product
    prod = get_product(payload.product_id)
    if not prod:
        raise HTTPException(404, "Producto desconocido")
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    if not base:
        raise HTTPException(500, "Falta PUBLIC_BASE_URL")

    session_kwargs = dict(
        line_items=[{
            "price_data": {
                "currency": "usd",
                "unit_amount": prod["price_usd"] * 100,
                "product_data": {"name": f"NOCTUA · {prod['name']}",
                                  "description": prod["description"]},
            },
            "quantity": 1,
        }],
        mode="payment",
        success_url=f"{base}/marketplace/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{base}/marketplace",
        metadata={"user_id": user["user_id"], "product_id": prod["id"],
                   "kind": "marketplace"},
    )
    try:
        session = stripe.checkout.Session.create(
            **session_kwargs, managed_payments={"enabled": True})
    except Exception:
        session = stripe.checkout.Session.create(
            **session_kwargs, billing_address_collection="required")

    await db.payment_transactions.insert_one({
        "session_id": session.id,
        "user_id": user["user_id"],
        "kind": "marketplace",
        "product_id": prod["id"],
        "amount": prod["price_usd"] * 100,
        "currency": "usd",
        "status": "initiated",
        "payment_status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"session_id": session.id, "url": session.url,
            "product": prod["name"], "amount": prod["price_usd"]}


@router.post("/bounty/reports")
async def create_bounty_report(body: BountyReportBody, user=Depends(get_current_user)):
    if body.status not in {"submitted", "duplicate", "accepted", "informative", "rejected", "triaged"}:
        raise HTTPException(400, "status inválido")
    # Ownership check on the scan
    scan = await db.scans.find_one(
        {"scan_id": body.scan_id, "user_id": user["user_id"]}, {"_id": 0, "scan_id": 1,
                                                                 "result.domain": 1})
    if not scan:
        raise HTTPException(404, "Scan not found")
    doc = {
        "user_id": user["user_id"],
        "scan_id": body.scan_id,
        "domain": (scan.get("result") or {}).get("domain"),
        "finding_key": body.finding_key,
        "program": body.program,
        "report_id": body.report_id,
        "status": body.status,
        "severity": body.severity,
        "notes": (body.notes or "")[:1000],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    result = await db.bounty_reports.insert_one(doc)
    doc["id"] = str(result.inserted_id)
    doc.pop("_id", None)
    return doc


@router.get("/bounty/reports")
async def list_bounty_reports(user=Depends(get_current_user),
                              domain: Optional[str] = None,
                              status: Optional[str] = None):
    q = {"user_id": user["user_id"]}
    if domain:
        q["domain"] = domain.lower()
    if status:
        q["status"] = status
    cursor = db.bounty_reports.find(q, {"_id": 0}).sort("created_at", -1)
    items = await cursor.to_list(500)
    return {"count": len(items), "reports": items}


@router.patch("/bounty/reports/{finding_key}")
async def update_bounty_report(finding_key: str, body: BountyReportUpdate,
                                user=Depends(get_current_user),
                                scan_id: Optional[str] = None):
    q = {"user_id": user["user_id"], "finding_key": finding_key}
    if scan_id:
        q["scan_id"] = scan_id
    updates = {"updated_at": datetime.now(timezone.utc).isoformat()}
    for f in ("status", "report_id", "program", "notes", "severity"):
        v = getattr(body, f)
        if v is not None:
            updates[f] = v[:1000] if isinstance(v, str) else v
    r = await db.bounty_reports.update_one(q, {"$set": updates})
    if r.matched_count == 0:
        raise HTTPException(404, "Report not found")
    return {"updated": r.modified_count}


@router.delete("/bounty/reports/{finding_key}")
async def delete_bounty_report(finding_key: str, user=Depends(get_current_user),
                                scan_id: Optional[str] = None):
    q = {"user_id": user["user_id"], "finding_key": finding_key}
    if scan_id:
        q["scan_id"] = scan_id
    r = await db.bounty_reports.delete_one(q)
    if r.deleted_count == 0:
        raise HTTPException(404, "Report not found")
    return {"deleted": True}

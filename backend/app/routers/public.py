"""Routes: public. Extracted from server.py."""
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

router = APIRouter()


@router.get("/stealth/status")
async def get_stealth_status():
    from integrations.stealth import stealth_status
    return stealth_status()


@router.get("/public/takeover-check")
async def public_takeover_check(request: Request, domain: str):
    """Free public tier: quick takeover scan for a single domain.
    Rate-limited to 5 requests / hour per IP. Preview mode — full report requires Pro.
    """
    _rate_limit_check(request)
    domain = (domain or "").strip().lower()
    if not domain or len(domain) < 4 or "." not in domain:
        raise HTTPException(400, "Dominio inválido")
    try:
        assert_public_host(domain)  # anti-SSRF guard on the public/unauthenticated tier
    except ValueError as e:
        raise HTTPException(400, str(e))

    from integrations.takeover_scanner import scan_takeovers
    from osint_engine import find_subdomains
    # Use only a small subset of subdomains to keep it fast for the free tier
    subs_info = await find_subdomains(domain)
    subs = [s["subdomain"] for s in (subs_info.get("found") or [])][:15]
    result = await scan_takeovers(subs, domain)

    # Track the public scan for the live global counter
    try:
        await db.public_scans.insert_one({
            "domain": domain,
            "checked_subdomains": result.get("checked", 0),
            "vulnerable_count": result.get("vulnerable_count", 0),
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:
        logger.exception("public_scans insert failed")

    return {
        "tier": "free_public",
        "domain": domain,
        "checked_subdomains": result["checked"],
        "with_cname": result["with_cname"],
        "vulnerable_count": result["vulnerable_count"],
        "results": result["results"][:20],  # cap output
        "explanation": result["explanation"],
        "upsell": {
            "message": "Escaneo básico. Consigue el reporte completo con NOCTUA Pro: fingerprint de tecnologías, "
                       "geolocalización, Shodan + AbuseIPDB, resumen IA, PDF exportable y monitorización continua.",
            "cta_url": "https://noctua.osint/pricing",
            "features_locked": [
                "Análisis IA de riesgos con Claude Sonnet 4.5",
                "Reputación IP con AbuseIPDB",
                "Shodan CVEs + puertos indexados",
                "Cloud storage enumeration (S3/Azure/GCS)",
                "Extractor de metadatos de documentos",
                "Mapa de red interactivo",
                "PDF ejecutivo con portada de riesgo",
                "Escaneos programados + alertas Slack",
            ],
        },
    }


@router.get("/")
async def root():
    return {"service": "OSINT Scanner API", "status": "ok"}


@router.get("/health")
async def health():
    """Liveness/readiness probe: checks MongoDB connectivity."""
    db_ok = True
    try:
        await db.command("ping")
    except Exception:
        db_ok = False
    return {"status": "ok" if db_ok else "degraded", "db": db_ok}


@router.get("/public/stats")
async def public_stats():
    """Aggregated NOCTUA stats for the landing page. Cached for 5 minutes."""
    now_ts = datetime.now(timezone.utc).timestamp()
    if _stats_cache["at"] and (now_ts - _stats_cache["at"]) < _STATS_TTL and _stats_cache["data"]:
        return {**_stats_cache["data"], "cached": True}

    month_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    try:
        public_scans_month = await db.public_scans.count_documents({"created_at": {"$gte": month_ago}})
    except Exception:
        public_scans_month = 0
    try:
        auth_scans_month = await db.scans.count_documents({"created_at": {"$gte": month_ago}})
    except Exception:
        auth_scans_month = 0
    try:
        total_scans = await db.scans.estimated_document_count() + await db.public_scans.estimated_document_count()
    except Exception:
        total_scans = 0
    try:
        # Sum vulnerable_count from public_scans
        pipeline = [{"$group": {"_id": None, "n": {"$sum": "$vulnerable_count"}}}]
        agg = await db.public_scans.aggregate(pipeline).to_list(1)
        takeovers_found = int(agg[0]["n"]) if agg else 0
    except Exception:
        takeovers_found = 0
    try:
        active_users = await db.users.estimated_document_count()
    except Exception:
        active_users = 0

    data = {
        "scans_this_month": public_scans_month + auth_scans_month,
        "public_scans_this_month": public_scans_month,
        "total_scans": total_scans,
        "takeovers_detected": takeovers_found,
        "active_users": active_users,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    _stats_cache["at"] = now_ts
    _stats_cache["data"] = data
    return {**data, "cached": False}

"""Routes: scans. Extracted from server.py."""
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
from app.models import ScanRequest

router = APIRouter()


@router.post("/scan")
async def scan(req: ScanRequest, user=Depends(get_current_user)):
    if not req.domain or len(req.domain.strip()) < 3:
        raise HTTPException(status_code=400, detail="Dominio inválido")
    try:
        assert_public_host(req.domain)  # anti-SSRF guard (SSRF_GUARD env, default on)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        analysis = await analyze_domain(req.domain, extended_ports=req.extended_ports)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en escaneo: {str(e)}")

    if req.ai_summary:
        analysis["ai_summary"] = await _generate_ai_summary(analysis)
    else:
        analysis["ai_summary"] = None

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    doc = {
        "scan_id": scan_id,
        "user_id": user["user_id"],
        "domain": analysis["domain"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "extended_ports": req.extended_ports,
        "result": analysis,
    }
    await db.scans.insert_one(doc)
    return {"scan_id": scan_id, "result": analysis}


@router.get("/scans")
async def list_scans(user=Depends(get_current_user)):
    cursor = db.scans.find(
        {"user_id": user["user_id"]},
        {"_id": 0, "scan_id": 1, "domain": 1, "created_at": 1, "tags": 1,
         "primary_category": 1, "flagged": 1,
         "result.security": 1, "result.ip.ip": 1, "result.ports.open_ports": 1},
    ).sort("created_at", -1).limit(100)
    items = await cursor.to_list(length=100)
    for it in items:
        r = it.get("result", {})
        sec = r.get("security", {})
        it["overview"] = {
            "ip": r.get("ip", {}).get("ip"),
            "open_ports": len(r.get("ports", {}).get("open_ports", [])),
            "score_basic": sec.get("basic", {}).get("score"),
            "score_medium": sec.get("medium", {}).get("score"),
            "score_advanced": sec.get("advanced", {}).get("score"),
        }
        it.pop("result", None)
    return items


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]},
        {"_id": 0},
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    return doc


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, user=Depends(get_current_user)):
    res = await db.scans.delete_one({"scan_id": scan_id, "user_id": user["user_id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"ok": True}


@router.get("/scans/{scan_id}/geoip")
async def scan_geoip(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("geoip"):
        return {"geoip": doc["geoip"], "cached": True}
    from geoip import geolocate_scan
    geoip = await geolocate_scan(doc["result"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"geoip": geoip}})
    return {"geoip": geoip, "cached": False}


@router.get("/scans/{scan_id}/wayback")
async def scan_wayback(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("wayback"):
        return {"wayback": doc["wayback"], "cached": True}
    from wayback import get_wayback_timeline
    domain = doc["result"]["domain"]
    timeline = await get_wayback_timeline(domain, count=5)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"wayback": timeline}})
    return {"wayback": timeline, "cached": False}


@router.get("/scans/{scan_id}/intel")
async def scan_intel(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("intel"):
        return {"intel": doc["intel"], "cached": True}
    # Ensure we have wayback + reputation in the result for enrichment
    result = doc["result"]
    if not result.get("wayback") and doc.get("wayback"):
        result = {**result, "wayback": doc["wayback"]}
    if doc.get("reputation"):
        result = {**result, "_abuse_worst_score": doc["reputation"].get("worst_score", 0)}
    if doc.get("takeover"):
        result = {**result, "_takeover_vulns": doc["takeover"].get("vulnerable_count", 0)}
    from intel import generate_intel_summary
    from user_settings import get_ai_config
    ai = get_ai_config(user)
    intel = await generate_intel_summary(
        result, EMERGENT_LLM_KEY,
        ai_provider=ai["provider"], ai_key=ai["key"], ai_mode=ai["mode"],
        claude_tier=(user.get("preferences") or {}).get("claude_tier"),
        ollama_url=ai.get("ollama_url"), ollama_model=ai.get("ollama_model"),
    )
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"intel": intel}})
    return {"intel": intel, "cached": False}


@router.get("/scans/{scan_id}/pdf")
async def scan_pdf(scan_id: str, user=Depends(get_current_user)):
    from fastapi.responses import Response as FResponse
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")

    intel = doc.get("intel")
    if not intel:
        result = doc["result"]
        if not result.get("wayback") and doc.get("wayback"):
            result = {**result, "wayback": doc["wayback"]}
        from intel import generate_intel_summary
        from user_settings import get_ai_config
        ai = get_ai_config(user)
        intel = await generate_intel_summary(
            result, EMERGENT_LLM_KEY,
            ai_provider=ai["provider"], ai_key=ai["key"], ai_mode=ai["mode"],
            claude_tier=(user.get("preferences") or {}).get("claude_tier"),
            ollama_url=ai.get("ollama_url"), ollama_model=ai.get("ollama_model"),
        )
        await db.scans.update_one({"scan_id": scan_id}, {"$set": {"intel": intel}})

    from pdf_export import build_pdf
    pdf_bytes = build_pdf(doc, intel)
    filename = f"noctua_{doc['result']['domain']}_{scan_id}.pdf".replace("/", "_")
    return FResponse(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/reputation")
async def scan_reputation(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("reputation"):
        return {"reputation": doc["reputation"], "cached": True}
    from integrations import reputation
    from user_settings import get_user_key
    ips = _collect_scan_ips(doc)
    checks = await reputation.check_ips(ips, override_key=get_user_key(user, "abuseipdb"))
    payload = {
        "provider": reputation.get_hint(),
        "checks": checks,
        "worst_score": max((c.get("abuse_confidence") or 0) for c in checks) if checks else 0,
    }
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"reputation": payload}})
    return {"reputation": payload, "cached": False}


@router.get("/scans/{scan_id}/shodan")
async def scan_shodan(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("shodan"):
        return {"shodan": doc["shodan"], "cached": True}
    from integrations import shodan_service
    from user_settings import get_user_key
    ips = _collect_scan_ips(doc)
    hosts = await shodan_service.lookup_ips(ips, override_key=get_user_key(user, "shodan"))
    all_vulns = []
    for h in hosts:
        for v in (h.get("vulns") or []):
            all_vulns.append({"cve": v, "ip": h["ip"]})
        for svc in h.get("services") or []:
            for v in svc.get("vulns") or []:
                all_vulns.append({"cve": v, "ip": h["ip"], "port": svc.get("port"), "product": svc.get("product")})
    payload = {
        "provider": shodan_service.get_hint(),
        "hosts": hosts,
        "total_vulns": len(all_vulns),
        "vulns": all_vulns[:200],
    }
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"shodan": payload}})
    return {"shodan": payload, "cached": False}


@router.get("/scans/{scan_id}/cloud")
async def scan_cloud(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("cloud"):
        return {"cloud": doc["cloud"], "cached": True}
    from integrations.cloud_scanner import scan_cloud_storage
    cloud = await scan_cloud_storage(doc["result"]["domain"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"cloud": cloud}})
    return {"cloud": cloud, "cached": False}


@router.get("/scans/{scan_id}/metadata")
async def scan_metadata(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("metadata"):
        return {"metadata": doc["metadata"], "cached": True}
    from integrations.metadata import extract_domain_docs
    md = await extract_domain_docs(doc["result"]["domain"], max_docs=10)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"metadata": md}})
    return {"metadata": md, "cached": False}


@router.get("/scans/{scan_id}/takeover")
async def scan_takeover(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("takeover"):
        return {"takeover": doc["takeover"], "cached": True}
    from integrations.takeover_scanner import scan_takeovers
    result = doc["result"]
    subs = [s["subdomain"] for s in (result.get("subdomains") or {}).get("found", [])]
    takeover = await scan_takeovers(subs, result["domain"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"takeover": takeover}})
    return {"takeover": takeover, "cached": False}


@router.get("/scans/{scan_id}/pastes")
async def scan_pastes(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("pastes"):
        return {"pastes": doc["pastes"], "cached": True}
    from integrations.paste_search import search_paste_mentions
    result = doc["result"]
    ips = _collect_scan_ips(doc)
    pastes = await search_paste_mentions(result["domain"], ips)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"pastes": pastes}})
    return {"pastes": pastes, "cached": False}


@router.get("/scans/{scan_id}/threat-intel")
async def scan_threat_intel(scan_id: str, user=Depends(get_current_user)):
    doc = await db.scans.find_one(
        {"scan_id": scan_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("threat_intel"):
        return {"threat_intel": doc["threat_intel"], "cached": True}
    from integrations.threat_intel import urlscan_search, intelx_search
    from user_settings import get_user_key
    domain = doc["result"]["domain"]
    intelx_user_key = (user.get("api_keys") or {}).get("intelx")
    urlscan_user_key = (user.get("api_keys") or {}).get("urlscan")
    urls, ix = await asyncio.gather(
        urlscan_search(domain, user_key=urlscan_user_key),
        intelx_search(domain, user_key=intelx_user_key),
    )
    ti = {"urlscan": urls, "intelx": ix}
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"threat_intel": ti}})
    return {"threat_intel": ti, "cached": False}


@router.post("/scans/{scan_id}/evidence-seal/timestamp")
async def scan_evidence_timestamp(scan_id: str, user=Depends(get_current_user)):
    """Request a real RFC3161 signed timestamp for this scan's chain_hash from FreeTSA."""
    doc = await _load_scan(scan_id, user)
    evidence = doc.get("evidence")
    if not evidence or not evidence.get("chain_hash"):
        # Compute the seal first
        from integrations.evidence_seal import seal_scan_evidence
        evidence = seal_scan_evidence(doc)
        await db.scans.update_one({"scan_id": scan_id}, {"$set": {"evidence": evidence}})
    from integrations.evidence_seal import request_rfc3161_timestamp
    tsr = await request_rfc3161_timestamp(evidence["chain_hash"])
    await db.scans.update_one(
        {"scan_id": scan_id},
        {"$set": {"evidence.rfc3161_timestamp": tsr}})
    return {"chain_hash": evidence["chain_hash"], "rfc3161": tsr}


@router.get("/scans/history/{domain}")
async def scan_history_for_domain(domain: str, user=Depends(get_current_user)):
    """List all scans of a given domain by the user (for diff picker)."""
    cursor = db.scans.find(
        {"user_id": user["user_id"], "result.domain": domain.lower()},
        {"_id": 0, "scan_id": 1, "created_at": 1,
         "tags": 1}).sort("created_at", -1)
    scans = await cursor.to_list(200)
    return {"domain": domain, "count": len(scans), "scans": scans}

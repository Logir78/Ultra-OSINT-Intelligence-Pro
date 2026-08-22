"""Routes: intel. Extracted from server.py."""
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
from app.models import AttackPathBody, FlagScanBody, ManualTagsBody

router = APIRouter()


@router.get("/scans/{scan_id}/js-miner")
async def scan_js_miner(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("js_miner"):
        return {"js_miner": doc["js_miner"], "cached": True}
    from integrations.js_miner import mine
    data = await mine(doc["result"]["domain"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"js_miner": data}})
    return {"js_miner": data, "cached": False}


@router.get("/scans/{scan_id}/ct-logs")
async def scan_ct_logs(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("ct_logs"):
        return {"ct_logs": doc["ct_logs"], "cached": True}
    from integrations.ct_logs import discover_and_crosscheck
    active = (doc["result"].get("subdomains") or {}).get("found", [])
    data = await discover_and_crosscheck(doc["result"]["domain"], active)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"ct_logs": data}})
    return {"ct_logs": data, "cached": False}


@router.get("/scans/{scan_id}/shodan-deep")
async def scan_shodan_deep(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("shodan_deep"):
        return {"shodan_deep": doc["shodan_deep"], "cached": True}
    from integrations.shodan_deep import deep_scan
    from user_settings import get_user_key
    ips = _collect_scan_ips(doc)
    key = get_user_key(user, "shodan")
    data = await deep_scan(ips, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"shodan_deep": data}})
    return {"shodan_deep": data, "cached": False}


@router.get("/scans/{scan_id}/dna")
async def scan_dna(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("dna"):
        return {"dna": doc["dna"], "cached": True}
    from integrations.dna_fingerprint import find_siblings
    from user_settings import get_user_key
    shodan_key = get_user_key(user, "shodan")
    data = await find_siblings(doc["result"], shodan_key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"dna": data}})
    return {"dna": data, "cached": False}


@router.get("/scans/{scan_id}/risk-oracle")
async def scan_risk_oracle(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("risk_oracle"):
        return {"risk_oracle": doc["risk_oracle"], "cached": True}
    from integrations.risk_oracle import predict_breach
    provider, key, mode = _user_ai(user)
    data = await predict_breach(doc["result"], EMERGENT_LLM_KEY, provider, key, mode)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"risk_oracle": data}})
    return {"risk_oracle": data, "cached": False}


@router.get("/scans/{scan_id}/brand-guardian")
async def scan_brand_guardian(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("brand_guardian"):
        return {"brand_guardian": doc["brand_guardian"], "cached": True}
    from integrations.brand_guardian import scan_typosquats
    provider, key, _ = _user_ai(user)
    data = await scan_typosquats(doc["result"]["domain"], EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"brand_guardian": data}})
    return {"brand_guardian": data, "cached": False}


@router.post("/scans/{scan_id}/phishing-sim")
async def scan_phishing_sim(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if user.get("plan") != "pro":
        raise HTTPException(status_code=402, detail="Pro plan required")
    from integrations.phishing_sim import generate_simulation
    provider, key, _ = _user_ai(user)
    # Always regenerate — user may want variants
    data = await generate_simulation(doc["result"], EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"phishing_sim": data}})
    return {"phishing_sim": data, "cached": False}


@router.post("/scans/{scan_id}/attack-path")
async def scan_attack_path(scan_id: str, body: AttackPathBody, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    cache_key = f"attack_path_{body.apt_persona or 'none'}"
    cached = (doc.get("attack_paths") or {}).get(cache_key)
    if cached and not body.regenerate:
        return {"attack_path": cached, "cached": True}
    from integrations.attack_path import build_attack_path
    provider, key, mode = _user_ai(user)
    data = await build_attack_path(doc["result"], EMERGENT_LLM_KEY, provider, key,
                                    apt_persona=body.apt_persona or "none", ai_mode=mode)
    await db.scans.update_one(
        {"scan_id": scan_id},
        {"$set": {f"attack_paths.{cache_key}": data}},
    )
    return {"attack_path": data, "cached": False}


@router.get("/scans/{scan_id}/poc")
async def scan_poc(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("poc"):
        return {"poc": doc["poc"], "cached": True}
    from integrations.poc_generator import generate_pocs
    provider, key, _ = _user_ai(user)
    data = await generate_pocs(doc["result"], EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"poc": data}})
    return {"poc": data, "cached": False}


@router.get("/scans/{scan_id}/param-miner")
async def scan_param_miner(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("param_miner"):
        return {"param_miner": doc["param_miner"], "cached": True}
    from integrations.param_miner import mine_params
    js_sources = ((doc.get("js_miner") or {}).get("sources") or [])
    data = await mine_params(doc["result"]["domain"], js_sources)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"param_miner": data}})
    return {"param_miner": data, "cached": False}


@router.get("/scans/{scan_id}/cloud-config")
async def scan_cloud_config(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("cloud_config"):
        return {"cloud_config": doc["cloud_config"], "cached": True}
    from integrations.cloud_config import hunt_configs
    subs = [s["subdomain"] for s in ((doc["result"].get("subdomains") or {}).get("found") or [])]
    data = await hunt_configs(doc["result"]["domain"], subs)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"cloud_config": data}})
    return {"cloud_config": data, "cached": False}


@router.get("/scans/{scan_id}/api-audit")
async def scan_api_audit(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("api_audit"):
        return {"api_audit": doc["api_audit"], "cached": True}
    from integrations.api_auditor import audit_apis
    data = await audit_apis(doc["result"]["domain"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"api_audit": data}})
    return {"api_audit": data, "cached": False}


@router.get("/scans/{scan_id}/idor")
async def scan_idor(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("idor"):
        return {"idor": doc["idor"], "cached": True}
    # Merge accumulated modules into a shallow view for analysis
    merged = dict(doc.get("result") or {})
    for k in ("js_miner", "api_audit", "param_miner"):
        if doc.get(k):
            merged[k] = doc[k]
    from integrations.idor_analyzer import analyze_idor
    provider, key, _ = _user_ai(user)
    data = await analyze_idor(merged, EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"idor": data}})
    return {"idor": data, "cached": False}


@router.get("/scans/{scan_id}/supply-chain")
async def scan_supply_chain(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("supply_chain"):
        return {"supply_chain": doc["supply_chain"], "cached": True}
    from integrations.supply_chain import audit_supply_chain
    data = await audit_supply_chain(doc["result"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"supply_chain": data}})
    return {"supply_chain": data, "cached": False}


@router.get("/scans/{scan_id}/logic-flow")
async def scan_logic_flow(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("logic_flow"):
        return {"logic_flow": doc["logic_flow"], "cached": True}
    merged = dict(doc.get("result") or {})
    for k in ("js_miner", "api_audit"):
        if doc.get(k):
            merged[k] = doc[k]
    from integrations.logic_flow import analyze_logic_flows
    provider, key, mode = _user_ai(user)
    data = await analyze_logic_flows(merged, EMERGENT_LLM_KEY, provider, key, mode)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"logic_flow": data}})
    return {"logic_flow": data, "cached": False}


@router.get("/scans/{scan_id}/reverse-ip")
async def scan_reverse_ip(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("reverse_ip"):
        return {"reverse_ip": doc["reverse_ip"], "cached": True}
    from integrations.reverse_ip import find_ip_neighbors
    ip = (doc["result"].get("ip") or {}).get("ip")
    data = await find_ip_neighbors(doc["result"]["domain"], ip)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"reverse_ip": data}})
    return {"reverse_ip": data, "cached": False}


@router.get("/scans/{scan_id}/github-miner")
async def scan_github_miner(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("github_miner"):
        return {"github_miner": doc["github_miner"], "cached": True}
    from integrations.github_miner import search_github
    from user_settings import get_user_key
    gh_key = get_user_key(user, "github")
    data = await search_github(doc["result"]["domain"], gh_key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"github_miner": data}})
    return {"github_miner": data, "cached": False}


@router.get("/scans/{scan_id}/bot-resistance")
async def scan_bot_resistance(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("bot_resistance"):
        return {"bot_resistance": doc["bot_resistance"], "cached": True}
    from integrations.bot_resistance import evaluate
    data = await evaluate(doc["result"]["domain"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"bot_resistance": data}})
    return {"bot_resistance": data, "cached": False}


@router.post("/scans/{scan_id}/cve-correlate")
async def scan_cve_correlate(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.cve_engine import correlate_cves
    tech = (doc.get("result") or {}).get("tech_analysis") or []
    data = await correlate_cves(tech)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"cve_correlation": data}})
    return {"cve_correlation": data, "cached": False}


@router.get("/scans/{scan_id}/cve-correlate")
async def scan_cve_get(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    return {"cve_correlation": doc.get("cve_correlation"), "cached": True}


@router.post("/scans/{scan_id}/typosquat")
async def scan_typosquat(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.typosquat import probe_variants
    domain = (doc.get("result") or {}).get("domain") or doc.get("domain")
    if not domain:
        raise HTTPException(400, "Scan sin dominio")
    data = await probe_variants(domain)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"typosquat": data}})
    return {"typosquat": data, "cached": False}


@router.get("/scans/{scan_id}/typosquat")
async def scan_typosquat_get(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    return {"typosquat": doc.get("typosquat"), "cached": True}


@router.get("/scans/{scan_id}/attack-mapping")
async def scan_attack_mapping(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.attack_mapping import map_scan_to_attack
    data = map_scan_to_attack(doc)
    return {"attack_mapping": data}


@router.get("/scans/{scan_id}/attack-navigator")
async def scan_attack_navigator(scan_id: str, user=Depends(get_current_user)):
    """Return an ATT&CK Navigator layer JSON (for import in mitre-attack.github.io/attack-navigator)."""
    from fastapi.responses import Response as FResponse
    doc = await _load_scan(scan_id, user)
    from integrations.attack_mapping import map_scan_to_attack, to_stix_layer
    mapping = map_scan_to_attack(doc)
    target = (doc.get("result") or {}).get("domain") or doc.get("domain") or "target"
    layer = to_stix_layer(mapping, target)
    import json
    return FResponse(
        content=json.dumps(layer, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="noctua_{target}_attack_layer.json"'},
    )


@router.post("/scans/{scan_id}/cert-monitor")
async def scan_cert_monitor(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.cert_monitor import monitor_hosts
    domain = (doc.get("result") or {}).get("domain") or doc.get("domain")
    subs = ((doc.get("result") or {}).get("subdomains") or {}).get("found") or []
    hosts = [domain] + [s.get("hostname") for s in subs
                         if isinstance(s, dict) and s.get("hostname")][:40]
    hosts = [h for h in hosts if h]
    data = await monitor_hosts(hosts)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"cert_monitor": data}})
    return {"cert_monitor": data, "cached": False}


@router.get("/scans/{scan_id}/cert-monitor")
async def scan_cert_monitor_get(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    return {"cert_monitor": doc.get("cert_monitor"), "cached": True}


@router.get("/scans/{scan_id}/compliance")
async def scan_compliance(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.compliance import compute_scorecard
    return {"compliance": compute_scorecard(doc)}


@router.get("/scans/{scan_id}/waf-bypass")
async def scan_waf_bypass(scan_id: str, use_ai: bool = True,
                           user=Depends(get_current_user)):
    """Suggest WAF bypass tactics for the target based on detected proxies/WAF fingerprints.
    Optional AI narrative (Emergent LLM). Cache result on scan doc.
    """
    doc = await _load_scan(scan_id, user)
    if doc.get("waf_bypass") and not use_ai:
        return {"waf_bypass": doc["waf_bypass"], "cached": True}
    from integrations.waf_bypass import suggest_bypass, ai_summary
    tech = (doc.get("result") or {}).get("tech_analysis") or []
    domain = doc.get("result", {}).get("domain", "")
    data = suggest_bypass(tech, domain)
    if use_ai:
        data["ai_summary"] = await ai_summary(data)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"waf_bypass": data}})
    return {"waf_bypass": data, "cached": False}


@router.get("/scans/{scan_id}/jarm")
async def scan_jarm(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("jarm"):
        return {"jarm": doc["jarm"], "cached": True}
    from integrations.jarm_fingerprint import compute_jarm
    data = await compute_jarm(doc["result"]["domain"], 443)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"jarm": data}})
    return {"jarm": data, "cached": False}


@router.get("/scans/{scan_id}/honeypot")
async def scan_honeypot(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("honeypot"):
        return {"honeypot": doc["honeypot"], "cached": True}
    from integrations.honeypot_detector import detect_honeypot
    ip = (doc["result"].get("ip") or {}).get("ip")
    data = await detect_honeypot(doc["result"]["domain"], ip)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"honeypot": data}})
    return {"honeypot": data, "cached": False}


@router.get("/scans/{scan_id}/evidence-seal")
async def scan_evidence_seal(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    from integrations.evidence_seal import seal_scan_evidence
    # Always recompute so the seal reflects the current state (deterministic)
    data = seal_scan_evidence(doc)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"evidence": data}})
    return {"evidence": data, "cached": False}


@router.get("/scans/{scan_id}/sleeping-infra")
async def scan_sleeping_infra(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("sleeping_infra"):
        return {"sleeping_infra": doc["sleeping_infra"], "cached": True}
    from integrations.sleeping_infra import hunt_sleeping
    data = hunt_sleeping(doc["result"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"sleeping_infra": data}})
    return {"sleeping_infra": data, "cached": False}


@router.get("/scans/{scan_id}/org-map")
async def scan_org_map(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("org_map"):
        return {"org_map": doc["org_map"], "cached": True}
    merged = dict(doc.get("result") or {})
    for k in ("breaches", "metadata", "github_miner"):
        if doc.get(k):
            merged[k] = doc[k]
    from integrations.org_mapping import map_organization
    provider, key, _ = _user_ai(user)
    data = await map_organization(merged, EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"org_map": data}})
    return {"org_map": data, "cached": False}


@router.get("/scans/{scan_id}/dev-profile")
async def scan_dev_profile(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("dev_profile"):
        return {"dev_profile": doc["dev_profile"], "cached": True}
    merged = dict(doc.get("result") or {})
    for k in ("js_miner", "api_audit", "cloud_config", "supply_chain"):
        if doc.get(k):
            merged[k] = doc[k]
    from integrations.dev_profile import profile_dev_team
    provider, key, _ = _user_ai(user)
    data = await profile_dev_team(merged, EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"dev_profile": data}})
    return {"dev_profile": data, "cached": False}


@router.get("/scans/{scan_id}/diff")
async def scan_diff(scan_id: str, vs: Optional[str] = None,
                    user=Depends(get_current_user)):
    """Compare two scans of the same domain. If `vs` omitted, uses the immediately previous scan."""
    current = await _load_scan(scan_id, user)
    domain = current["result"]["domain"]

    if vs:
        previous = await db.scans.find_one(
            {"scan_id": vs, "user_id": user["user_id"]}, {"_id": 0})
        if not previous:
            raise HTTPException(404, "Previous scan not found")
        if (previous.get("result") or {}).get("domain") != domain:
            raise HTTPException(400, "Los dos escaneos deben ser del mismo dominio")
    else:
        previous = await db.scans.find_one(
            {"user_id": user["user_id"],
             "result.domain": domain,
             "scan_id": {"$ne": scan_id},
             "created_at": {"$lt": current.get("created_at") or ""}},
            {"_id": 0}, sort=[("created_at", -1)])
        if not previous:
            return {"available": False,
                    "reason": "No hay escaneo anterior del mismo dominio para comparar."}

    from integrations.scan_delta import compute_diff
    diff = compute_diff(previous, current)
    return {"available": True, "diff": diff}


@router.post("/scans/{scan_id}/auto-tag")
async def scan_auto_tag(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("tags") and doc.get("tag_meta"):
        return {"tags": doc["tags"], "tag_meta": doc["tag_meta"], "cached": True}
    from integrations.auto_tags import suggest_tags
    provider, key, _ = _user_ai(user)
    result = await suggest_tags(doc["result"], EMERGENT_LLM_KEY, provider, key)
    await db.scans.update_one(
        {"scan_id": scan_id},
        {"$set": {"tags": result["tags"],
                  "primary_category": result.get("primary_category"),
                  "tag_meta": {
                      "reasoning": result.get("reasoning"),
                      "confidence": result.get("confidence"),
                      "heuristic_tags": result.get("heuristic_tags"),
                      "ai_tags": result.get("ai_tags"),
                  }}})
    return {"tags": result["tags"], "tag_meta": result, "cached": False}


@router.post("/scans/{scan_id}/tags")
async def scan_manual_tags(scan_id: str, body: ManualTagsBody,
                           user=Depends(get_current_user)):
    from integrations.auto_tags import TAG_ONTOLOGY
    tags = [t for t in body.tags if t in TAG_ONTOLOGY][:12]
    doc = await _load_scan(scan_id, user)
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"tags": tags}})
    return {"tags": tags}


@router.get("/scans/{scan_id}/correlate")
async def scan_correlate(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("correlation"):
        return {"correlation": doc["correlation"], "cached": True}
    from integrations.global_correlation import find_correlations
    data = await find_correlations(db, doc["result"], user["user_id"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"correlation": data}})
    return {"correlation": data, "cached": False}


@router.post("/scans/{scan_id}/flag")
async def scan_flag(scan_id: str, body: FlagScanBody,
                    user=Depends(get_current_user)):
    """Flag a scan as suspicious/malicious. Feeds the Global Threat Graph anonymously."""
    doc = await _load_scan(scan_id, user)
    await db.scans.update_one(
        {"scan_id": scan_id},
        {"$set": {"flagged": bool(body.flagged),
                  "flag_reason": (body.reason or "")[:200] if body.flagged else None,
                  "flagged_at": datetime.now(timezone.utc).isoformat() if body.flagged else None}})
    return {"ok": True, "flagged": body.flagged}


@router.get("/scans/{scan_id}/version-track")
async def scan_version_track(scan_id: str, user=Depends(get_current_user)):
    doc = await _load_scan(scan_id, user)
    if doc.get("version_track"):
        return {"version_track": doc["version_track"], "cached": True}
    from integrations.version_tracker import check_rollbacks
    data = await check_rollbacks(db, doc["result"]["domain"], scan_id,
                                  doc["result"], user["user_id"])
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"version_track": data}})
    return {"version_track": data, "cached": False}


@router.post("/scans/{scan_id}/predict")
async def scan_predict_all(scan_id: str, user=Depends(get_current_user)):
    """Run all IA-heavy predictive modules in parallel and cache each result."""
    doc = await _load_scan(scan_id, user)
    from integrations.risk_oracle import predict_breach
    from integrations.brand_guardian import scan_typosquats
    from integrations.attack_path import build_attack_path
    from integrations.dna_fingerprint import find_siblings
    from user_settings import get_user_key
    provider, key, mode = _user_ai(user)
    shodan_key = get_user_key(user, "shodan")

    oracle, brand, attack, dna = await asyncio.gather(
        predict_breach(doc["result"], EMERGENT_LLM_KEY, provider, key, mode),
        scan_typosquats(doc["result"]["domain"], EMERGENT_LLM_KEY, provider, key),
        build_attack_path(doc["result"], EMERGENT_LLM_KEY, provider, key,
                          apt_persona="none", ai_mode=mode),
        find_siblings(doc["result"], shodan_key),
        return_exceptions=True,
    )

    def _safe(x):
        return {"error": str(x)} if isinstance(x, Exception) else x

    payload = {
        "risk_oracle": _safe(oracle),
        "brand_guardian": _safe(brand),
        "dna": _safe(dna),
    }
    ap_res = _safe(attack)
    await db.scans.update_one(
        {"scan_id": scan_id},
        {"$set": {
            "risk_oracle": payload["risk_oracle"],
            "brand_guardian": payload["brand_guardian"],
            "dna": payload["dna"],
            "attack_paths.attack_path_none": ap_res,
        }},
    )
    payload["attack_path"] = ap_res
    return payload

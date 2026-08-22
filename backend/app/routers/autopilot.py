"""Routes: agentic recon orchestrator "Autopilot" (Diferenciador #4)."""
from fastapi import APIRouter, Depends

from app.core import db, get_current_user, _load_scan
from app import autopilot, verifier, notary

router = APIRouter()


def _merged_doc(scan_doc: dict, state_findings: dict) -> dict:
    """A scan doc enriched with findings gathered so far (for chained steps)."""
    merged = dict(scan_doc)
    merged.update({k: v for k, v in state_findings.items()})
    return merged


def _make_executor(scan_doc: dict, user: dict):
    """Map a planned module to a real integration call. Defensive by design:
    each call is best-effort; failures degrade to {'error': ...} and never
    abort the run (autopilot.run wraps this too)."""
    domain = (scan_doc.get("result") or {}).get("domain")

    async def executor(module: str, state: dict) -> dict:
        if module == "js_miner":
            from integrations.js_miner import mine
            return await mine(domain)
        if module == "takeover":
            from integrations.takeover_scanner import scan_takeovers
            from osint_engine import find_subdomains
            subs_info = await find_subdomains(domain)
            subs = [s["subdomain"] for s in (subs_info.get("found") or [])][:25]
            return await scan_takeovers(subs, domain)
        if module == "cloud_scanner":
            from integrations.cloud_scanner import scan_cloud_storage
            return await scan_cloud_storage(domain)
        if module == "api_audit":
            from integrations.api_auditor import audit_apis
            return await audit_apis(domain)
        if module == "verify_exploitability":
            return await verifier.verify_scan(_merged_doc(scan_doc, state["findings"]))
        if module == "notarize":
            return await notary.notarize(_merged_doc(scan_doc, state["findings"]),
                                         user["user_id"], db)
        return {"error": f"unknown module {module}"}

    return executor


@router.post("/scans/{scan_id}/autopilot")
async def run_autopilot(scan_id: str, user=Depends(get_current_user)):
    """Autonomously chain recon modules, narrating each decision."""
    doc = await _load_scan(scan_id, user)
    result = await autopilot.run(doc, _make_executor(doc, user))
    await db.scans.update_one({"scan_id": scan_id}, {"$set": {"autopilot": result}})
    return result

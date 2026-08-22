"""Organizational Mapping — AI infers key personnel & roles from public signals."""
import json
import re
import logging
from datetime import datetime, timezone
from intel import _call_ai_with_fallback

log = logging.getLogger("org_map")


def _collect_org_signals(scan_result: dict) -> dict:
    """Pull all signals about org identity + employees from the scan."""
    whois = (scan_result.get("whois") or {}).get("data") or {}
    metadata = (scan_result.get("metadata") or {})
    breaches = (scan_result.get("breaches") or {})
    github = (scan_result.get("github_miner") or {})
    social = scan_result.get("social") or {}

    emails: set[str] = set()
    authors: set[str] = set()

    for d in (metadata.get("documents") or []):
        if d.get("author"):
            authors.add(d["author"])
    for b in (breaches.get("breaches") or []):
        if b.get("query"):
            emails.add(b["query"])
    for r in (github.get("results") or []):
        # e.g. author from repo path (rough)
        repo = r.get("repository") or ""
        if "/" in repo:
            authors.add(repo.split("/", 1)[0])

    return {
        "domain": scan_result.get("domain"),
        "whois_org": whois.get("org") or whois.get("registrant_organization"),
        "whois_name": whois.get("registrant_name") or whois.get("admin_name"),
        "emails_leaked": sorted(emails)[:20],
        "document_authors": sorted(authors)[:20],
        "social_hints": social,
    }


async def map_organization(scan_result: dict, llm_key: str,
                          ai_provider: str = "emergent",
                          ai_key: str | None = None) -> dict:
    signals = _collect_org_signals(scan_result)

    system_msg = (
        "Eres el MAPPER ORGANIZACIONAL. A partir de señales OSINT (WHOIS, autores de docs, "
        "emails filtrados, cuentas de GitHub) infieres roles y estimas exposición a "
        "ingeniería social. Solo trabajas con información PÚBLICA y AUTORIZADA. "
        "Respondes en JSON estricto en español."
    )
    prompt = f"""Señales OSINT del dominio:
{json.dumps(signals, ensure_ascii=False, indent=2)}

Devuelve JSON EXACTO. NO inventes personas si no hay señales — usa marcadores '?' si no lo sabes:
{{
  "organization_name": "nombre estimado o null",
  "org_type": "startup|enterprise|government|nonprofit|small_business|unknown",
  "key_people": [
    {{"handle_or_name": "nombre/handle/email", "inferred_role": "rol probable", "signal_source": "whois|metadata|breach|github", "social_exposure": "high|medium|low", "notes": "corto"}}
  ],
  "high_exposure_targets": ["subset de key_people con más riesgo de phishing"],
  "attack_surface_summary": "1 frase sobre la superficie humana"
}}
Máximo 10 key_people. Solo incluye a los que salen en las señales."""

    try:
        text, _ = await _call_ai_with_fallback(
            ai_provider if ai_key else "emergent",
            ai_key or llm_key, llm_key, system_msg, prompt, 0.25)
        m = re.search(r"\{[\s\S]*\}", text)
        parsed = json.loads(m.group(0) if m else text)
    except Exception as e:
        log.warning(f"Org-map AI failed: {e}")
        parsed = {"organization_name": None, "org_type": "unknown",
                  "key_people": [], "high_exposure_targets": [],
                  "attack_surface_summary": ""}

    return {
        "signals_used": signals,
        "organization_name": parsed.get("organization_name"),
        "org_type": parsed.get("org_type", "unknown"),
        "key_people": (parsed.get("key_people") or [])[:10],
        "high_exposure_targets": parsed.get("high_exposure_targets", [])[:5],
        "attack_surface_summary": parsed.get("attack_surface_summary", ""),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

"""Auto-Tagging IA — assign smart tags to a completed scan based on findings."""
import json
import re
import logging
from intel import _call_ai_with_fallback

log = logging.getLogger("auto_tags")

# Curated tag ontology — the AI is constrained to pick from this set
TAG_ONTOLOGY = [
    "e-commerce", "saas", "government", "healthcare", "financial",
    "media", "blog", "corporate", "portfolio", "landing-page",
    "critical-infrastructure", "dev-environment", "staging",
    "abandoned", "high-value-target", "small-business",
    "phishing-risk", "malware-adjacent", "typosquat-target",
    "cdn-protected", "self-hosted", "cloud-native",
    "wordpress", "shopify", "react-spa", "static-site",
    "api-heavy", "database-exposed", "cert-expiring-soon",
    "no-https", "old-tls", "high-exposure",
]


def _heuristic_tags(scan_result: dict) -> list[str]:
    """Baseline tags computed from raw signals (no AI needed)."""
    tags: set[str] = set()

    tech = scan_result.get("tech_analysis") or []
    cms_names = {c["name"].lower() for t in tech for c in (t.get("cms") or [])}
    frameworks = {f["name"].lower() for t in tech for f in (t.get("frameworks") or [])}
    if "wordpress" in cms_names:
        tags.add("wordpress")
    if "shopify" in cms_names:
        tags.add("shopify")
    if any(x in frameworks for x in ("react", "next.js", "vue", "angular", "svelte")):
        tags.add("react-spa")
    if any(t.get("is_protected") for t in tech):
        tags.add("cdn-protected")

    ports = (scan_result.get("ports") or {}).get("open_ports") or []
    for p in ports:
        if p["port"] in (3306, 5432, 6379, 27017, 9200):
            tags.add("database-exposed")
            tags.add("high-exposure")
            break

    ssl = scan_result.get("ssl") or {}
    tls = (ssl.get("tls_version") or "").upper()
    if tls in ("TLSV1", "TLSV1.1"):
        tags.add("old-tls")
    if not (scan_result.get("https_headers") or {}).get("success"):
        tags.add("no-https")

    subs_count = len((scan_result.get("subdomains") or {}).get("found") or [])
    if subs_count > 20:
        tags.add("high-value-target")

    return sorted(tags)


async def suggest_tags(scan_result: dict, llm_key: str,
                       ai_provider: str = "emergent",
                       ai_key: str | None = None) -> dict:
    heuristic = _heuristic_tags(scan_result)

    # Compact summary for AI (do NOT send the full result — too many tokens)
    summary = {
        "domain": scan_result.get("domain"),
        "whois_org": ((scan_result.get("whois") or {}).get("data") or {}).get("org"),
        "tech": [{"host": t.get("hostname"),
                  "cms": [c["name"] for c in t.get("cms") or []],
                  "frameworks": [f["name"] for f in t.get("frameworks") or []],
                  "server": t.get("server")}
                 for t in (scan_result.get("tech_analysis") or [])[:3]],
        "open_ports": [p["port"] for p in ((scan_result.get("ports") or {}).get("open_ports") or [])],
        "subdomain_sample": [s["subdomain"] for s in ((scan_result.get("subdomains") or {}).get("found") or [])[:8]],
        "cert_issuer": ((scan_result.get("ssl") or {}).get("issuer") or {}).get("organizationName"),
    }

    system_msg = (
        "Eres el AUTO-ETIQUETADOR IA. Recibes un resumen de escaneo OSINT y devuelves "
        "3-6 etiquetas de la ontología permitida que mejor describen el activo. "
        "Nunca inventes tags nuevas. Responde en JSON estricto en español."
    )
    prompt = f"""Ontología permitida (elige SOLO de esta lista):
{json.dumps(TAG_ONTOLOGY, ensure_ascii=False)}

Resumen del escaneo:
{json.dumps(summary, ensure_ascii=False, indent=2)}

Tags ya sugeridos por heurística (puedes ratificar o descartar):
{json.dumps(heuristic, ensure_ascii=False)}

Devuelve JSON EXACTO:
{{
  "tags": ["3-6 tags"],
  "primary_category": "una de: e-commerce, saas, government, healthcare, financial, media, blog, corporate, portfolio, landing-page, critical-infrastructure, dev-environment, staging, abandoned, small-business",
  "confidence": "alta|media|baja",
  "reasoning": "una frase que explica por qué esos tags"
}}"""

    ai_tags = []
    primary = None
    reasoning = ""
    confidence = "media"
    try:
        text, _ = await _call_ai_with_fallback(
            ai_provider if ai_key else "emergent",
            ai_key or llm_key, llm_key, system_msg, prompt, 0.2)
        m = re.search(r"\{.*\}", text, re.DOTALL)
        parsed = json.loads(m.group(0) if m else text)
        ai_tags = [t for t in (parsed.get("tags") or []) if t in TAG_ONTOLOGY]
        primary = parsed.get("primary_category") if parsed.get("primary_category") in TAG_ONTOLOGY else None
        reasoning = parsed.get("reasoning", "")
        confidence = parsed.get("confidence", "media")
    except Exception as e:
        log.warning(f"Auto-tag AI failed: {e}")

    combined = sorted(set(heuristic) | set(ai_tags))

    return {
        "tags": combined,
        "heuristic_tags": heuristic,
        "ai_tags": ai_tags,
        "primary_category": primary,
        "reasoning": reasoning,
        "confidence": confidence,
    }

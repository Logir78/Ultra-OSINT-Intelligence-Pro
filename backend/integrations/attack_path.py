"""Attack Path Mapper — chains findings into a step-by-step intrusion narrative."""
import json
import re
import logging
from datetime import datetime, timezone
from intel import _call_ai_with_fallback

log = logging.getLogger("attack_path")


def _collect_findings(scan_result: dict) -> dict:
    """Aggregate all interesting findings from a completed scan."""
    subs = (scan_result.get("subdomains") or {}).get("found", [])
    ports = (scan_result.get("ports") or {}).get("open_ports", [])
    ssl = scan_result.get("ssl") or {}
    tech = scan_result.get("tech_analysis") or []
    cloud = scan_result.get("cloud") or {}
    takeover = scan_result.get("takeover") or {}
    js_miner = scan_result.get("js_miner") or {}
    shodan_deep = scan_result.get("shodan_deep") or {}
    breach = scan_result.get("breaches") or {}
    metadata = scan_result.get("metadata") or {}

    # Filter interesting-only slice
    return {
        "domain": scan_result.get("domain"),
        "ip": (scan_result.get("ip") or {}).get("ip"),
        "subdomains_sample": [s["subdomain"] for s in subs[:20]],
        "risky_ports": [p for p in ports if p["port"] in {21, 22, 23, 25, 445, 3306, 3389, 5432, 6379, 9200, 27017}],
        "all_open_ports": [p["port"] for p in ports][:30],
        "ssl_issuer": (ssl.get("issuer") or {}).get("organizationName"),
        "tls_version": ssl.get("tls_version"),
        "tech_stack": [{"host": t.get("hostname"), "cms": [c["name"] for c in t.get("cms") or []],
                        "frameworks": [f["name"] for f in t.get("frameworks") or []],
                        "protected": t.get("is_protected"),
                        "missing_headers": t.get("missing_critical") or []}
                       for t in tech[:5]],
        "cloud_buckets": [
            {"name": b.get("name"), "kind": b.get("kind"), "listable": b.get("listable"),
             "url": b.get("url")}
            for b in (cloud.get("open") or [])[:10]],
        "vulnerable_subdomains": [
            {"subdomain": r.get("subdomain"), "service": r.get("service"), "evidence": (r.get("evidence") or "")[:120]}
            for r in (takeover.get("results") or []) if r.get("vulnerable")][:10],
        "js_secrets": [
            {"kind": f.get("kind"), "match": f.get("match", "")[:80], "source": f.get("source", "")[:100]}
            for f in (js_miner.get("findings") or [])
            if f.get("severity") in ("critical", "high")][:15],
        "js_endpoints": [f.get("match") for f in (js_miner.get("findings") or [])
                         if f.get("kind") == "api_endpoint"][:15],
        "shodan_critical_alerts": [a for a in ((shodan_deep or {}).get("hosts") or [])
                                    for _a in (a.get("alerts") or [])
                                    if _a.get("severity") == "critical"][:15],
        "leaked_emails_count": breach.get("total") or 0,
        "metadata_authors": [d.get("author") for d in (metadata.get("documents") or [])[:5] if d.get("author")],
    }


APT_PROFILES = {
    "none": "Actor genérico oportunista sin perfil específico.",
    "apt29_cozybear": "APT29 (Cozy Bear / Rusia): sofisticado, focus en spear-phishing, "
                     "supply-chain, tokens OAuth, persistencia sigilosa. Prioriza credenciales de nube y M365.",
    "apt41_china":    "APT41 (China): mixto espionaje+financiero. Explota web apps, credenciales VPN, "
                     "usa 0-days en CMS (WordPress/Confluence). Movimiento lateral rápido.",
    "lazarus_dprk":   "Lazarus (Corea del Norte): APT financiero. Phishing dirigido, malware customizado, "
                     "prioridad en exchanges cripto y SWIFT. Uso agresivo de LOLBins.",
    "conti_ransomware": "Conti/Ransomware afiliados: acceso vía RDP/VPN comprometidos, tools tipo Cobalt Strike, "
                       "encripta y exfiltra. Busca AD/backups.",
    "script_kiddie":  "Actor amateur: escaneos masivos, exploits públicos (Metasploit), takeovers de "
                     "subdominios abandonados. Bajo esfuerzo, alto ruido.",
    "insider":        "Amenaza interna: empleado descontento con credenciales legítimas, "
                     "abusa de accesos válidos, exfil por canales normales.",
}


async def build_attack_path(scan_result: dict, llm_key: str,
                            ai_provider: str = "emergent",
                            ai_key: str | None = None,
                            apt_persona: str = "none",
                            ai_mode: str = "precision") -> dict:
    findings = _collect_findings(scan_result)
    persona_desc = APT_PROFILES.get(apt_persona, APT_PROFILES["none"])

    system_msg = (
        "Eres el ESTRATEGA DE INTRUSIÓN. Encadenas hallazgos aparentemente aislados en una "
        "narrativa paso-a-paso que explica cómo un atacante REAL comprometería el sistema. "
        "Usa lenguaje SIMPLE (analogías físicas del tipo 'llave bajo el felpudo') para que "
        "un directivo no técnico entienda el peligro. Respondes en JSON estricto en español."
    )
    prompt = f"""Analiza estos hallazgos como un adversario que planea la intrusión completa.

PERFIL DE ADVERSARIO: {persona_desc}

Hallazgos del reconocimiento:
{json.dumps(findings, ensure_ascii=False, indent=2)}

Devuelve JSON EXACTO:
{{
  "executive_summary": "3-4 frases NO técnicas explicando el peligro principal con una analogía cotidiana",
  "attack_chain": [
    {{
      "step": 1,
      "action_technical": "descripción técnica corta",
      "action_plain": "misma acción en lenguaje sencillo con analogía",
      "asset_used": "qué hallazgo se utiliza",
      "outcome": "qué se logra en este paso"
    }},
    ...máximo 6 pasos
  ],
  "final_impact": "consecuencia final para el negocio (pérdidas económicas, reputación, RGPD, etc.) en 2 frases",
  "urgency": "critical|high|medium|low",
  "estimated_time_to_compromise": "ej: '2-6 horas', '1-3 días', '1-2 semanas'",
  "mitigation_priorities": ["3 acciones que romperían la cadena, ordenadas por impacto"],
  "confidence": "alta|media|baja"
}}"""

    try:
        temp = 0.2 if ai_mode == "precision" else 0.7
        text, used = await _call_ai_with_fallback(
            ai_provider if ai_key else "emergent",
            ai_key or llm_key,
            llm_key,
            system_msg, prompt, temp,
        )
        m = re.search(r"\{.*\}", text, re.DOTALL)
        parsed = json.loads(m.group(0) if m else text)
    except Exception as e:
        log.warning(f"Attack Path AI failed: {e}")
        parsed = {
            "executive_summary": "No se pudo generar la narrativa de ataque con IA en este momento.",
            "attack_chain": [],
            "final_impact": "",
            "urgency": "medium",
            "estimated_time_to_compromise": "desconocido",
            "mitigation_priorities": [],
            "confidence": "baja",
        }

    return {
        "apt_persona": apt_persona,
        "apt_description": persona_desc,
        "findings_analyzed": {
            "risky_ports": len(findings["risky_ports"]),
            "vulnerable_subdomains": len(findings["vulnerable_subdomains"]),
            "js_secrets": len(findings["js_secrets"]),
            "cloud_buckets": len(findings["cloud_buckets"]),
            "shodan_alerts": len(findings["shodan_critical_alerts"]),
        },
        **parsed,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

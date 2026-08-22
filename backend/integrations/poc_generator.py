"""PoC Generator — safe, non-destructive Proof-of-Concept snippets for critical findings."""
import json
import re
import logging
from datetime import datetime, timezone
from intel import _call_ai_with_fallback

log = logging.getLogger("poc_gen")


def _extract_critical_vulns(scan_result: dict) -> list[dict]:
    """Return a list of critical/high findings from all modules."""
    vulns = []

    # Takeover
    for r in ((scan_result.get("takeover") or {}).get("results") or []):
        if r.get("vulnerable"):
            vulns.append({
                "kind": "subdomain_takeover",
                "severity": "critical",
                "target": r.get("subdomain"),
                "service": r.get("service"),
                "evidence": (r.get("evidence") or "")[:200],
                "cname_chain": r.get("cname_chain") or [],
            })

    # Cloud open buckets
    for b in ((scan_result.get("cloud") or {}).get("open") or []):
        if b.get("listable"):
            vulns.append({
                "kind": "open_cloud_bucket",
                "severity": "critical",
                "target": b.get("url") or b.get("name"),
                "provider": b.get("kind"),
                "evidence": "Listable via public URL",
            })

    # Risky open ports without auth
    RISKY = {21: "FTP", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL",
             6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 3389: "RDP"}
    domain = scan_result.get("domain", "")
    for p in ((scan_result.get("ports") or {}).get("open_ports", []))[:15]:
        if p["port"] in RISKY:
            vulns.append({
                "kind": "exposed_service",
                "severity": "high",
                "target": f"{domain}:{p['port']}",
                "service": RISKY[p["port"]],
                "evidence": f"Port {p['port']} open externally",
            })

    # JS Miner critical secrets
    for f in ((scan_result.get("js_miner") or {}).get("findings") or []):
        if f.get("severity") == "critical":
            vulns.append({
                "kind": "leaked_secret_in_js",
                "severity": "critical",
                "target": f.get("source"),
                "service": f.get("kind"),
                "evidence": (f.get("match") or "")[:100],
            })

    # Shodan deep critical alerts
    for host in ((scan_result.get("shodan_deep") or {}).get("hosts") or []):
        for a in (host.get("alerts") or []):
            if a.get("severity") == "critical":
                vulns.append({
                    "kind": "unauth_service",
                    "severity": "critical",
                    "target": f"{host.get('ip')}:{a.get('port')}",
                    "service": a.get("service") or a.get("cve"),
                    "evidence": a.get("flag") or "No auth exposed",
                })

    return vulns[:15]  # cap


async def generate_pocs(scan_result: dict, llm_key: str,
                       ai_provider: str = "emergent",
                       ai_key: str | None = None) -> dict:
    vulns = _extract_critical_vulns(scan_result)
    if not vulns:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "vulns_analyzed": 0,
            "pocs": [],
            "message": "No hay vulnerabilidades críticas identificadas que requieran PoC.",
            "disclaimer": ("Todos los PoC son NO DESTRUCTIVOS y verifican únicamente la existencia del fallo. "
                           "Uso autorizado exclusivamente sobre sistemas propios o con permiso escrito."),
        }

    system_msg = (
        "Eres un pentester senior certificado. Generas Proof-of-Concept SEGUROS y NO destructivos "
        "en Python (usando requests/socket) o curl. NUNCA generas exploits que dañen datos, "
        "roben credenciales reales o modifiquen sistemas. Los PoCs solo verifican la EXISTENCIA "
        "del fallo (ej: 'este puerto responde', 'este archivo lista'). Respondes en JSON estricto."
    )
    prompt = f"""Genera Proof-of-Concept seguros para las siguientes vulnerabilidades detectadas:

{json.dumps(vulns, ensure_ascii=False, indent=2)}

Devuelve JSON EXACTO (sin markdown ni backticks):
{{
  "pocs": [
    {{
      "vuln_kind": "coincide con la kind del input",
      "target": "coincide con el target",
      "severity": "critical|high",
      "title": "nombre corto del PoC",
      "explanation_plain": "1 frase no técnica: '¿por qué esto es un problema?'",
      "poc_language": "python|curl|bash",
      "poc_code": "código completo listo para ejecutar (idempotente y no destructivo)",
      "expected_output": "qué debería mostrar si el fallo existe",
      "safety_notes": ["3 razones de por qué este PoC es seguro"],
      "remediation": "cómo arreglar el fallo (1-2 frases)"
    }}
  ]
}}

Máximo un PoC por vulnerabilidad. Prioriza los critical."""

    try:
        text, used = await _call_ai_with_fallback(
            ai_provider if ai_key else "emergent",
            ai_key or llm_key,
            llm_key,
            system_msg, prompt, 0.2,
        )
        m = re.search(r"\{.*\}", text, re.DOTALL)
        parsed = json.loads(m.group(0) if m else text)
    except Exception as e:
        log.warning(f"PoC AI failed: {e}")
        parsed = {"pocs": []}

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vulns_analyzed": len(vulns),
        "pocs": (parsed.get("pocs") or [])[:15],
        "disclaimer": ("Todos los PoC son NO DESTRUCTIVOS y verifican únicamente la existencia del fallo. "
                       "Uso autorizado exclusivamente sobre sistemas propios o con permiso escrito."),
    }

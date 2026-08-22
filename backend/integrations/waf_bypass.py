"""WAF Bypass Suggestor — analyses the fingerprint of a detected WAF/CDN and
suggests header obfuscations, payload variations, and evasion tactics ranked
by likelihood. Optionally augmented with an AI-generated tactical summary
(Emergent LLM key) when available.
"""
import os
import logging
from typing import Optional

log = logging.getLogger("waf_bypass")

# Curated, high-signal bypass playbook per WAF/CDN vendor. Techniques are
# widely published on OWASP / bugbounty reports (defensive research use).
WAF_PLAYBOOK = {
    "Cloudflare": {
        "risk": "medium",
        "notes": [
            "Cloudflare protege por IP de edge — a menudo la IP origen (host real) se expone en registros DNS antiguos, CT logs o correos MX.",
            "IUAM (I'm Under Attack Mode) activa desafíos JS. Cambios de User-Agent + IP residencial reducen fricción.",
        ],
        "techniques": [
            {"name": "Origin IP discovery", "category": "recon",
             "detail": "Consultar CT logs, ViewDNS, historical A records, MX/SPF, favicon hash y Shodan por certificado. Conectar directo a IP con Host header al dominio real."},
            {"name": "Header case & duplicate", "category": "payload",
             "detail": "Duplicar cabeceras (`X-Forwarded-For` + `X-Forwarded-For:`) o mezclar mayúsculas para desalinear el parser (`Cookie` vs `cookie`)."},
            {"name": "HTTP/2 request smuggling",  "category": "protocol",
             "detail": "Cloudflare a veces normaliza HTTP/2 → HTTP/1.1 al origen. Explorar CL.TE / TE.CL desync."},
            {"name": "Unicode & encoding", "category": "payload",
             "detail": "Codificar payloads con `%uXXXX`, doble URL-encoding, o fullwidth Unicode (ａｄｍｉｎ) para evadir regex."},
            {"name": "Rotating stealth UAs",     "category": "traffic",
             "detail": "NOCTUA usa StealthClient — rota User-Agent + Accept-Language por escaneo. Complementa con proxies residenciales."},
        ],
    },
    "Akamai": {
        "risk": "high",
        "notes": [
            "Akamai Kona/Bot Manager fingerprintea TLS (JA3) y ordenamiento HTTP/2. Solo cambiar UA no basta.",
            "Sensor data (Akamai Bot Manager) invalidará requests sin cookies válidas.",
        ],
        "techniques": [
            {"name": "JA3/JA4 rotation", "category": "protocol",
             "detail": "Usar librerías tipo curl-impersonate para replicar TLS ClientHello de Chrome/Firefox reales."},
            {"name": "Cookie rotation", "category": "traffic",
             "detail": "Sesionar previamente el sitio para obtener `_abck`, `bm_sz`, `ak_bmsc`. Reutilizar en scanner."},
            {"name": "Slowloris timing", "category": "traffic",
             "detail": "Espaciar requests 3-10s con `human_pause_chance` alto. Akamai marca ráfagas."},
            {"name": "Path normalization", "category": "payload",
             "detail": "Probar `//`, `/./`, `%2f`, `..%2f` — Akamai a veces normaliza distinto del origen."},
        ],
    },
    "Imperva": {
        "risk": "high",
        "notes": [
            "Imperva (Incapsula) usa cookie `visid_incap_*` y `incap_ses_*`. Rechaza requests sin JS render.",
        ],
        "techniques": [
            {"name": "Session cookie replay", "category": "traffic",
             "detail": "Renderizar la home una vez con Playwright y volcar cookies al scanner."},
            {"name": "IP subnet rotation", "category": "traffic",
             "detail": "Rate limit por /24. Usa un pool de IPs residenciales rotativas."},
            {"name": "Chunked encoding", "category": "protocol",
             "detail": "Enviar payloads con `Transfer-Encoding: chunked` — algunos rulesets de Imperva no reensamblan."},
        ],
    },
    "Sucuri": {
        "risk": "low",
        "notes": [
            "Sucuri es principalmente virtual patching; muchas reglas son firmas SQLi/XSS clásicas.",
        ],
        "techniques": [
            {"name": "SQL keyword split", "category": "payload",
             "detail": "Insertar comentarios `/*!50000UNION*/`, `SEL/**/ECT` para romper firmas."},
            {"name": "XSS via SVG/event obfuscation", "category": "payload",
             "detail": "`<svg/onload=confirm(1)>`, `<img src=x onerror=&#x61;lert(1)>`."},
            {"name": "Method override", "category": "protocol",
             "detail": "Usar `X-HTTP-Method-Override: PUT` en un POST."},
        ],
    },
    "AWS CloudFront": {
        "risk": "medium",
        "notes": [
            "CloudFront con AWS WAF: reglas custom o managed rules (Core, SQLi, Bot Control).",
        ],
        "techniques": [
            {"name": "Origin S3 discovery", "category": "recon",
             "detail": "Buscar buckets `*.s3.amazonaws.com` en JS/HTML y saltarse CloudFront directo."},
            {"name": "Country rotation", "category": "traffic",
             "detail": "AWS WAF a veces bloquea por GeoMatch. Proxies en países permitidos."},
            {"name": "Body size splitting", "category": "payload",
             "detail": "AWS WAF inspecciona solo primeros 8KB del body — payload después de padding puede evadir."},
        ],
    },
    "Fastly": {
        "risk": "low",
        "notes": [
            "Fastly VCL puede tener reglas custom por cliente. Sin bot manager por defecto.",
        ],
        "techniques": [
            {"name": "Cache poisoning probes", "category": "cache",
             "detail": "Explorar `X-Forwarded-Host`, `X-Original-URL` para envenenar edge cache."},
            {"name": "Purge key leaks", "category": "recon",
             "detail": "Buscar `Fastly-Debug-*` headers en respuestas."},
        ],
    },
}

# Generic advice cuando el WAF no está en el playbook
GENERIC_TECHNIQUES = [
    {"name": "Rotating User-Agent + Accept-Language", "category": "traffic",
     "detail": "NOCTUA StealthClient ya lo hace. Verifica que todos los módulos usen `stealth_httpx_client`."},
    {"name": "Timing jitter (100-800ms + human pauses)", "category": "traffic",
     "detail": "Evita ráfagas. WAFs modernos correlacionan por rate."},
    {"name": "Header case & order fuzz", "category": "payload",
     "detail": "Aleatorizar orden y capitalización de cabeceras HTTP/1.1."},
    {"name": "Path encoding tricks", "category": "payload",
     "detail": "Doble URL encode (`%252e%252e%252f`), overlong UTF-8, mixed case in path."},
    {"name": "Payload chunking", "category": "protocol",
     "detail": "Enviar el payload dividido en múltiples chunks (Transfer-Encoding)."},
    {"name": "Host header manipulation", "category": "payload",
     "detail": "Cambiar `Host:` a IP directa u host alternativo (SNI vs Host mismatch)."},
]


def suggest_bypass(tech_analysis: list[dict], target: str) -> dict:
    """Analyze tech stack fingerprint and produce a WAF bypass playbook.

    Args:
        tech_analysis: list of per-host tech dicts (from analyze_tech_for_hosts)
        target: root domain being scanned
    """
    detected_wafs = set()
    main_kind = None
    main_evidence = []

    for entry in tech_analysis or []:
        for p in entry.get("proxies", []):
            if p.get("category") in ("waf", "cdn+waf"):
                detected_wafs.add(p["name"])
                main_kind = p.get("category")
                main_evidence.append({"host": entry.get("hostname"), **p})

    playbook = []
    for waf in sorted(detected_wafs):
        entry = WAF_PLAYBOOK.get(waf)
        if entry:
            playbook.append({
                "waf": waf,
                "risk": entry["risk"],
                "notes": entry["notes"],
                "techniques": entry["techniques"],
            })

    return {
        "target": target,
        "waf_detected": bool(detected_wafs),
        "wafs": sorted(detected_wafs),
        "kind": main_kind,
        "evidence": main_evidence[:10],
        "playbook": playbook,
        "generic": GENERIC_TECHNIQUES,
        "ai_summary": None,  # filled in by caller if AI is enabled
    }


async def ai_summary(bypass_data: dict) -> Optional[str]:
    """Optional AI narrative summary of the bypass strategy. Uses Emergent LLM key."""
    key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not key or not bypass_data.get("waf_detected"):
        return None
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        wafs = ", ".join(bypass_data["wafs"])
        techs = []
        for entry in bypass_data["playbook"]:
            for t in entry["techniques"][:3]:
                techs.append(f"- [{entry['waf']}] {t['name']}: {t['detail']}")
        prompt = (
            f"Eres un red-teamer autorizado. El objetivo `{bypass_data['target']}` "
            f"está protegido por: {wafs}. Basado en estas técnicas conocidas:\n"
            + "\n".join(techs[:12])
            + "\n\nEscribe un briefing táctico en español (máx 200 palabras) explicando "
              "cómo abordar el reconocimiento y qué evasiones probar primero, ordenadas por "
              "probabilidad de éxito. NO incluyas payloads destructivos ni instrucciones para "
              "explotación real; solo estrategia defensiva/ofensiva ética alineada con bug bounty."
        )
        chat = LlmChat(api_key=key, session_id=f"wafbypass-{bypass_data['target']}",
                        system_message="You are a defensive security consultant briefing an authorized red team.")
        from claude_models import CLAUDE_TIERS
        chat = chat.with_model("anthropic", CLAUDE_TIERS["balanced"])
        resp = await chat.send_message(UserMessage(text=prompt))
        return str(resp).strip()
    except Exception as e:
        log.warning(f"WAF bypass AI summary failed: {e}")
        return None

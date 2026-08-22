"""Dev Style Profiler — AI infers dev-team maturity from code quality signals."""
import json
import re
import logging
from datetime import datetime, timezone
from intel import _call_ai_with_fallback

log = logging.getLogger("dev_profile")


def _collect_dev_signals(scan_result: dict) -> dict:
    """Aggregate signals that hint at dev maturity."""
    js_miner = scan_result.get("js_miner") or {}
    api_audit = scan_result.get("api_audit") or {}
    cloud_config = scan_result.get("cloud_config") or {}
    supply_chain = scan_result.get("supply_chain") or {}
    tech = scan_result.get("tech_analysis") or []
    headers = ((scan_result.get("https_headers") or {}).get("headers") or {})

    # Signal 1: comments in JS (TODO/FIXME → rushed)
    dev_comments = sum(1 for f in (js_miner.get("findings") or []) if f.get("kind") == "dev_comment")
    # Signal 2: leaked secrets in JS
    leaked_secrets = sum(1 for f in (js_miner.get("findings") or [])
                          if f.get("severity") in ("critical", "high") and f.get("kind") != "api_endpoint")
    # Signal 3: multiple API versions (v1, v2, v3) still active → poor deprecation
    active_versions = [b.get("url", "") for b in (api_audit.get("active_api_bases") or [])]
    version_count = sum(1 for u in active_versions if re.search(r"/v\d/", u))
    # Signal 4: exposed dev files
    config_leaks = (cloud_config.get("counts_by_severity") or {}).get("critical", 0) + \
                    (cloud_config.get("counts_by_severity") or {}).get("high", 0)
    # Signal 5: outdated libs w/ known CVEs
    vulnerable_libs = supply_chain.get("libraries_with_vulns", 0)
    # Signal 6: missing security headers
    critical_hdr = ["strict-transport-security", "content-security-policy", "x-frame-options"]
    missing_hdr = [h for h in critical_hdr if h not in {k.lower() for k in headers}]
    # Signal 7: swagger/docs exposed
    docs_exposed = any(("swagger" in (f.get("url") or "").lower() or
                        "openapi" in (f.get("url") or "").lower())
                       for f in (api_audit.get("findings") or []))

    return {
        "dev_comments_leaked": dev_comments,
        "secrets_leaked_in_js": leaked_secrets,
        "api_versions_active": version_count,
        "config_files_exposed": config_leaks,
        "vulnerable_libraries": vulnerable_libs,
        "missing_critical_headers": missing_hdr,
        "api_docs_exposed": docs_exposed,
        "tech_stack_diversity": len({t.get("hostname") for t in tech}),
    }


def _score(signals: dict) -> tuple[int, str]:
    """0..100 maturity score (higher = better)."""
    s = 80
    s -= min(30, 5 * signals["dev_comments_leaked"])
    s -= min(40, 20 * signals["secrets_leaked_in_js"])
    s -= min(15, 5 * signals["api_versions_active"])
    s -= min(30, 8 * signals["config_files_exposed"])
    s -= min(20, 4 * signals["vulnerable_libraries"])
    s -= 5 * len(signals["missing_critical_headers"])
    if signals["api_docs_exposed"]:
        s -= 5
    s = max(0, min(100, s))
    if s >= 75: label = "maduro"
    elif s >= 50: label = "estándar"
    elif s >= 25: label = "descuidado"
    else: label = "caótico"
    return s, label


async def profile_dev_team(scan_result: dict, llm_key: str,
                          ai_provider: str = "emergent",
                          ai_key: str | None = None) -> dict:
    signals = _collect_dev_signals(scan_result)
    score, label = _score(signals)

    system_msg = (
        "Eres el PERFILADOR DE ESTILO DE DESARROLLO. Recibes señales concretas sobre la práctica "
        "de desarrollo de un objetivo (comentarios TODO, secretos filtrados, versiones API, "
        "cabeceras faltantes) y describes el equipo en 3 rasgos, indicando la probabilidad de "
        "encontrar bugs lógicos básicos. Responde en JSON estricto en español."
    )
    prompt = f"""Señales de desarrollo:
{json.dumps(signals, ensure_ascii=False, indent=2)}

Puntaje determinista: {score}/100 ({label})

Devuelve JSON EXACTO:
{{
  "team_profile": "3 rasgos separados por coma (ej: 'rápido, descuidado, poca revisión de código')",
  "logic_bug_probability": "alta|media|baja",
  "bug_hunting_verdict": "1 frase de estilo: 'El equipo parece usar prácticas...'",
  "recommended_focus_areas": ["3 áreas donde buscar bugs con más probabilidad de éxito"]
}}"""

    try:
        text, _ = await _call_ai_with_fallback(
            ai_provider if ai_key else "emergent",
            ai_key or llm_key, llm_key, system_msg, prompt, 0.3)
        m = re.search(r"\{[\s\S]*\}", text)
        parsed = json.loads(m.group(0) if m else text)
    except Exception as e:
        log.warning(f"Dev-profile AI failed: {e}")
        parsed = {"team_profile": "señal insuficiente",
                  "logic_bug_probability": "media",
                  "bug_hunting_verdict": "",
                  "recommended_focus_areas": []}

    return {
        "maturity_score": score,
        "maturity_label": label,
        "signals": signals,
        "team_profile": parsed.get("team_profile", ""),
        "logic_bug_probability": parsed.get("logic_bug_probability", "media"),
        "bug_hunting_verdict": parsed.get("bug_hunting_verdict", ""),
        "recommended_focus_areas": parsed.get("recommended_focus_areas", [])[:5],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

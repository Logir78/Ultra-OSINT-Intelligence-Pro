"""Business Logic Flow Analyzer — AI maps critical processes and suggests bypass routes."""
import json
import re
import logging
from datetime import datetime, timezone
from intel import _call_ai_with_fallback

log = logging.getLogger("logic_flow")

# Regex patterns that identify critical business flows in URLs / endpoint discovery
FLOW_PATTERNS = {
    "authentication":     [r"/login", r"/signin", r"/auth", r"/oauth", r"/logout", r"/session"],
    "registration":       [r"/register", r"/signup", r"/register\-user", r"/create\-account"],
    "password_reset":     [r"/password.reset", r"/forgot", r"/reset\-password", r"/change\-password"],
    "payment_checkout":   [r"/checkout", r"/payment", r"/pay/", r"/billing", r"/subscribe", r"/upgrade"],
    "coupon_discount":    [r"/coupon", r"/promo", r"/discount", r"/voucher"],
    "email_verification": [r"/verify", r"/confirm", r"/activate"],
    "kyc_upload":         [r"/kyc", r"/verify\-identity", r"/upload\-doc"],
    "admin_panel":        [r"/admin", r"/dashboard/admin", r"/wp-admin"],
    "profile_update":     [r"/profile", r"/settings/account", r"/user/edit"],
    "api_versioning":     [r"/api/v[1-9]"],
}


def _detect_flows(scan_result: dict) -> dict[str, list[str]]:
    """Which business flows appear to exist based on discovered endpoints."""
    urls: set[str] = set()

    # JS Miner endpoints
    for f in ((scan_result.get("js_miner") or {}).get("findings") or []):
        if f.get("kind") == "api_endpoint":
            urls.add((f.get("match") or "").lower())
    # API Auditor findings
    for f in ((scan_result.get("api_audit") or {}).get("findings") or []):
        u = (f.get("url") or "").lower()
        # strip host to match pattern
        urls.add(re.sub(r"^https?://[^/]+", "", u))
    # Subdomains hint at possible flow surfaces
    for s in ((scan_result.get("subdomains") or {}).get("found") or []):
        name = (s.get("subdomain") or "").lower()
        # keywords in subdomain names
        for word in ("login", "auth", "sso", "checkout", "pay", "admin", "api",
                     "kyc", "signup", "portal"):
            if word in name:
                urls.add(f"//{name}")

    detected = {}
    for flow_name, patterns in FLOW_PATTERNS.items():
        matches = []
        for u in urls:
            for p in patterns:
                if re.search(p, u):
                    matches.append(u)
                    break
        if matches:
            detected[flow_name] = sorted(set(matches))[:15]
    return detected


async def analyze_logic_flows(scan_result: dict, llm_key: str,
                              ai_provider: str = "emergent",
                              ai_key: str | None = None,
                              ai_mode: str = "precision") -> dict:
    flows = _detect_flows(scan_result)
    if not flows:
        return {
            "flows_detected": 0,
            "flows": {},
            "bypass_scenarios": [],
            "note": "No se detectaron flujos críticos en los endpoints descubiertos.",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    system_msg = (
        "Eres el DETECTIVE DE LÓGICA. Recibes flujos de negocio detectados en un objetivo OSINT "
        "y sugieres pruebas AUTORIZADAS de bypass lógico (no ataques). Buscas patrones típicos: "
        "cupones aplicables N veces, race conditions en checkout, forzar rol admin, saltarse "
        "verificaciones de email, secuencias fuera de orden. Respondes en JSON estricto en español."
    )
    prompt = f"""Flujos de negocio detectados:
{json.dumps(flows, ensure_ascii=False, indent=2)}

Dominio: {scan_result.get('domain', '')}

Devuelve JSON EXACTO con hasta 8 escenarios de bypass:
{{
  "bypass_scenarios": [
    {{
      "flow": "nombre del flujo (uno de: authentication, registration, password_reset, payment_checkout, coupon_discount, email_verification, kyc_upload, admin_panel, profile_update)",
      "vulnerability_class": "clase de fallo lógico (race_condition, missing_step, insufficient_authorization, replay, forced_browsing, mass_assignment)",
      "hypothetical_bypass": "cómo se podría saltar en una frase (autorizado)",
      "test_steps": ["3 pasos concretos y no destructivos para verificar"],
      "expected_indicator": "qué respuesta HTTP/comportamiento confirmaría el bypass",
      "risk": "critical|high|medium",
      "impact_plain": "impacto en lenguaje sencillo, sin tecnicismos"
    }}
  ],
  "priority_flow": "el flujo con mayor riesgo",
  "overall_verdict": "una frase que resuma el riesgo lógico global"
}}"""

    try:
        temp = 0.25 if ai_mode == "precision" else 0.6
        text, _ = await _call_ai_with_fallback(
            ai_provider if ai_key else "emergent",
            ai_key or llm_key, llm_key, system_msg, prompt, temp)
        m = re.search(r"\{[\s\S]*\}", text)
        parsed = json.loads(m.group(0) if m else text)
    except Exception as e:
        log.warning(f"Logic-flow AI failed: {e}")
        parsed = {"bypass_scenarios": [], "priority_flow": None, "overall_verdict": ""}

    return {
        "flows_detected": len(flows),
        "flows": flows,
        "bypass_scenarios": (parsed.get("bypass_scenarios") or [])[:12],
        "priority_flow": parsed.get("priority_flow"),
        "overall_verdict": parsed.get("overall_verdict", ""),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

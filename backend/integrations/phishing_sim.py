"""Phishing Simulator — AI-generated email template + clone-target suggestion.
For authorized red-team exercises ONLY. Includes hard-coded legal disclaimer.
"""
import json
import re
import logging
from datetime import datetime, timezone
from intel import _call_ai_with_fallback

log = logging.getLogger("phishing_sim")

DISCLAIMER = (
    "USO EXCLUSIVAMENTE AUTORIZADO. Esta plantilla se genera para ejercicios de red-team "
    "internos con AUTORIZACIÓN ESCRITA de la organización objetivo. Su uso contra terceros "
    "sin permiso constituye un delito bajo las leyes de la mayoría de jurisdicciones."
)


async def generate_simulation(scan_result: dict, llm_key: str,
                              ai_provider: str = "emergent",
                              ai_key: str | None = None) -> dict:
    domain = scan_result.get("domain", "")
    tech = scan_result.get("tech_analysis") or []
    main = next((t for t in tech if t.get("hostname") == domain), tech[0] if tech else {})
    cms = [c["name"] for c in (main.get("cms") or [])]
    frameworks = [f["name"] for f in (main.get("frameworks") or [])]

    # Leaked emails from prior breach lookup (if any)
    breach = scan_result.get("breaches") or {}
    leaked_emails = [b.get("query") for b in (breach.get("breaches") or [])[:8] if b.get("query")]

    context = {
        "target_domain": domain,
        "detected_cms": cms,
        "detected_frameworks": frameworks,
        "server": main.get("server"),
        "leaked_emails_sample": leaked_emails,
        "has_login": "login" in " ".join([main.get("server", "").lower()] + cms + frameworks).lower(),
    }

    system_msg = (
        "Eres un consultor de red-team certificado. Diseñas simulaciones de phishing "
        "AUTORIZADAS para ejercicios internos de concienciación. NUNCA generas plantillas "
        "destinadas a víctimas sin consentimiento. Respondes en JSON estricto en español."
    )
    prompt = f"""Genera una plantilla de correo de simulación de phishing autorizada para el objetivo:

{json.dumps(context, ensure_ascii=False, indent=2)}

Devuelve JSON EXACTO (sin markdown ni comentarios):
{{
  "scenario_name": "nombre corto del escenario (ej: 'Reset urgente credenciales Office365')",
  "target_role": "rol tipo (ej: 'empleados con acceso al CRM')",
  "clone_target": {{
    "page_type": "qué página clonar (ej: 'portal de login corporativo Office365')",
    "url_suggestion": "propuesta de URL fake con dominio similar (ej: 'https://login-empresa-secure.com')",
    "visual_hints": "3 elementos visuales a replicar"
  }},
  "email": {{
    "subject": "asunto profesional (con marcador {{first_name}} si aplica)",
    "from_display": "quién parece enviarlo (ej: 'IT Security <it-security@empresa.com>')",
    "body_html": "<p>cuerpo HTML de 100-200 palabras con marcadores {{first_name}}, {{login_url}}, {{deadline}}</p>",
    "body_text": "versión texto plano equivalente"
  }},
  "psychological_triggers": ["3 palancas usadas (autoridad, urgencia, miedo, curiosidad, prueba social)"],
  "success_indicators": ["3 métricas medibles del ejercicio"],
  "safe_reminders": ["3 advertencias que se deben incluir en la landing tras clic"]
}}"""

    try:
        text, used = await _call_ai_with_fallback(
            ai_provider if ai_key else "emergent",
            ai_key or llm_key,
            llm_key,
            system_msg, prompt, 0.5,
        )
        m = re.search(r"\{.*\}", text, re.DOTALL)
        parsed = json.loads(m.group(0) if m else text)
    except Exception as e:
        log.warning(f"Phishing sim AI failed: {e}")
        parsed = {
            "scenario_name": "Fallback — reset de credenciales",
            "target_role": "empleados",
            "clone_target": {"page_type": "portal de login corporativo",
                             "url_suggestion": f"https://login-{domain}", "visual_hints": ""},
            "email": {"subject": "Acción urgente: verifica tu cuenta {{first_name}}",
                      "from_display": "IT",
                      "body_html": "<p>Estimado/a {{first_name}}, verifica tu acceso.</p>",
                      "body_text": "Verifica tu acceso."},
            "psychological_triggers": ["autoridad", "urgencia", "miedo"],
            "success_indicators": ["click rate", "credential capture rate", "report rate"],
            "safe_reminders": ["This was a simulation", "No credentials stored", "Report all real phishing"],
        }

    return {
        "disclaimer": DISCLAIMER,
        "authorization_required": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **parsed,
    }

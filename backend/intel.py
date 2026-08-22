"""Intelligence Summary — AI-powered 3-point briefing with risk-level classification."""
import json
import re
import uuid
import logging
from typing import Optional
from datetime import datetime, timezone
from emergentintegrations.llm.chat import LlmChat, UserMessage

log = logging.getLogger("intel")


def _domain_age_years(scan_result: dict) -> float | None:
    """Try to extract creation date from WHOIS and compute age in years."""
    whois_data = (scan_result.get("whois") or {}).get("data") or {}
    for key in ("creation_date", "created", "created_on", "registered", "registration_date"):
        v = whois_data.get(key)
        if not v:
            continue
        if isinstance(v, list):
            v = v[0] if v else None
        if not v:
            continue
        try:
            # try ISO first
            dt = datetime.fromisoformat(str(v).replace(" ", "T").split(".")[0])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - dt).days / 365.25
        except Exception:
            pass
    # fallback: use oldest wayback snapshot
    wb = scan_result.get("wayback") or {}
    oldest = (wb.get("oldest") or [])
    if oldest:
        try:
            dt = datetime.fromisoformat(oldest[0]["date"])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - dt).days / 365.25
        except Exception:
            pass
    return None


def compute_risk_level(scan_result: dict) -> dict:
    """Deterministic risk classification based on scan findings."""
    sec = scan_result.get("security") or {}
    basic = (sec.get("basic") or {}).get("score", 0)
    medium = (sec.get("medium") or {}).get("score", 0)
    advanced = (sec.get("advanced") or {}).get("score", 0)
    avg = (basic + medium + advanced) / 3 if (basic or medium or advanced) else 0

    open_ports = (scan_result.get("ports") or {}).get("open_ports", [])
    risky = [21, 23, 3389, 3306, 5432, 6379, 27017, 5900, 445]
    exposed_risky = [p for p in open_ports if p["port"] in risky]

    tech = scan_result.get("tech_analysis") or []
    main = next((t for t in tech if t.get("hostname") == scan_result.get("domain")), None)
    protected = bool(main and main.get("is_protected"))

    age_years = _domain_age_years(scan_result)

    # AbuseIPDB worst score if injected
    abuse_worst = int(scan_result.get("_abuse_worst_score") or 0)

    # Subdomain takeover (any vulnerable = critical)
    takeover_vulns = int(scan_result.get("_takeover_vulns") or 0)

    # rules
    if takeover_vulns > 0 or abuse_worst >= 50 or advanced < 40 or len(exposed_risky) >= 2:
        level = "red"
    elif age_years is not None and age_years < 1 and not protected:
        level = "red"
    elif abuse_worst >= 25:
        level = "orange"
    elif advanced >= 80 and (age_years is None or age_years >= 3) and len(exposed_risky) == 0 and medium >= 60 and abuse_worst == 0:
        level = "green"
    else:
        level = "orange"

    confidence = {"red": "Baja", "orange": "Media", "green": "Alta"}[level]

    return {
        "level": level,
        "confidence": confidence,
        "score_average": round(avg),
        "age_years": round(age_years, 1) if age_years is not None else None,
        "protected": protected,
        "exposed_risky_ports": [p["port"] for p in exposed_risky],
        "abuse_worst_score": abuse_worst,
        "takeover_vulns": takeover_vulns,
    }


async def generate_intel_summary(scan_result: dict, llm_key: str,
                                  ai_provider: str = "emergent",
                                  ai_key: str | None = None,
                                  ai_mode: str = "precision",
                                  claude_tier: str | None = None,
                                  ollama_url: str | None = None,
                                  ollama_model: str | None = None) -> dict:
    """Produce a 3-point intelligence briefing.

    ai_provider ∈ {emergent, openai, anthropic, gemini, ollama}
    ai_mode ∈ {precision, investigative}
    claude_tier ∈ {fast, balanced, deep} — applies when provider uses Claude (emergent/anthropic).
    ollama_url, ollama_model — required when ai_provider == 'ollama'.
    """
    from claude_models import resolve_claude_model
    claude_model = resolve_claude_model(tier_override=claude_tier)
    risk = compute_risk_level(scan_result)

    # Determine the effective provider and key
    effective_provider = ai_provider
    effective_key = ai_key or llm_key
    if ai_provider == "emergent" or not ai_key:
        effective_provider = "emergent"
        effective_key = llm_key

    if not effective_key:
        return {
            "profile": "IA no disponible (falta key).",
            "critical_risks": ["No se pudo generar el análisis con IA."],
            "confidence": risk["confidence"], "risk_level": risk["level"],
            "risk_meta": risk, "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    tech = scan_result.get("tech_analysis") or []
    main = next((t for t in tech if t.get("hostname") == scan_result.get("domain")), tech[0] if tech else {})
    proxies = [p["name"] for p in (main.get("proxies") or [])]
    cms = [c["name"] for c in (main.get("cms") or [])]
    frameworks = [f["name"] for f in (main.get("frameworks") or [])]
    subs = (scan_result.get("subdomains") or {}).get("found", [])
    wb = scan_result.get("wayback") or {}
    oldest_year = None
    if wb.get("oldest"):
        try:
            oldest_year = int(wb["oldest"][0]["date"][:4])
        except Exception:
            pass

    context = {
        "domain": scan_result.get("domain"),
        "ip": (scan_result.get("ip") or {}).get("ip"),
        "server": main.get("server"),
        "protected_by": proxies,
        "cms": cms,
        "frameworks": frameworks,
        "subdomains_count": len(subs),
        "subdomain_samples": [s["subdomain"] for s in subs[:8]],
        "open_ports": [p["port"] for p in (scan_result.get("ports") or {}).get("open_ports", [])],
        "ssl_issuer": ((scan_result.get("ssl") or {}).get("issuer") or {}).get("organizationName"),
        "ssl_tls_version": (scan_result.get("ssl") or {}).get("tls_version"),
        "security_scores": {
            "basic": ((scan_result.get("security") or {}).get("basic") or {}).get("score"),
            "medium": ((scan_result.get("security") or {}).get("medium") or {}).get("score"),
            "advanced": ((scan_result.get("security") or {}).get("advanced") or {}).get("score"),
        },
        "domain_age_years": risk["age_years"],
        "oldest_snapshot_year": oldest_year,
        "risk_level_hint": risk["level"],
    }

    prompt = f"""Eres un analista senior de ciberinteligencia. Genera un briefing de 3 puntos en JSON estricto para un ejecutivo.

Datos:
{json.dumps(context, ensure_ascii=False, indent=2)}

Responde EXACTAMENTE con este formato JSON (sin texto extra ni markdown):
{{
  "profile": "1-2 frases describiendo qué tipo de infraestructura es (CDN, hosting compartido, cloud propio, mail server, e-commerce, corporativo, etc.) y en qué tecnología corre",
  "critical_risks": [
    "punto crítico 1 accionable y específico",
    "punto crítico 2",
    "punto crítico 3"
  ]
}}

Reglas:
- Español profesional, sin adornos.
- Máximo 3 puntos críticos, cada uno de máx. 20 palabras.
- Si no hay riesgos graves, indica el mejor punto de mejora observable en `critical_risks`."""

    try:
        temperature = 0.1 if ai_mode == "precision" else 0.85
        system_msg = "Eres un analista de ciberinteligencia. Respondes en JSON estricto y en español."
        if ai_mode == "investigative":
            system_msg += (" Modo Investigativo: identifica patrones sutiles, correlaciones entre "
                           "hallazgos y posibles vectores de ataque basados en tu conocimiento.")
        else:
            system_msg += " Modo Precisión: cíñete estrictamente a los datos aportados, sin especular."

        text, used_provider = await _call_ai_with_fallback(
            effective_provider, effective_key, llm_key, system_msg, prompt, temperature,
            claude_model=claude_model,
            ollama_url=ollama_url,
            ollama_model=ollama_model,
        )
        m = re.search(r"\{.*\}", text.strip(), re.DOTALL)
        parsed = json.loads(m.group(0) if m else text)
        effective_provider = used_provider
    except Exception as e:
        log.exception("Intel LLM failed")
        parsed = {
            "profile": "No fue posible generar el perfil con IA en este momento.",
            "critical_risks": [f"Error de IA: {str(e)[:120]}"],
        }

    return {
        "profile": parsed.get("profile", ""),
        "critical_risks": parsed.get("critical_risks", [])[:3],
        "confidence": risk["confidence"],
        "risk_level": risk["level"],
        "risk_meta": risk,
        "ai_provider": effective_provider,
        "ai_mode": ai_mode,
        "claude_model": claude_model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


async def _call_ai_with_fallback(primary: str, primary_key: str, emergent_key: str,
                                  system_msg: str, prompt: str, temperature: float,
                                  claude_model: Optional[str] = None,
                                  ollama_url: Optional[str] = None,
                                  ollama_model: Optional[str] = None) -> tuple[str, str]:
    """Try primary provider. If it fails, degrade to Emergent as safety net."""
    try:
        return await _call_ai(primary, primary_key, system_msg, prompt, temperature,
                               claude_model=claude_model,
                               ollama_url=ollama_url,
                               ollama_model=ollama_model), primary
    except Exception as e:
        log.warning(f"Primary AI provider '{primary}' failed: {e}. Falling back to Emergent.")
        if primary == "emergent" or not emergent_key:
            raise
        try:
            text = await _call_ai("emergent", emergent_key, system_msg, prompt, temperature,
                                   claude_model=claude_model)
            return text, "emergent (fallback)"
        except Exception as e2:
            log.warning(f"Fallback to Emergent also failed: {e2}")
            raise


async def _call_ai(provider: str, key: str, system_msg: str, prompt: str, temperature: float,
                    claude_model: Optional[str] = None,
                    ollama_url: Optional[str] = None,
                    ollama_model: Optional[str] = None) -> str:
    from claude_models import resolve_claude_model
    if claude_model is None:
        claude_model = resolve_claude_model()
    if provider == "emergent":
        chat = LlmChat(
            api_key=key, session_id=f"intel-{uuid.uuid4().hex[:8]}",
            system_message=system_msg,
        ).with_model("anthropic", claude_model)
        raw = await chat.send_message(UserMessage(text=prompt))
        return str(raw)
    import httpx
    if provider == "openai":
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post("https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json={"model": "gpt-4o", "temperature": temperature,
                      "messages": [{"role": "system", "content": system_msg},
                                   {"role": "user", "content": prompt}],
                      "response_format": {"type": "json_object"}})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    if provider == "anthropic":
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post("https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": claude_model, "max_tokens": 1200,
                      "temperature": temperature, "system": system_msg,
                      "messages": [{"role": "user", "content": prompt}]})
        r.raise_for_status()
        return r.json()["content"][0]["text"]
    if provider == "ollama":
        base = (ollama_url or "").rstrip("/")
        model = ollama_model or "llama3.1"
        if not base:
            raise RuntimeError("Ollama base URL not configured")
        async with httpx.AsyncClient(timeout=120.0) as c:
            r = await c.post(f"{base}/api/chat",
                json={"model": model, "stream": False,
                       "options": {"temperature": temperature},
                       "messages": [{"role": "system", "content": system_msg},
                                    {"role": "user", "content": prompt}]})
        r.raise_for_status()
        d = r.json()
        return (d.get("message") or {}).get("content") or ""
    if provider == "gemini":
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post(
                "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent",
                params={"key": key},
                json={"systemInstruction": {"parts": [{"text": system_msg}]},
                      "contents": [{"parts": [{"text": prompt}]}],
                      "generationConfig": {"temperature": temperature, "responseMimeType": "application/json"}})
        r.raise_for_status()
        return r.json()["candidates"][0]["content"]["parts"][0]["text"]
    raise ValueError(f"Provider desconocido: {provider}")

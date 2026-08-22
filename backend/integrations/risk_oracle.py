"""Risk Oracle — AI-based breach probability score using tech debt + passive signals."""
import json
import re
import logging
from datetime import datetime, timezone
from intel import _call_ai_with_fallback

log = logging.getLogger("risk_oracle")


def _tech_debt_signals(scan_result: dict) -> dict:
    """Extract technical-debt hints from the scan."""
    signals = {"old_versions": [], "deprecated_tls": False, "no_https": False,
               "risky_ports": [], "missing_headers": [], "cert_expiry_days": None}

    # SSL/TLS
    ssl = scan_result.get("ssl") or {}
    tls = (ssl.get("tls_version") or "").upper()
    if tls in ("TLSV1", "TLSV1.1", "SSLV3", "SSLV2"):
        signals["deprecated_tls"] = True
    # cert expiry (days left)
    try:
        na = ssl.get("not_after")
        if na:
            dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            signals["cert_expiry_days"] = (dt - datetime.now(timezone.utc)).days
    except Exception:
        pass

    # HTTP-only
    headers = scan_result.get("https_headers") or {}
    if not headers.get("success"):
        signals["no_https"] = True

    # Missing critical headers
    for t in (scan_result.get("tech_analysis") or []):
        for missing in (t.get("missing_critical") or []):
            if missing not in signals["missing_headers"]:
                signals["missing_headers"].append(missing)

    # Tech versions — look for obviously old versions
    for t in (scan_result.get("tech_analysis") or []):
        for entry in (t.get("cms") or []) + (t.get("frameworks") or []) + (t.get("libraries") or []):
            name, ver = entry.get("name"), entry.get("version")
            if name and ver:
                # Heuristic: PHP < 8, jQuery < 3, Apache < 2.4, nginx < 1.20
                if name.lower() == "php" and _semver_lt(ver, "8.0"):
                    signals["old_versions"].append(f"{name} {ver} (soporte terminado)")
                elif name.lower() == "jquery" and _semver_lt(ver, "3.0"):
                    signals["old_versions"].append(f"{name} {ver}")
                elif name.lower() == "wordpress" and _semver_lt(ver, "6.0"):
                    signals["old_versions"].append(f"{name} {ver}")

    # Risky ports
    RISKY = {21: "FTP", 23: "Telnet", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
             6379: "Redis", 27017: "MongoDB", 445: "SMB", 9200: "Elasticsearch"}
    for p in (scan_result.get("ports") or {}).get("open_ports", []):
        if p["port"] in RISKY:
            signals["risky_ports"].append({"port": p["port"], "service": RISKY[p["port"]]})

    return signals


def _semver_lt(v: str, target: str) -> bool:
    def parse(s):
        return tuple(int(x) for x in re.findall(r"\d+", s)[:3]) or (0,)
    try:
        return parse(v) < parse(target)
    except Exception:
        return False


def _breach_signals(scan_result: dict) -> dict:
    """Extract leaked-credential hints (from prior breach lookups if run)."""
    bx = scan_result.get("breaches") or {}
    return {
        "leaked_emails": bx.get("total") or 0,
        "leaked_email_samples": [b.get("query") for b in (bx.get("breaches") or [])[:5] if b.get("query")],
    }


def _deterministic_probability(signals: dict) -> float:
    """Baseline percentage that the AI can then refine within a bounded range."""
    score = 5.0  # baseline
    if signals["deprecated_tls"]: score += 15
    if signals["no_https"]: score += 12
    score += min(20, 5 * len(signals["old_versions"]))
    score += min(25, 8 * len(signals["risky_ports"]))
    score += min(10, 2 * len(signals["missing_headers"]))
    if signals.get("cert_expiry_days") is not None and signals["cert_expiry_days"] < 30:
        score += 8
    return min(95.0, round(score, 1))


async def predict_breach(scan_result: dict, llm_key: str,
                          ai_provider: str = "emergent",
                          ai_key: str | None = None,
                          ai_mode: str = "precision") -> dict:
    tech = _tech_debt_signals(scan_result)
    breach = _breach_signals(scan_result)
    baseline = _deterministic_probability(tech)

    system_msg = ("Eres el ORÁCULO DE RIESGOS: un modelo predictivo de probabilidad de brecha. "
                  "Combinas deuda técnica + señales pasivas para estimar el riesgo a 90 días. "
                  "Responde en JSON estricto y español. Usa lenguaje claro no técnico.")
    prompt = f"""Analiza esta empresa/dominio y estima la probabilidad de sufrir una brecha en los próximos 90 días.

Deuda técnica detectada:
{json.dumps(tech, ensure_ascii=False, indent=2)}

Señales pasivas de credenciales:
{json.dumps(breach, ensure_ascii=False, indent=2)}

Baseline determinista calculado: {baseline}%

Ajusta ese baseline ±25 puntos según tu análisis. Devuelve JSON EXACTO:
{{
  "probability_percent": <0-100 número>,
  "verdict": "una frase de impacto no técnica que resume el peligro (tipo: 'Es como dejar la llave bajo el felpudo con la ventana abierta')",
  "top_risk_factors": ["3 factores principales, cada uno en 15 palabras máx"],
  "timeline": "corto/medio/largo plazo",
  "confidence": "alta/media/baja"
}}"""

    try:
        text, used = await _call_ai_with_fallback(
            ai_provider if ai_key else "emergent",
            ai_key or llm_key,
            llm_key,
            system_msg, prompt, 0.35,
        )
        m = re.search(r"\{.*\}", text, re.DOTALL)
        parsed = json.loads(m.group(0) if m else text)
    except Exception as e:
        log.warning(f"Oracle AI call failed: {e}")
        parsed = {
            "probability_percent": baseline,
            "verdict": "Predicción determinista sin IA. Deuda técnica evidente.",
            "top_risk_factors": [f"{len(tech['old_versions'])} versiones obsoletas",
                                 f"{len(tech['risky_ports'])} servicios peligrosos expuestos",
                                 "Cabeceras críticas ausentes"],
            "timeline": "corto plazo" if baseline >= 50 else "medio plazo",
            "confidence": "media",
        }

    prob = float(parsed.get("probability_percent", baseline))
    prob = max(0.0, min(100.0, prob))
    return {
        "probability_percent": round(prob, 1),
        "baseline_percent": baseline,
        "verdict": parsed.get("verdict", ""),
        "top_risk_factors": parsed.get("top_risk_factors", [])[:5],
        "timeline": parsed.get("timeline", "medio plazo"),
        "confidence": parsed.get("confidence", "media"),
        "tech_debt_signals": tech,
        "breach_signals": breach,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

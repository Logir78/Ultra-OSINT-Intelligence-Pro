"""IDOR Pattern Analyzer — map API endpoints with IDs and suggest fuzz variations."""
import re
import logging
import json
from intel import _call_ai_with_fallback

log = logging.getLogger("idor_analyzer")

# Patterns for endpoints containing sequential/enumerable identifiers
NUMERIC_ID_RE = re.compile(r"(/api/[^?\s\"']*?)/(\d{1,10})(/|$|\?)")
UUID_RE = re.compile(
    r"(/api/[^?\s\"']*?)/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$|\?)",
    re.IGNORECASE,
)
GUID_HEX_RE = re.compile(r"(/api/[^?\s\"']*?)/([0-9a-f]{16,32})(/|$|\?)", re.IGNORECASE)
QUERY_ID_RE = re.compile(r"[?&](user_?id|id|account|profile|record)=(\d{1,10}|[a-f0-9\-]{16,})", re.IGNORECASE)


def _classify_context(endpoint: str) -> tuple[str, str]:
    """(risk, hint) — 'critical' if endpoint clearly returns user data."""
    e = endpoint.lower()
    for word in ("account", "profile", "user", "order", "invoice", "payment",
                 "address", "message", "chat", "document", "file", "ticket",
                 "settings", "password", "email"):
        if word in e:
            return "critical", f"Contiene '{word}' — probablemente devuelve datos de usuario"
    if any(w in e for w in ("admin", "internal", "debug")):
        return "critical", "Endpoint administrativo — riesgo de escalado de privilegios"
    return "high", "Endpoint parametrizado — susceptible a enumeración"


def _generate_variations(id_value: str, kind: str) -> list[str]:
    """Suggest ID fuzz values."""
    variations = []
    if kind == "numeric":
        # Boundary values first so they always survive the truncation cap
        variations.extend(["0", "1", "-1"])
        try:
            n = int(id_value)
            for delta in (-3, -2, -1, 1, 2, 3, 100, 1000):
                v = n + delta
                if v > 0 and str(v) not in variations:
                    variations.append(str(v))
        except ValueError:
            pass
    elif kind == "uuid":
        # Suggest 00000000-... and ffffffff-... boundary values
        variations = [
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "11111111-1111-1111-1111-111111111111",
        ]
    return variations[:15]


def _extract_endpoints_from_scan(scan_result: dict) -> list[dict]:
    """Pull API endpoints from JS Miner + API Auditor results."""
    endpoints = []

    # JS Miner findings of kind=api_endpoint
    for f in ((scan_result.get("js_miner") or {}).get("findings") or []):
        if f.get("kind") == "api_endpoint":
            endpoints.append({"url": f.get("match", ""), "source": "js_miner"})

    # API Auditor findings
    for f in ((scan_result.get("api_audit") or {}).get("findings") or []):
        if f.get("url"):
            endpoints.append({"url": f["url"], "source": "api_audit"})
    for b in ((scan_result.get("api_audit") or {}).get("active_api_bases") or []):
        if b.get("url"):
            endpoints.append({"url": b["url"], "source": "api_audit_base"})

    # Param Miner candidate URLs
    for c in ((scan_result.get("param_miner") or {}).get("candidates") or []):
        if c.get("candidate_url"):
            endpoints.append({"url": c["candidate_url"], "source": "param_miner"})

    return endpoints


def _mine_id_patterns(endpoints: list[dict]) -> list[dict]:
    """Extract every URL that contains an ID pattern and build fuzz payloads."""
    findings = []
    seen = set()
    for e in endpoints:
        url = e["url"]
        matches = []
        for m in NUMERIC_ID_RE.finditer(url):
            matches.append(("numeric", m.group(1), m.group(2), m.start(2), m.end(2)))
        for m in UUID_RE.finditer(url):
            matches.append(("uuid", m.group(1), m.group(2), m.start(2), m.end(2)))
        for m in GUID_HEX_RE.finditer(url):
            matches.append(("guid_hex", m.group(1), m.group(2), m.start(2), m.end(2)))
        for m in QUERY_ID_RE.finditer(url):
            matches.append(("query", m.group(1), m.group(2), m.start(2), m.end(2)))
        for kind, prefix, value, s, en in matches:
            key = (url, s, value)
            if key in seen:
                continue
            seen.add(key)
            risk, hint = _classify_context(prefix)
            fuzz_ids = _generate_variations(value, "numeric" if kind == "numeric" else "uuid")
            fuzz_urls = [url[:s] + fv + url[en:] for fv in fuzz_ids] if fuzz_ids else []
            findings.append({
                "endpoint": url,
                "id_type": kind,
                "id_value": value,
                "endpoint_context": prefix,
                "risk": risk,
                "reason": hint,
                "fuzz_ids": fuzz_ids,
                "fuzz_urls": fuzz_urls[:6],
                "source": e["source"],
            })
    return findings


async def analyze_idor(scan_result: dict, llm_key: str,
                      ai_provider: str = "emergent",
                      ai_key: str | None = None) -> dict:
    endpoints = _extract_endpoints_from_scan(scan_result)
    id_findings = _mine_id_patterns(endpoints)

    # AI reasoning layer — pick top candidates + explain risk
    ai_recommendations = None
    if id_findings:
        try:
            sample = [{"endpoint": f["endpoint"], "id_type": f["id_type"],
                       "risk": f["risk"], "reason": f["reason"]}
                      for f in id_findings[:15]]
            system_msg = ("Eres un pentester experto en IDOR/BOLA. Recibes endpoints con IDs "
                          "y priorizas los más peligrosos para pruebas AUTORIZADAS. Responde en JSON estricto en español.")
            prompt = f"""Analiza estos endpoints con IDs enumerable:

{json.dumps(sample, ensure_ascii=False, indent=2)}

Devuelve JSON EXACTO:
{{
  "top_targets": [
    {{"endpoint": "...", "why_dangerous": "explicación corta", "test_strategy": "cómo probarlo de forma segura"}}
  ],
  "overall_verdict": "una frase que resuma el riesgo IDOR global"
}}
Prioriza max 5 top_targets."""
            text, _ = await _call_ai_with_fallback(
                ai_provider if ai_key else "emergent",
                ai_key or llm_key, llm_key, system_msg, prompt, 0.2)
            m = re.search(r"\{.*\}", text, re.DOTALL)
            ai_recommendations = json.loads(m.group(0) if m else text)
        except Exception as e:
            log.warning(f"IDOR AI failed: {e}")

    counts_by_risk = {"critical": 0, "high": 0}
    for f in id_findings:
        counts_by_risk[f["risk"]] = counts_by_risk.get(f["risk"], 0) + 1

    return {
        "endpoints_analyzed": len(endpoints),
        "total_id_patterns": len(id_findings),
        "counts_by_risk": counts_by_risk,
        "findings": sorted(id_findings, key=lambda x: {"critical": 0, "high": 1}.get(x["risk"], 2))[:60],
        "ai_recommendations": ai_recommendations,
    }

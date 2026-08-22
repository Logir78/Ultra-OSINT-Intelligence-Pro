"""Glass-box explainable AI (Diferenciador #5).

Competitors' AI is a black box: it states verdicts with no evidence. NOCTUA asks
the model for *structured* conclusions, then **grounds every claim against the
real scan data** before showing it. A claim whose cited evidence isn't found in
the scan is flagged `grounded:false` — that's the anti-hallucination guarantee.

Also emits a per-conclusion confidence and an overall trust score.
"""
from __future__ import annotations

import json
import logging

log = logging.getLogger("noctua.glassbox")

_SYSTEM = ("Eres un analista de ciberseguridad. Devuelve SOLO JSON válido. No inventes datos: "
           "cada conclusión debe citar evidencia textual presente en los datos aportados.")


def evidence_pool(scan_doc: dict) -> list[str]:
    """Flat list of factual strings from the scan the AI is allowed to cite."""
    r = scan_doc.get("result") or {}
    pool: list[str] = []
    if r.get("domain"):
        pool.append(f"domain={r['domain']}")
    ip = (r.get("ip") or {}).get("ip")
    if ip:
        pool.append(f"ip={ip}")
    ssl = r.get("ssl") or {}
    if ssl:
        pool.append(f"ssl_valid={ssl.get('success')}")
        pool.append(f"tls={ssl.get('tls_version')}")
    for p in (r.get("ports") or {}).get("open_ports", []):
        pool.append(f"open_port={p.get('port')}")
    for sub in (r.get("subdomains") or {}).get("found", []):
        h = sub.get("subdomain") if isinstance(sub, dict) else sub
        if h:
            pool.append(f"subdomain={h}")
    sec = r.get("security") or {}
    for level in ("basic", "medium", "advanced"):
        blk = sec.get(level) or {}
        if blk.get("score") is not None:
            pool.append(f"security_{level}_score={blk.get('score')}")
        for item in blk.get("items", []):
            if item.get("status") != "pass":
                pool.append(f"failed_check={item.get('check')}")
    return pool


def _build_prompt(pool: list[str]) -> str:
    data = "\n".join(f"- {p}" for p in pool)
    return (
        "Datos verificados del escaneo (única fuente permitida):\n" + data + "\n\n"
        "Devuelve un JSON con esta forma exacta:\n"
        '{"conclusions":[{"claim":"...","severity":"low|medium|high|critical",'
        '"evidence":["cita exacta de un dato de arriba"],"confidence":0.0-1.0,'
        '"uncertain":true|false}]}\n'
        "Reglas: máx. 6 conclusiones; cada evidence debe copiar un dato de la lista; "
        "si no estás seguro pon uncertain=true y baja la confidence."
    )


def _parse_json(text: str) -> dict:
    """Robustly extract the first JSON object from an LLM response."""
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t[:4].lower() == "json":
            t = t[4:]
    start = t.find("{")
    end = t.rfind("}")
    if start == -1 or end == -1:
        return {}
    try:
        return json.loads(t[start:end + 1])
    except Exception:
        return {}


def _ground(conclusion: dict, pool: list[str]) -> dict:
    pool_l = [p.lower() for p in pool]
    cites = conclusion.get("evidence") or []
    grounded_cites = []
    for c in cites:
        cl = str(c).strip().lower()
        # A citation is grounded if it matches (or is contained in) a real data point.
        if any(cl == p or cl in p or p in cl for p in pool_l):
            grounded_cites.append(c)
    grounded = bool(grounded_cites) and len(grounded_cites) == len(cites)
    conf = conclusion.get("confidence")
    try:
        conf = float(conf)
    except Exception:
        conf = 0.5
    return {
        "claim": conclusion.get("claim"),
        "severity": (conclusion.get("severity") or "medium").lower(),
        "evidence": cites,
        "grounded_evidence": grounded_cites,
        "grounded": grounded,
        "confidence": round(max(0.0, min(1.0, conf)), 2),
        "uncertain": bool(conclusion.get("uncertain")) or not grounded,
    }


async def explain(scan_doc: dict) -> dict:
    pool = evidence_pool(scan_doc)
    if not pool:
        return {"conclusions": [], "trust_score": 0, "note": "Sin datos de escaneo para explicar."}

    from app.llm import complete
    raw = await complete(_build_prompt(pool), _SYSTEM)
    parsed = _parse_json(raw)
    conclusions = [_ground(c, pool) for c in (parsed.get("conclusions") or [])]

    grounded_n = sum(1 for c in conclusions if c["grounded"])
    trust = int(round(100 * grounded_n / len(conclusions))) if conclusions else 0
    return {
        "scan_id": scan_doc.get("scan_id"),
        "domain": (scan_doc.get("result") or {}).get("domain"),
        "conclusions": conclusions,
        "grounded": grounded_n,
        "total": len(conclusions),
        "trust_score": trust,
        "note": ("Cada conclusión se contrasta contra los datos reales del escaneo. "
                 "'grounded:false' = la IA citó algo que no está en los datos (posible alucinación) "
                 "y se marca como no fiable."),
    }

"""Brand Guardian — typosquatting generation + DNS resolution + AI clone detection."""
import asyncio
import logging
import re
import string
import socket
import json
from intel import _call_ai_with_fallback

log = logging.getLogger("brand_guardian")

# Homoglyph substitutions (basic Latin only to keep it fast/portable)
HOMOGLYPHS = {
    "o": ["0"], "0": ["o"],
    "l": ["1", "i"], "1": ["l", "i"], "i": ["l", "1"],
    "e": ["3"], "3": ["e"],
    "a": ["4"], "4": ["a"],
    "s": ["5"], "5": ["s"],
    "b": ["8"], "8": ["b"],
    "g": ["q"], "q": ["g"],
    "m": ["rn"], "vv": ["w"], "w": ["vv"],
}

COMMON_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "shop", "app", "xyz",
               "online", "site", "top", "click", "email", "digital"]


def _bitflips(name: str) -> list[str]:
    """Adjacent-char swaps and single-char substitutions with common typos."""
    variants = set()
    # Adjacent swaps
    for i in range(len(name) - 1):
        v = list(name)
        v[i], v[i + 1] = v[i + 1], v[i]
        variants.add("".join(v))
    # Character insertions
    for i in range(len(name) + 1):
        for c in "aeiourstn":
            variants.add(name[:i] + c + name[i:])
    # Character deletions
    for i in range(len(name)):
        variants.add(name[:i] + name[i + 1:])
    return list(variants)


def _homoglyph_variants(name: str) -> list[str]:
    variants = set()
    for i, ch in enumerate(name):
        for sub in HOMOGLYPHS.get(ch, []):
            variants.add(name[:i] + sub + name[i + 1:])
    return list(variants)


def _typo_variants(domain: str) -> list[str]:
    """Generate suspicious variants of the target domain (SLD + TLD)."""
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    sld, tld = parts[0], ".".join(parts[1:])

    variants: set[str] = set()
    # SLD manipulations with same TLD
    for v in _bitflips(sld):
        variants.add(f"{v}.{tld}")
    for v in _homoglyph_variants(sld):
        variants.add(f"{v}.{tld}")
    # SLD-hyphen insertion
    for word in ["login", "secure", "auth", "support", "help", "account", "verify", "mail", "app"]:
        variants.add(f"{sld}-{word}.{tld}")
        variants.add(f"{word}-{sld}.{tld}")
    # Same SLD, different TLDs (TLD swap)
    for t in COMMON_TLDS:
        if t != tld:
            variants.add(f"{sld}.{t}")
    # Only valid dns names
    return [v for v in variants
            if re.match(r"^[a-z0-9\-]{1,63}(\.[a-z0-9\-]{2,63})+$", v)
            and v != domain][:120]


async def _resolve(host: str) -> tuple[str, str | None]:
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, host)
        return host, ip
    except Exception:
        return host, None


async def _resolve_bulk(hosts: list[str]) -> list[dict]:
    sem = asyncio.Semaphore(20)

    async def _one(h):
        async with sem:
            return await _resolve(h)

    results = await asyncio.gather(*[_one(h) for h in hosts])
    return [{"host": h, "ip": ip} for h, ip in results if ip]


async def scan_typosquats(domain: str, llm_key: str,
                          ai_provider: str = "emergent",
                          ai_key: str | None = None) -> dict:
    variants = _typo_variants(domain.lower())
    resolved = await _resolve_bulk(variants)
    hits = resolved[:60]  # cap for AI analysis

    ai_analysis = None
    if hits:
        try:
            names = [h["host"] for h in hits]
            system_msg = ("Eres el GUARDIÁN DE MARCA. Recibes una lista de dominios similares al objetivo "
                          "y debes clasificar cada uno como: 'clone' (probable phishing), 'suspicious' "
                          "(sospechoso pero no confirmado), o 'unrelated'. Responde en JSON estricto en español.")
            prompt = f"""Dominio objetivo legítimo: {domain}

Dominios similares detectados (ya resueltos en DNS): {json.dumps(names, ensure_ascii=False)}

Devuelve JSON EXACTO:
{{
  "brand_at_risk": <true|false>,
  "impersonation_verdict": "una frase que resuma el peligro para el CEO en lenguaje sencillo",
  "assessments": [
    {{"domain": "...", "class": "clone|suspicious|unrelated", "reason": "corta"}}
  ]
}}"""
            text, used = await _call_ai_with_fallback(
                ai_provider if ai_key else "emergent",
                ai_key or llm_key,
                llm_key,
                system_msg, prompt, 0.2,
            )
            m = re.search(r"\{.*\}", text, re.DOTALL)
            ai_analysis = json.loads(m.group(0) if m else text)
        except Exception as e:
            log.warning(f"Brand Guardian AI failed: {e}")

    # Attach class to each resolved variant
    class_map: dict[str, dict] = {}
    if ai_analysis:
        for a in ai_analysis.get("assessments") or []:
            class_map[a.get("domain", "").lower()] = {
                "class": a.get("class", "suspicious"),
                "reason": a.get("reason", ""),
            }

    for h in hits:
        info = class_map.get(h["host"], {"class": "suspicious", "reason": ""})
        h.update(info)

    clones = [h for h in hits if h.get("class") == "clone"]
    suspicious = [h for h in hits if h.get("class") == "suspicious"]

    return {
        "domain": domain,
        "variants_tested": len(variants),
        "resolved_variants": len(resolved),
        "clones_detected": len(clones),
        "suspicious_count": len(suspicious),
        "brand_at_risk": bool((ai_analysis or {}).get("brand_at_risk")) or len(clones) > 0,
        "impersonation_verdict": (ai_analysis or {}).get("impersonation_verdict", ""),
        "clones": clones[:40],
        "suspicious": suspicious[:40],
        "sample_resolved": hits[:20],
    }

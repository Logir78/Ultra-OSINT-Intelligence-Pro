"""Typosquatting / Homograph Hunter.

Generates plausible domain variants (typos + IDN homographs + TLD swaps) and
optionally probes them via DNS to see which are actually registered.
Used by brand protection teams to preemptively detect phishing campaigns.

Zero external dependencies.
"""
import asyncio
import logging
from typing import Iterable

import dns.resolver
import dns.exception

log = logging.getLogger("typosquat")

# Common TLD swaps (top phishing TLDs)
TLD_SWAPS = ["com", "net", "org", "io", "co", "app", "xyz", "info", "biz",
             "online", "site", "top", "click", "email", "link", "help", "support"]

# Common visual homoglyphs (Unicode confusables — limited to ASCII-safe set for practical hunt)
HOMOGLYPHS = {
    "o": ["0", "ο", "о"],   # cyrillic о
    "a": ["à", "á", "â", "ä"],
    "e": ["è", "é", "ê", "ë"],
    "i": ["1", "l", "í", "ì"],
    "l": ["1", "i", "|"],
    "u": ["ù", "ú", "û"],
    "s": ["5", "$"],
    "b": ["6", "8"],
    "g": ["9", "q"],
    "m": ["rn"],   # 'rn' can look like 'm'
    "n": ["m"],
    "c": ["ç"],
}

# Keyboard-adjacency for typos
QWERTY = {
    "q": "wa", "w": "qeas", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh",
    "u": "yij", "i": "uok", "o": "ipl", "p": "ol",
    "a": "qws", "s": "adwe", "d": "sfe", "f": "dgt", "g": "fhy", "h": "gjb",
    "j": "hkn", "k": "jlm", "l": "kp",
    "z": "xs", "x": "zcd", "c": "xvf", "v": "cbg", "b": "vnh", "n": "bmj", "m": "nk",
}


def _split_domain(domain: str) -> tuple[str, str]:
    parts = domain.split(".", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return domain, ""


def _gen_typos(name: str) -> Iterable[str]:
    for i, ch in enumerate(name):
        # Character omission
        yield name[:i] + name[i+1:]
        # Character swap with next
        if i < len(name) - 1:
            yield name[:i] + name[i+1] + name[i] + name[i+2:]
        # Character duplication
        yield name[:i] + ch + ch + name[i+1:]
        # Adjacent-key replacement
        for adj in QWERTY.get(ch.lower(), ""):
            yield name[:i] + adj + name[i+1:]


def _gen_homoglyphs(name: str) -> Iterable[str]:
    for i, ch in enumerate(name):
        for glyph in HOMOGLYPHS.get(ch.lower(), []):
            yield name[:i] + glyph + name[i+1:]


def _gen_hyphenation(name: str) -> Iterable[str]:
    """foo → f-oo, fo-o, etc."""
    for i in range(1, len(name)):
        yield name[:i] + "-" + name[i:]


def _gen_tld_swaps(name: str, current_tld: str) -> Iterable[str]:
    for tld in TLD_SWAPS:
        if tld != current_tld.lower():
            yield f"{name}.{tld}"


def generate_variants(domain: str, limit: int = 300) -> list[str]:
    """Generate a de-duplicated list of plausible typosquatting variants."""
    name, tld = _split_domain(domain.lower())
    if not name or not tld:
        return []
    variants: set[str] = set()
    # 1) Typos on the SLD (keep same TLD)
    for typo in _gen_typos(name):
        if typo and typo != name and " " not in typo:
            variants.add(f"{typo}.{tld}")
    # 2) Homoglyphs
    for hg in _gen_homoglyphs(name):
        if hg != name:
            variants.add(f"{hg}.{tld}")
    # 3) Hyphenation
    for hy in _gen_hyphenation(name):
        variants.add(f"{hy}.{tld}")
    # 4) TLD swaps
    for tsw in _gen_tld_swaps(name, tld):
        variants.add(tsw)
    # 5) Common prefixes/suffixes
    for word in ("secure", "login", "app", "my", "portal", "www"):
        variants.add(f"{word}-{name}.{tld}")
        variants.add(f"{name}-{word}.{tld}")
    variants.discard(domain.lower())
    result = list(variants)
    result.sort()
    return result[:limit]


async def _resolve(name: str) -> dict | None:
    """DNS-resolve a domain. Return {ip, ns} if it exists."""
    try:
        loop = asyncio.get_event_loop()
        a = await loop.run_in_executor(None, _sync_resolve, name)
        return a
    except Exception:
        return None


def _sync_resolve(name: str) -> dict | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4
        resolver.timeout = 4
        ans = resolver.resolve(name, "A")
        ips = [r.to_text() for r in ans]
        ns = []
        try:
            ns_ans = resolver.resolve(name, "NS")
            ns = [r.to_text() for r in ns_ans]
        except Exception:
            pass
        return {"ip": ips[0] if ips else None,
                "all_ips": ips[:5],
                "ns": ns[:3]}
    except Exception:
        return None


async def probe_variants(domain: str, max_probes: int = 150) -> dict:
    """Generate variants and DNS-probe them. Returns registered candidates."""
    variants = generate_variants(domain, limit=max_probes)
    # Limit concurrency to avoid DNS server flooding
    sem = asyncio.Semaphore(20)

    async def _one(v: str) -> tuple[str, dict | None]:
        async with sem:
            return v, await _resolve(v)

    results = await asyncio.gather(*[_one(v) for v in variants])

    registered = []
    for v, data in results:
        if data:
            registered.append({
                "variant": v,
                "ip": data["ip"],
                "all_ips": data["all_ips"],
                "ns": data["ns"],
                "kind": _classify_variant(domain, v),
            })

    # Sort by risk kind (homoglyph > tld_swap > typo > hyphen > prefix)
    KIND_RANK = {"homoglyph": 5, "tld_swap": 4, "typo": 3,
                 "hyphenation": 2, "prefix_suffix": 1}
    registered.sort(key=lambda r: KIND_RANK.get(r["kind"], 0), reverse=True)

    return {
        "target": domain,
        "variants_generated": len(variants),
        "variants_probed": len(results),
        "registered_count": len(registered),
        "registered": registered[:50],
        "risk_level": (
            "critical" if len(registered) >= 10 else
            "high" if len(registered) >= 5 else
            "medium" if len(registered) >= 2 else
            "low" if len(registered) >= 1 else "clean"
        ),
    }


def _classify_variant(original: str, variant: str) -> str:
    o_name, o_tld = _split_domain(original.lower())
    v_name, v_tld = _split_domain(variant.lower())
    if o_name == v_name and o_tld != v_tld:
        return "tld_swap"
    if "-" in v_name and "-" not in o_name:
        # Could be hyphenation or prefix/suffix
        parts = v_name.split("-")
        if o_name in parts:
            return "prefix_suffix"
        if "".join(parts) == o_name:
            return "hyphenation"
    if any(ord(c) > 127 for c in v_name):
        return "homoglyph"
    return "typo"

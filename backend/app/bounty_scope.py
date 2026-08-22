"""Bug-bounty scope awareness (Diferenciador #3).

Paste a program scope and NOCTUA respects it: every asset is classified
in-scope / out-of-scope / unknown, so you never waste time (or break rules) on
targets outside the program. Out-of-scope always wins over in-scope.
"""
from __future__ import annotations


def parse_scope(raw: str) -> dict:
    """Parse a free-text scope. Lines starting with '!' or '-' are out-of-scope.

    Examples of accepted lines:
        *.target.com          -> in-scope wildcard
        api.target.com        -> in-scope exact
        !staging.target.com   -> out-of-scope
        -*.internal.target.com-> out-of-scope wildcard
    """
    in_scope, out_scope = [], []
    for line in (raw or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s[0] in "!-":
            out_scope.append(_norm(s[1:]))
        else:
            in_scope.append(_norm(s))
    return {"in_scope": [p for p in in_scope if p], "out_scope": [p for p in out_scope if p]}


def _norm(pattern: str) -> str:
    p = pattern.strip().lower()
    for pre in ("https://", "http://"):
        if p.startswith(pre):
            p = p[len(pre):]
    return p.strip("/").strip()


def match_host(host: str, pattern: str) -> bool:
    host = (host or "").strip().lower().strip(".")
    pattern = (pattern or "").strip().lower().strip(".")
    if not host or not pattern:
        return False
    if pattern.startswith("*."):
        base = pattern[2:]
        # A wildcard covers sub-domains, NOT the apex (like a *.x TLS cert).
        return host.endswith("." + base)
    return host == pattern


def classify(host: str, scope: dict) -> str:
    """out_of_scope > in_scope > unknown."""
    if any(match_host(host, p) for p in scope.get("out_scope", [])):
        return "out_of_scope"
    if any(match_host(host, p) for p in scope.get("in_scope", [])):
        return "in_scope"
    return "unknown"


def _scan_hosts(scan_doc: dict) -> list[str]:
    result = scan_doc.get("result") or {}
    hosts = set()
    dom = result.get("domain")
    if dom:
        hosts.add(dom)
    for sub in (result.get("subdomains") or {}).get("found", []):
        h = sub.get("subdomain") if isinstance(sub, dict) else sub
        if h:
            hosts.add(h)
    return sorted(hosts)


def classify_scan_assets(scan_doc: dict, scope: dict) -> dict:
    buckets = {"in_scope": [], "out_of_scope": [], "unknown": []}
    for h in _scan_hosts(scan_doc):
        buckets[classify(h, scope)].append(h)
    return {
        "domain": (scan_doc.get("result") or {}).get("domain"),
        "counts": {k: len(v) for k, v in buckets.items()},
        "assets": buckets,
    }

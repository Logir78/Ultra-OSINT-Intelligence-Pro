"""Safe exploitability verification (Diferenciador #1).

Closes the market's "validation gap": most tools say *exposed* and stop. This
turns each critical finding into a verdict backed by **non-destructive, read-only**
evidence:

    verified    — independently confirmed live & reachable right now
    probable    — strong signal, but not actively confirmed (or unsafe to confirm)
    theoretical — reported by a source, not independently checked

Safety rules (non-negotiable):
  * Only GET/HEAD, read-only. Never write, delete, or use leaked credentials.
  * Every outbound request is guarded by the anti-SSRF check (assert_public_host).
  * Short timeouts; failures degrade to a lower-confidence verdict, never an error.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from security import assert_public_host

log = logging.getLogger("noctua.verifier")

VERIFIED = "verified"
PROBABLE = "probable"
THEORETICAL = "theoretical"

# Live takeover signatures (subset; the scanner already carries the full set).
_TAKEOVER_SIGNATURES = [
    "there isn't a github pages site here",
    "no such app",
    "herokucdn.com/error-pages/no-such-app.html",
    "the specified bucket does not exist",
    "nosuchbucket",
    "repository not found",
    "project not found",
    "do not have access to this shopify",
    "the request could not be satisfied",
    "fastly error: unknown domain",
    "unrecognized domain",
    "this page is reserved for future use",
]


async def _fetch(url: str, timeout: float = 8.0) -> dict:
    """Read-only GET. Returns {ok, status, text, error}. Never raises."""
    try:
        host = urlparse(url if "://" in url else f"//{url}").hostname or url
        assert_public_host(host)  # anti-SSRF: refuse internal targets
    except ValueError as e:
        return {"ok": False, "error": f"blocked: {e}"}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as c:
            r = await c.get(url, headers={"User-Agent": "NOCTUA-verifier"})
            return {"ok": True, "status": r.status_code, "text": r.text[:4000]}
    except Exception as e:  # noqa: BLE001 — degrade gracefully, never fail the scan
        return {"ok": False, "error": str(e)}


def _verdict(level: str, method: str, detail: str = "") -> dict:
    return {"verdict": level, "method": method, "detail": detail}


async def _verify_takeover(f: dict) -> dict:
    sub = f.get("subdomain")
    if not sub:
        return _verdict(THEORETICAL, "no-target")
    res = await _fetch(f"https://{sub}")
    if not res.get("ok"):
        return _verdict(PROBABLE, "unreachable",
                        "El fingerprint se detectó antes; ahora no responde.")
    body = (res.get("text") or "").lower()
    if any(sig in body for sig in _TAKEOVER_SIGNATURES):
        return _verdict(VERIFIED, "live-signature",
                        "La firma de takeover está viva: el servicio anuncia que el recurso no existe → reclamable.")
    return _verdict(PROBABLE, "reachable-no-signature",
                    "El subdominio responde pero no muestra la firma de takeover ahora mismo.")


async def _verify_open_bucket(f: dict) -> dict:
    url = f.get("url")
    if not url:
        return _verdict(THEORETICAL, "no-target")
    res = await _fetch(url)
    if not res.get("ok"):
        return _verdict(PROBABLE, "unreachable")
    text = res.get("text") or ""
    if res.get("status") == 200 and ("<ListBucketResult" in text or "<Contents>" in text
                                     or "<EnumerationResults" in text):
        return _verdict(VERIFIED, "listing-readable",
                        "El bucket devuelve un listado de objetos legible públicamente.")
    if res.get("status") in (200, 206):
        return _verdict(PROBABLE, "reachable")
    return _verdict(THEORETICAL, f"http-{res.get('status')}")


async def _verify_config_leak(f: dict) -> dict:
    url = f.get("url")
    if not url:
        return _verdict(THEORETICAL, "no-target")
    res = await _fetch(url)
    if not res.get("ok"):
        return _verdict(PROBABLE, "unreachable")
    text = res.get("text") or ""
    path = (f.get("path") or url).lower()
    if res.get("status") != 200 or not text.strip():
        return _verdict(THEORETICAL, f"http-{res.get('status')}")
    # Signature per leaked file type — confirms the sensitive content is really served.
    if ".git" in path and ("[core]" in text or "ref:" in text or "repositoryformatversion" in text):
        return _verdict(VERIFIED, "git-config-served", "El repositorio .git está expuesto y se sirve.")
    if ".env" in path and ("=" in text and any(k in text.upper() for k in ("KEY", "SECRET", "TOKEN", "PASSWORD", "DB"))):
        return _verdict(VERIFIED, "env-served", "El archivo .env con variables sensibles se sirve públicamente.")
    if any(k in text for k in ("BEGIN RSA", "BEGIN PRIVATE KEY", "aws_access_key_id")):
        return _verdict(VERIFIED, "secret-material-served")
    return _verdict(PROBABLE, "served-no-signature",
                    "El recurso responde 200 pero no coincide con una firma de contenido sensible.")


# Finding types we can safely verify. Secrets/services stay conservative on purpose:
# actively *using* a leaked credential would be unauthorized, so we never do it.
async def _verify_one(finding: dict) -> dict:
    ftype = finding.get("type")
    if ftype == "subdomain_takeover":
        v = await _verify_takeover(finding)
    elif ftype == "open_cloud_bucket":
        v = await _verify_open_bucket(finding)
    elif ftype == "config_leak":
        v = await _verify_config_leak(finding)
    elif ftype == "leaked_secret":
        v = _verdict(PROBABLE, "found-in-source",
                     "Secreto hallado en el código. No se valida usándolo (sería acceso no autorizado).")
    else:
        v = _verdict(THEORETICAL, "not-auto-verifiable")
    return {**finding, **v}


def _collect_findings(scan_doc: dict) -> list[dict]:
    """Reuse the same critical findings the evidence seal extracts."""
    from integrations.evidence_seal import seal_scan_evidence
    sealed = seal_scan_evidence(scan_doc).get("sealed_findings", [])
    return [s.get("finding", {}) for s in sealed]


async def verify_scan(scan_doc: dict) -> dict:
    findings = _collect_findings(scan_doc)
    results = []
    for f in findings:
        results.append(await _verify_one(f))
    summary = {VERIFIED: 0, PROBABLE: 0, THEORETICAL: 0}
    for r in results:
        summary[r.get("verdict", THEORETICAL)] = summary.get(r.get("verdict", THEORETICAL), 0) + 1
    return {
        "scan_id": scan_doc.get("scan_id"),
        "domain": (scan_doc.get("result") or {}).get("domain"),
        "total": len(results),
        "summary": summary,
        "note": ("Verificación no destructiva (solo lectura). 'verified' = confirmado en vivo; "
                 "'probable' = señal fuerte sin confirmar (o inseguro de confirmar); "
                 "'theoretical' = reportado, no comprobado de forma independiente."),
        "findings": results,
    }

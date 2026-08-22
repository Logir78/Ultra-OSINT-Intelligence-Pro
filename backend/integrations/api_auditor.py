"""API Auditor — passive discovery of API endpoints + version enumeration + auth flags."""
import asyncio
import httpx
import re
import logging

from integrations.stealth import stealth_httpx_client

log = logging.getLogger("api_auditor")

# Common API base paths to probe
API_BASES = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/graphql", "/graphiql",
]

# Sensitive endpoints often exposed by mistake
SENSITIVE_ENDPOINTS = [
    "docs", "swagger", "swagger-ui", "swagger-ui.html", "swagger/index.html",
    "openapi.json", "openapi.yaml", "api-docs", "api/docs",
    "debug", "debug/vars", "debug/pprof", "trace",
    "admin", "admin/users", "admin/config", "administrator",
    "internal", "internal/health", "internal/metrics",
    "metrics", "health", "healthz", "status", "server-status",
    "actuator", "actuator/env", "actuator/health", "actuator/heapdump",
    "console", "_cat", "_cluster",
    "users", "user", "accounts", "customers",
]


async def _probe(client: httpx.AsyncClient, url: str) -> dict | None:
    try:
        r = await client.get(url, timeout=5.0, follow_redirects=False,
                              headers={"Accept": "application/json"})
        if r.status_code in (200, 201, 401, 403, 405, 500):
            ct = r.headers.get("content-type", "")
            body_preview = r.text[:400] if r.text else ""
            is_json = "application/json" in ct or (body_preview.strip().startswith(("{", "[")) if body_preview else False)
            return {
                "url": url,
                "status": r.status_code,
                "content_type": ct[:80],
                "is_json": is_json,
                "auth_required": r.status_code in (401, 403),
                "body_preview": body_preview[:250],
            }
    except Exception:
        return None


async def _detect_graphql(client: httpx.AsyncClient, base: str) -> dict | None:
    """POST introspection query to /graphql — see if introspection is enabled."""
    url = f"{base}/graphql"
    try:
        r = await client.post(url, json={"query": "{__schema{types{name}}}"},
                              timeout=5.0, follow_redirects=False,
                              headers={"Content-Type": "application/json"})
        if r.status_code in (200, 400):
            j = r.json() if "application/json" in r.headers.get("content-type", "") else {}
            if isinstance(j, dict) and (j.get("data", {}).get("__schema") or j.get("errors")):
                return {"url": url, "introspection_enabled": bool(j.get("data")),
                        "sample": str(j)[:200]}
    except Exception:
        return None
    return None


async def audit_apis(domain: str) -> dict:
    """Discover API versions + sensitive endpoints + auth exposure."""
    async with stealth_httpx_client(domain, timeout=6.0) as client:
        # 1) Discover which /api/vN bases respond
        base_urls = [f"https://{domain}{b}" for b in API_BASES]
        base_results = await asyncio.gather(*[_probe(client, u) for u in base_urls])
        active_bases = [r for r in base_results if r]

        # 2) For each active API base, probe sensitive endpoints
        probe_tasks = []
        for base_res in active_bases:
            base = base_res["url"]
            for ep in SENSITIVE_ENDPOINTS:
                probe_tasks.append(_probe(client, f"{base}/{ep}"))

        # Also probe sensitive endpoints on root (not under /api)
        for ep in SENSITIVE_ENDPOINTS[:8]:  # top 8 only on root
            probe_tasks.append(_probe(client, f"https://{domain}/{ep}"))

        sensitive_results = await asyncio.gather(*probe_tasks) if probe_tasks else []
        sensitive = [r for r in sensitive_results if r]

        # 3) GraphQL introspection check
        graphql = await _detect_graphql(client, f"https://{domain}")

    # Classify each sensitive finding
    classified = []
    for f in sensitive:
        path_lower = f["url"].lower()
        severity = "medium"
        why = "endpoint expuesto"
        if not f["auth_required"] and f["status"] in (200, 201):
            if any(k in path_lower for k in ("admin", "debug", "internal", "actuator",
                                              "heapdump", "console", "server-status")):
                severity = "critical"
                why = "endpoint sensible sin auth"
            elif "docs" in path_lower or "swagger" in path_lower or "openapi" in path_lower:
                severity = "high"
                why = "documentación API pública (expone superficie de ataque)"
            elif "users" in path_lower or "accounts" in path_lower:
                severity = "critical"
                why = "endpoint de usuarios/cuentas sin auth"
            else:
                severity = "high"
                why = "endpoint respondiendo 200 sin auth"
        elif f["auth_required"]:
            if any(k in path_lower for k in ("admin", "internal", "actuator", "debug")):
                severity = "medium"
                why = "endpoint sensible con auth requerida (documenta la existencia)"
        classified.append({**f, "severity": severity, "reason": why})

    counts = {}
    for f in classified:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "domain": domain,
        "active_api_bases": [{"url": b["url"], "status": b["status"],
                               "auth_required": b["auth_required"]} for b in active_bases],
        "active_bases_count": len(active_bases),
        "sensitive_endpoints_probed": len(probe_tasks),
        "findings_total": len(classified),
        "counts_by_severity": counts,
        "findings": sorted(classified, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x["severity"], 4)),
        "graphql": graphql,
    }

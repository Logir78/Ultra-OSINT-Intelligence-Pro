"""Agentic recon orchestrator — "Autopilot" (Diferenciador #4).

Give it a scan and the agent decides which modules to run and **chains** them:
a finding in one step triggers the next (JS secret → audit its API; takeover
found → verify exploitability → notarize). It narrates every decision and stops
when a full pass surfaces nothing new (loop-until-dry).

The planner (the "brain") is pure and deterministic here; the executor is
injected so the router wires real integration modules while tests use fakes.
"""
from __future__ import annotations

from typing import Awaitable, Callable

# An executor runs one module against the scan state and returns its result dict.
Executor = Callable[[str, dict], Awaitable[dict]]


def _has_subdomains(state: dict) -> bool:
    r = state["scan_doc"].get("result") or {}
    return bool((r.get("subdomains") or {}).get("found"))


def _takeover_vulnerable(state: dict) -> bool:
    t = state["findings"].get("takeover") or {}
    return any(x.get("vulnerable") for x in (t.get("results") or []))


def _js_secrets(state: dict) -> bool:
    j = state["findings"].get("js_miner") or {}
    return any(f.get("severity") == "critical" for f in (j.get("findings") or []))


def _looks_cloud(state: dict) -> bool:
    r = state["scan_doc"].get("result") or {}
    hosts = [s.get("subdomain", "") if isinstance(s, dict) else str(s)
             for s in (r.get("subdomains") or {}).get("found", [])]
    return any(k in h for h in hosts for k in ("s3", "storage", "blob", "cdn", "azure", "gcs"))


# Each rule: (module, human reason, precondition). Order = base priority.
_RULES = [
    ("js_miner", "Minar JS/HTML en busca de secretos y endpoints ocultos",
     lambda s: True),
    ("takeover", "Hay subdominios sin comprobar subdomain takeover",
     lambda s: _has_subdomains(s)),
    ("cloud_scanner", "El objetivo muestra pistas de almacenamiento cloud (S3/Azure/GCS)",
     lambda s: _looks_cloud(s)),
    # ── Chained (reactive) steps ──────────────────────────────────────────
    ("api_audit", "Se filtró un secreto en el código → auditar el alcance de esa API",
     lambda s: _js_secrets(s)),
    ("verify_exploitability", "Se detectó un takeover → confirmar si es realmente explotable (#1)",
     lambda s: _takeover_vulnerable(s)),
    ("notarize", "Hay hallazgos críticos confirmados → sellar la evidencia con fecha (#2)",
     lambda s: _takeover_vulnerable(s) or _js_secrets(s)),
]


def plan_next(state: dict) -> list[dict]:
    """Return the modules whose preconditions are met and haven't run yet."""
    plan = []
    for module, reason, pre in _RULES:
        if module in state["done"]:
            continue
        try:
            if pre(state):
                plan.append({"module": module, "reason": reason})
        except Exception:
            continue
    return plan


async def run(scan_doc: dict, executor: Executor, max_steps: int = 10) -> dict:
    """Plan → execute → merge → re-plan, until dry or budget exhausted."""
    state = {"scan_doc": scan_doc, "findings": dict(scan_doc.get("findings") or {}), "done": set()}
    # Seed findings already present on the scan so the planner reacts to them.
    for k in ("takeover", "js_miner", "cloud", "cloud_config"):
        if scan_doc.get(k) is not None:
            state["findings"][k] = scan_doc[k]

    trace = []
    steps = 0
    while steps < max_steps:
        plan = plan_next(state)
        if not plan:
            break
        action = plan[0]  # highest-priority pending action
        module = action["module"]
        steps += 1
        try:
            result = await executor(module, state)
        except Exception as e:  # noqa: BLE001 — a failed step never kills the run
            result = {"error": str(e)}
        state["done"].add(module)
        # Merge result so later steps can react to it (chaining).
        if isinstance(result, dict) and not result.get("error"):
            state["findings"][module] = result
        trace.append({
            "step": steps,
            "module": module,
            "reason": action["reason"],
            "outcome": _summarize(module, result),
        })

    return {
        "scan_id": scan_doc.get("scan_id"),
        "domain": (scan_doc.get("result") or {}).get("domain"),
        "steps_run": steps,
        "modules_run": [t["module"] for t in trace],
        "trace": trace,
        "note": ("El copiloto encadenó módulos de forma autónoma: cada hallazgo activó el siguiente "
                 "paso. Se detuvo al no quedar acciones nuevas de alto valor."),
    }


def _summarize(module: str, result: dict) -> str:
    if not isinstance(result, dict):
        return "sin resultado"
    if result.get("error"):
        return f"error: {result['error']}"
    if module == "takeover":
        n = sum(1 for x in (result.get("results") or []) if x.get("vulnerable"))
        return f"{n} takeover(s) vulnerable(s)"
    if module == "js_miner":
        n = len(result.get("findings") or [])
        return f"{n} hallazgo(s) en JS"
    if module == "verify_exploitability":
        s = result.get("summary") or {}
        return f"veredictos: {s}"
    if module == "notarize":
        return f"notarizado ({result.get('total_findings_sealed', 0)} hallazgos, chain {str(result.get('chain_hash',''))[:12]}…)"
    return "ok"

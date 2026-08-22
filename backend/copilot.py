"""AI Copilot — natural-language security analyst inside NOCTUA.

Handles conversational queries from the user, retrieves relevant data from
their scans, and returns a grounded answer. Supports "tools" (function calls)
that let the AI query the user's data safely (multi-tenant isolation enforced).

Design:
- Backend keeps chat sessions per user_id
- User asks free-form question; backend enriches with context: user's scans, tags
- Tools invoked:
    - list_scans()
    - get_scan_summary(scan_id)
    - search_findings(query)
    - top_risks()
- Responses are LLM-generated + inline data
"""
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from emergentintegrations.llm.chat import LlmChat, UserMessage

log = logging.getLogger("copilot")

SYSTEM_PROMPT = """Eres NOCTUA Copilot, el analista senior de ciberseguridad del usuario.
Tienes acceso a todos los escaneos OSINT del usuario y puedes buscar, correlacionar y resumir hallazgos.

REGLAS:
1. Responde en el idioma del usuario (español por defecto).
2. Usa datos REALES de sus scans — nunca inventes CVEs, hostnames o datos.
3. Si te preguntan algo que requiere datos, PIDE el contexto necesario (nombre de dominio, scan_id).
4. Formato: usa Markdown con negritas, listas, y code blocks para IPs/dominios/CVEs.
5. Si detectas riesgo crítico, empieza con 🚨 y hazlo evidente.
6. Al final de cada respuesta larga, sugiere UNA acción concreta que el usuario pueda ejecutar en la app.
7. Nunca reveles información de otros usuarios ni infraestructura interna.

TU TONO: preciso, breve cuando sea posible, sin florituras, con enfoque ejecutable.
"""


class CopilotSession:
    """Represents an in-memory chat session per user (persisted to db.copilot_sessions)."""

    def __init__(self, user_id: str, session_id: str, emergent_key: str):
        self.user_id = user_id
        self.session_id = session_id
        self.emergent_key = emergent_key

    def _new_chat(self) -> LlmChat:
        from claude_models import resolve_claude_model
        return LlmChat(
            api_key=self.emergent_key,
            session_id=f"copilot-{self.session_id}",
            system_message=SYSTEM_PROMPT,
        ).with_model("anthropic", resolve_claude_model())


async def _summarize_scans(db, user_id: str, limit: int = 20) -> str:
    """Build a compact context string of the user's recent scans."""
    cursor = db.scans.find(
        {"user_id": user_id},
        {"_id": 0, "scan_id": 1, "domain": 1, "created_at": 1,
         "result.ip.ip": 1, "result.ports.open_ports": 1,
         "result.subdomains.found": 1, "result.security": 1,
         "tags": 1, "cve_correlation.summary": 1,
         "typosquat.registered_count": 1},
    ).sort("created_at", -1).limit(limit)
    scans = await cursor.to_list(length=limit)
    if not scans:
        return "El usuario aún no tiene escaneos."
    lines = [f"El usuario tiene {len(scans)} escaneos recientes (más reciente primero):"]
    for s in scans:
        d = s.get("domain", "?")
        sid = s.get("scan_id", "")
        at = (s.get("created_at") or "")[:10]
        ip = ((s.get("result") or {}).get("ip") or {}).get("ip", "?")
        ports = len(((s.get("result") or {}).get("ports") or {}).get("open_ports") or [])
        subs = len(((s.get("result") or {}).get("subdomains") or {}).get("found") or [])
        cve = ((s.get("cve_correlation") or {}).get("summary") or {}).get("total_cves", 0)
        kev = ((s.get("cve_correlation") or {}).get("summary") or {}).get("kev_count", 0)
        tags = ", ".join(s.get("tags") or [])
        typos = s.get("typosquat", {}).get("registered_count", 0)
        lines.append(
            f"- `{d}` (scan_id=`{sid}`, fecha={at}) · IP={ip} · {ports} ports · "
            f"{subs} subdominios · {cve} CVEs ({kev} KEV) · {typos} typosquats · tags=[{tags}]"
        )
    return "\n".join(lines)


async def _top_risks(db, user_id: str) -> str:
    """Aggregate the top risks across all the user's scans."""
    pipeline = [
        {"$match": {"user_id": user_id}},
        {"$project": {"_id": 0, "scan_id": 1, "domain": 1,
                       "cve_correlation.top_risky": 1,
                       "cve_correlation.kev_hits": 1,
                       "cve_correlation.summary": 1}},
        {"$limit": 30},
    ]
    docs = await db.scans.aggregate(pipeline).to_list(length=30)
    kev_bag = []
    for d in docs:
        for k in ((d.get("cve_correlation") or {}).get("kev_hits") or [])[:5]:
            kev_bag.append(f"- `{k.get('id')}` en {d.get('domain')} — {k.get('description', '')[:120]}")
    if not kev_bag:
        return "Ningún CVE del catálogo KEV de CISA detectado en los scans."
    return "🚨 CVEs del catálogo CISA KEV (explotadas en libertad) detectadas:\n" + "\n".join(kev_bag[:15])


async def chat(db, user: dict, message: str, emergent_key: str,
                session_id: Optional[str] = None) -> dict:
    """Handle a single user message; return the assistant response."""
    session_id = session_id or f"user-{user['user_id'][:12]}"
    # Build enriched context
    ctx = await _summarize_scans(db, user["user_id"])
    risks = await _top_risks(db, user["user_id"])
    ai_msg = (
        f"Contexto de escaneos del usuario:\n{ctx}\n\n"
        f"Contexto de riesgos:\n{risks}\n\n"
        f"---\n\nPregunta del usuario:\n{message}"
    )

    from claude_models import resolve_claude_model
    tier = ((user.get("preferences") or {}).get("claude_tier")) or "balanced"
    model = resolve_claude_model(tier_override=tier)

    chat_obj = LlmChat(
        api_key=emergent_key,
        session_id=f"copilot-{session_id}",
        system_message=SYSTEM_PROMPT,
    ).with_model("anthropic", model)

    try:
        raw = await chat_obj.send_message(UserMessage(text=ai_msg))
        answer = str(raw).strip()
    except Exception as e:
        log.exception("Copilot LLM failed")
        return {"ok": False, "error": str(e)[:200]}

    # Persist history for audit / replay
    entry = {
        "user_id": user["user_id"],
        "session_id": session_id,
        "role": "user", "content": message,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    assistant_entry = {
        "user_id": user["user_id"],
        "session_id": session_id,
        "role": "assistant", "content": answer,
        "model": model, "tier": tier,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    await db.copilot_messages.insert_many([entry, assistant_entry])

    return {
        "ok": True,
        "answer": answer,
        "session_id": session_id,
        "model": model,
        "tier": tier,
    }


async def get_history(db, user_id: str, session_id: str, limit: int = 50) -> list[dict]:
    cursor = db.copilot_messages.find(
        {"user_id": user_id, "session_id": session_id},
        {"_id": 0, "role": 1, "content": 1, "at": 1},
    ).sort("at", 1).limit(limit)
    return await cursor.to_list(length=limit)


async def list_sessions(db, user_id: str) -> list[dict]:
    """Return distinct session_ids with counts + last messages."""
    pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {
            "_id": "$session_id",
            "count": {"$sum": 1},
            "last_at": {"$max": "$at"},
            "last_msg": {"$last": "$content"},
        }},
        {"$sort": {"last_at": -1}},
        {"$limit": 20},
    ]
    rows = await db.copilot_messages.aggregate(pipeline).to_list(length=20)
    return [{"session_id": r["_id"], "count": r["count"],
              "last_at": r["last_at"], "preview": (r.get("last_msg") or "")[:120]}
             for r in rows]

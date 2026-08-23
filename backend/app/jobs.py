"""Background scan queue (P0 — producción fiable).

Escaneos largos ya no bloquean la petición: se encolan en `db.scan_jobs`, un
worker en segundo plano (arrancado en el startup, como el scheduler) los procesa
uno a uno y actualiza el progreso. El cliente hace polling del estado.

Cero infraestructura nueva: usa el MongoDB que ya tienes. Para varias instancias,
cambia el claim atómico por Redis/arq (ver DEPLOY.md).
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

log = logging.getLogger("noctua.jobs")

COLLECTION = "scan_jobs"

QUEUED = "queued"
RUNNING = "running"
DONE = "done"
FAILED = "failed"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def enqueue_scan(db, user_id: str, domain: str, *, extended_ports: bool = False,
                       ai_summary: bool = True) -> dict:
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    doc = {
        "job_id": job_id,
        "user_id": user_id,
        "domain": domain,
        "extended_ports": extended_ports,
        "ai_summary": ai_summary,
        "status": QUEUED,
        "progress": 0,
        "stage": "en cola",
        "scan_id": None,
        "error": None,
        "created_at": _now(),
    }
    await db[COLLECTION].insert_one(dict(doc))
    doc.pop("_id", None)
    return {"job_id": job_id, "status": QUEUED}


async def get_job(db, user_id: str, job_id: str) -> dict | None:
    return await db[COLLECTION].find_one(
        {"job_id": job_id, "user_id": user_id}, {"_id": 0})


async def list_jobs(db, user_id: str, limit: int = 50) -> list[dict]:
    cur = db[COLLECTION].find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1)
    return await cur.to_list(limit)


async def _set(db, job_id: str, **fields):
    await db[COLLECTION].update_one({"job_id": job_id}, {"$set": fields})


async def process_one(db) -> bool:
    """Claim and run a single queued job. Returns True if one was processed."""
    job = await db[COLLECTION].find_one_and_update(
        {"status": QUEUED},
        {"$set": {"status": RUNNING, "stage": "iniciando", "progress": 5,
                  "started_at": _now()}},
        sort=[("created_at", 1)],
    )
    if not job:
        return False

    job_id = job["job_id"]
    domain = job["domain"]
    try:
        from security import assert_public_host
        assert_public_host(domain)  # anti-SSRF antes de tocar la red

        from osint_engine import analyze_domain
        await _set(db, job_id, stage="analizando dominio", progress=25)
        analysis = await analyze_domain(domain, extended_ports=job.get("extended_ports", False))

        if job.get("ai_summary", True):
            from app.core import _generate_ai_summary
            await _set(db, job_id, stage="resumen IA", progress=75)
            analysis["ai_summary"] = await _generate_ai_summary(analysis)
        else:
            analysis["ai_summary"] = None

        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        await db.scans.insert_one({
            "scan_id": scan_id,
            "user_id": job["user_id"],
            "domain": analysis.get("domain", domain),
            "created_at": _now(),
            "extended_ports": job.get("extended_ports", False),
            "result": analysis,
        })
        await _set(db, job_id, status=DONE, stage="completado", progress=100,
                   scan_id=scan_id, finished_at=_now())
        return True
    except ValueError as e:  # SSRF guard
        await _set(db, job_id, status=FAILED, stage="bloqueado", error=str(e),
                   finished_at=_now())
        return True
    except Exception as e:  # noqa: BLE001
        log.exception("scan job %s failed", job_id)
        await _set(db, job_id, status=FAILED, stage="error", error=str(e),
                   finished_at=_now())
        return True


async def worker_loop(db, interval_seconds: float = 2.0):
    """Poll for queued jobs forever (started as a background task at startup)."""
    import asyncio
    log.info("Scan job worker started")
    while True:
        try:
            processed = await process_one(db)
            if not processed:
                await asyncio.sleep(interval_seconds)
        except Exception:  # noqa: BLE001 — never let the worker die
            log.exception("worker_loop iteration failed")
            await asyncio.sleep(interval_seconds)

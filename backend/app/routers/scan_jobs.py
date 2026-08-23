"""Routes: asynchronous (non-blocking) scans (P0 — producción fiable)."""
from fastapi import APIRouter, HTTPException, Depends

from app.core import db, get_current_user
from app.models import ScanRequest
from app import jobs

router = APIRouter()


@router.post("/scan/async")
async def create_async_scan(req: ScanRequest, user=Depends(get_current_user)):
    """Encola un escaneo y devuelve un job_id al instante (no bloquea)."""
    if not req.domain or len(req.domain.strip()) < 3:
        raise HTTPException(status_code=400, detail="Dominio inválido")
    return await jobs.enqueue_scan(
        db, user["user_id"], req.domain.strip(),
        extended_ports=req.extended_ports, ai_summary=req.ai_summary,
    )


@router.get("/scan/jobs")
async def list_scan_jobs(user=Depends(get_current_user)):
    items = await jobs.list_jobs(db, user["user_id"])
    return {"count": len(items), "jobs": items}


@router.get("/scan/jobs/{job_id}")
async def get_scan_job(job_id: str, user=Depends(get_current_user)):
    job = await jobs.get_job(db, user["user_id"], job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

"""NOCTUA.osint backend — application entrypoint.

The former ~2000-line monolith was split into a package (see IMPROVEMENTS.md):
  - app/core.py      shared DB client, auth dependency, LLM + helpers
  - app/models.py    pydantic models
  - app/routers/*    endpoints grouped by domain

This module only wires everything together.
"""
import os
import asyncio

from fastapi import FastAPI, APIRouter
from starlette.middleware.cors import CORSMiddleware

import payments as payments_mod
import schedules as schedules_mod
import telegram_bot as telegram_bot_mod
from security import SecurityHeadersMiddleware

from app.core import db, client, logger
from app.observability import setup_logging, install as install_observability
from app.routers import (
    auth, auth_native, scans, intel, settings, breaches, copilot, commerce, public,
    notary, exploit, bounty_pro, glassbox, autopilot, scan_jobs, apikeys,
)

# Structured logging (LOG_FORMAT=json|plain, LOG_LEVEL=INFO). Fase 2.
setup_logging()

app = FastAPI(title="OSINT Scanner API")

# ---- Routers (all under /api) ---------------------------------------------
api_router = APIRouter(prefix="/api")
for module in (auth, auth_native, scans, intel, settings, breaches, copilot, commerce, public, notary, exploit, bounty_pro, glassbox, autopilot, scan_jobs, apikeys):
    api_router.include_router(module.router)
app.include_router(api_router)

# Domain routers that follow the existing build_router(db, get_current_user) pattern
from app.core import get_current_user  # noqa: E402  (after app.core import above)
app.include_router(payments_mod.build_router(db, get_current_user))
app.include_router(schedules_mod.build_router(db, get_current_user))
app.include_router(telegram_bot_mod.build_router(db, get_current_user))

# ---- Middleware -----------------------------------------------------------
# CORS: prefer an explicit allowlist. allow_credentials=True with a wildcard
# origin is unsafe, so we no longer default to "*".
_cors_env = os.environ.get("CORS_ORIGINS", "").strip()
if _cors_env:
    _cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
else:
    _cors_origins = ["http://localhost:3000"]
    logger.warning(
        "CORS_ORIGINS not set — defaulting to %s. Set an explicit allowlist in production.",
        _cors_origins,
    )

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting (slowapi), request-id + access logging, and a catch-all 500 handler.
install_observability(app)


# ---- Lifecycle ------------------------------------------------------------
_scheduler_task = None
_worker_task = None


@app.on_event("startup")
async def start_scheduler():
    global _scheduler_task
    _scheduler_task = asyncio.create_task(
        schedules_mod.scheduler_loop(db, interval_seconds=60)
    )
    from app.jobs import worker_loop
    global _worker_task
    _worker_task = asyncio.create_task(worker_loop(db, interval_seconds=2))
    logger.info("Scheduler + scan worker tasks started")


@app.on_event("shutdown")
async def shutdown_db_client():
    global _scheduler_task, _worker_task
    if _scheduler_task:
        _scheduler_task.cancel()
    if _worker_task:
        _worker_task.cancel()
    client.close()

"""Scheduled scans, alerts, and Slack notifications (Pro feature)."""
import asyncio
import logging
import uuid
import httpx
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from osint_engine import analyze_domain

log = logging.getLogger("schedules")


FREQ_TO_HOURS = {"daily": 24, "weekly": 168, "monthly": 720}


class ScheduleCreate(BaseModel):
    domain: str
    frequency: str = "daily"  # daily | weekly | monthly | custom
    custom_hours: Optional[int] = None
    extended_ports: bool = False
    alert_types: list[str] = Field(
        default_factory=lambda: ["new_ports", "new_subdomains", "ssl_expiry", "ip_change", "security_headers"]
    )


class SlackConfig(BaseModel):
    webhook_url: Optional[str] = None


class TelegramConfig(BaseModel):
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None


def _interval_hours(sched: dict) -> int:
    if sched["frequency"] == "custom":
        return max(1, int(sched.get("custom_hours") or 24))
    return FREQ_TO_HOURS.get(sched["frequency"], 24)


def _next_run(sched: dict) -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=_interval_hours(sched))


def _diff_ports(prev: list[dict], curr: list[dict]) -> list[int]:
    prev_p = {p["port"] for p in (prev or [])}
    curr_p = {p["port"] for p in (curr or [])}
    return sorted(curr_p - prev_p)


def _diff_subdomains(prev: list[dict], curr: list[dict]) -> list[str]:
    prev_s = {s["subdomain"] for s in (prev or [])}
    curr_s = {s["subdomain"] for s in (curr or [])}
    return sorted(curr_s - prev_s)


def _ssl_days_left(ssl_info: dict) -> Optional[int]:
    if not ssl_info or not ssl_info.get("success"):
        return None
    not_after = ssl_info.get("not_after")
    if not not_after:
        return None
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except Exception:
        return None


SEC_HEADERS = [
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options",
]


def _missing_headers(headers: dict) -> set[str]:
    if not headers or not headers.get("success"):
        return set()
    h = {k.lower() for k in (headers.get("headers") or {}).keys()}
    return {sh for sh in SEC_HEADERS if sh not in h}


def _detect_changes(prev_result: dict, curr_result: dict, alert_types: list[str]) -> list[dict]:
    alerts = []
    if "new_ports" in alert_types:
        added = _diff_ports(prev_result.get("ports", {}).get("open_ports", []),
                            curr_result.get("ports", {}).get("open_ports", []))
        if added:
            alerts.append({"type": "new_ports", "severity": "high",
                           "title": f"Nuevos puertos abiertos: {', '.join(map(str, added))}",
                           "detail": {"ports": added}})
    if "new_subdomains" in alert_types:
        added = _diff_subdomains(prev_result.get("subdomains", {}).get("found", []),
                                 curr_result.get("subdomains", {}).get("found", []))
        if added:
            alerts.append({"type": "new_subdomains", "severity": "high",
                           "title": f"🎯 NUEVO ACTIVO detectado ({len(added)}): {', '.join(added[:5])}{'...' if len(added) > 5 else ''}",
                           "detail": {"subdomains": added, "bug_bounty_priority": True}})
    if "ssl_expiry" in alert_types:
        days = _ssl_days_left(curr_result.get("ssl", {}))
        if days is not None and days < 30:
            sev = "critical" if days < 7 else "high"
            alerts.append({"type": "ssl_expiry", "severity": sev,
                           "title": f"Certificado SSL caduca en {days} días",
                           "detail": {"days_left": days}})
    if "ip_change" in alert_types:
        prev_ip = prev_result.get("ip", {}).get("ip")
        curr_ip = curr_result.get("ip", {}).get("ip")
        if prev_ip and curr_ip and prev_ip != curr_ip:
            alerts.append({"type": "ip_change", "severity": "medium",
                           "title": f"IP cambió: {prev_ip} → {curr_ip}",
                           "detail": {"prev": prev_ip, "curr": curr_ip}})
    if "security_headers" in alert_types:
        prev_missing = _missing_headers(prev_result.get("https_headers", {}))
        curr_missing = _missing_headers(curr_result.get("https_headers", {}))
        newly_missing = curr_missing - prev_missing
        if newly_missing:
            alerts.append({"type": "security_headers", "severity": "high",
                           "title": f"Cabeceras de seguridad perdidas: {', '.join(sorted(newly_missing))}",
                           "detail": {"missing": sorted(newly_missing)}})
    return alerts


async def _send_slack(webhook_url: str, domain: str, alerts: list[dict]):
    if not webhook_url or not alerts:
        return
    color_map = {"critical": "#FF3366", "high": "#FFB000", "medium": "#00E5FF", "low": "#666"}
    blocks = []
    for a in alerts:
        blocks.append({
            "color": color_map.get(a["severity"], "#666"),
            "text": f"*[{a['severity'].upper()}]* {a['title']}",
        })
    payload = {
        "text": f":rotating_light: NOCTUA · Cambios detectados en `{domain}` ({len(alerts)} alertas)",
        "attachments": [{"color": b["color"], "text": b["text"]} for b in blocks],
    }
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            await c.post(webhook_url, json=payload)
    except Exception as e:
        log.warning(f"Slack webhook failed: {e}")


SEV_EMOJI = {"critical": "🚨", "high": "⚠️", "medium": "🔶", "low": "ℹ️"}


def _escape_md(text: str) -> str:
    # Escape underscores/asterisks/backticks/brackets for Telegram Markdown v1
    if not text:
        return ""
    for ch in ("_", "*", "`", "["):
        text = text.replace(ch, f"\\{ch}")
    return text


async def _send_telegram(bot_token: str, chat_id: str, domain: str, alerts: list[dict]):
    if not bot_token or not chat_id or not alerts:
        return
    header = f"🦉 *NOCTUA.osint* · `{_escape_md(domain)}`\n{len(alerts)} cambio(s) detectado(s)\n"
    lines = [header]
    for a in alerts:
        emoji = SEV_EMOJI.get(a["severity"], "•")
        lines.append(f"{emoji} *{a['severity'].upper()}* — {_escape_md(a['title'])}")
    text = "\n".join(lines)
    if len(text) > 3800:
        text = text[:3800] + "\n…"
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True,
                },
            )
            if r.status_code != 200:
                log.warning(f"Telegram send failed: HTTP {r.status_code} {r.text[:200]}")
    except Exception as e:
        log.warning(f"Telegram webhook failed: {e}")


def build_router(db, get_current_user):
    router = APIRouter(prefix="/api")

    def _require_pro(user: dict):
        if user.get("plan") != "pro":
            raise HTTPException(status_code=402, detail="Pro plan required")

    @router.post("/schedules")
    async def create_schedule(payload: ScheduleCreate, user=Depends(get_current_user)):
        _require_pro(user)
        if payload.frequency not in ("daily", "weekly", "monthly", "custom"):
            raise HTTPException(400, "Invalid frequency")
        sched_id = f"sch_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        doc = {
            "schedule_id": sched_id,
            "user_id": user["user_id"],
            "domain": payload.domain.strip().lower(),
            "frequency": payload.frequency,
            "custom_hours": payload.custom_hours,
            "extended_ports": payload.extended_ports,
            "alert_types": payload.alert_types,
            "enabled": True,
            "created_at": now,
            "next_run_at": now,  # first run ASAP
            "last_run_at": None,
            "last_scan_id": None,
        }
        await db.schedules.insert_one(doc)
        doc.pop("_id", None)
        return doc

    @router.get("/schedules")
    async def list_schedules(user=Depends(get_current_user)):
        cursor = db.schedules.find({"user_id": user["user_id"]}, {"_id": 0}).sort("created_at", -1)
        return await cursor.to_list(length=200)

    @router.delete("/schedules/{schedule_id}")
    async def delete_schedule(schedule_id: str, user=Depends(get_current_user)):
        res = await db.schedules.delete_one({"schedule_id": schedule_id, "user_id": user["user_id"]})
        if res.deleted_count == 0:
            raise HTTPException(404, "Schedule not found")
        return {"ok": True}

    @router.patch("/schedules/{schedule_id}")
    async def toggle_schedule(schedule_id: str, user=Depends(get_current_user)):
        sched = await db.schedules.find_one({"schedule_id": schedule_id, "user_id": user["user_id"]}, {"_id": 0})
        if not sched:
            raise HTTPException(404, "Schedule not found")
        new_state = not sched.get("enabled", True)
        await db.schedules.update_one(
            {"schedule_id": schedule_id},
            {"$set": {"enabled": new_state}},
        )
        sched["enabled"] = new_state
        return sched

    @router.get("/alerts")
    async def list_alerts(user=Depends(get_current_user)):
        cursor = db.alerts.find({"user_id": user["user_id"]}, {"_id": 0}).sort("created_at", -1).limit(100)
        return await cursor.to_list(length=100)

    @router.post("/alerts/{alert_id}/read")
    async def mark_read(alert_id: str, user=Depends(get_current_user)):
        await db.alerts.update_one(
            {"alert_id": alert_id, "user_id": user["user_id"]},
            {"$set": {"read": True}},
        )
        return {"ok": True}

    @router.get("/settings/slack")
    async def get_slack(user=Depends(get_current_user)):
        return {"webhook_url": user.get("slack_webhook_url")}

    @router.post("/settings/slack")
    async def set_slack(cfg: SlackConfig, user=Depends(get_current_user)):
        _require_pro(user)
        url = (cfg.webhook_url or "").strip() or None
        if url and not url.startswith("https://hooks.slack.com/"):
            raise HTTPException(400, "Must be a valid https://hooks.slack.com/... URL")
        await db.users.update_one(
            {"user_id": user["user_id"]},
            {"$set": {"slack_webhook_url": url}},
        )
        return {"webhook_url": url}

    @router.get("/settings/telegram")
    async def get_telegram(user=Depends(get_current_user)):
        tg = user.get("telegram") or {}
        token = (tg.get("bot_token") or "").strip()
        chat_id = (tg.get("chat_id") or "").strip()
        return {
            "bot_token_set": bool(token),
            "bot_token_masked": (token[:6] + "•" * 6 + token[-4:]) if len(token) > 12 else ("•" * len(token) if token else ""),
            "chat_id": chat_id,
        }

    @router.post("/settings/telegram")
    async def set_telegram(cfg: TelegramConfig, user=Depends(get_current_user)):
        _require_pro(user)
        token = (cfg.bot_token or "").strip() or None
        chat_id = (cfg.chat_id or "").strip() or None
        # Allow clearing (both empty). If any provided, both are required.
        if (token and not chat_id) or (chat_id and not token):
            raise HTTPException(400, "Se requieren Bot Token y Chat ID juntos")
        if token and ":" not in token:
            raise HTTPException(400, "Bot token con formato inválido (esperado: 12345:AAA...)")
        await db.users.update_one(
            {"user_id": user["user_id"]},
            {"$set": {"telegram": {"bot_token": token, "chat_id": chat_id} if token else None}},
        )
        return {"bot_token_set": bool(token), "chat_id": chat_id}

    @router.post("/settings/telegram/test")
    async def test_telegram_settings(cfg: TelegramConfig, user=Depends(get_current_user)):
        _require_pro(user)
        token = (cfg.bot_token or "").strip()
        chat_id = (cfg.chat_id or "").strip()
        # If any field is blank, fall back to stored values
        if not token or not chat_id:
            stored = user.get("telegram") or {}
            token = token or (stored.get("bot_token") or "")
            chat_id = chat_id or (stored.get("chat_id") or "")
        if not token or not chat_id:
            raise HTTPException(400, "Faltan Bot Token y/o Chat ID")
        from user_settings import test_telegram
        res = await test_telegram(token, chat_id)
        return res

    return router


async def _run_due_schedules(db):
    """Find schedules whose next_run_at has passed and execute them."""
    now = datetime.now(timezone.utc)
    cursor = db.schedules.find(
        {"enabled": True, "next_run_at": {"$lte": now.isoformat()}},
        {"_id": 0},
    )
    due = await cursor.to_list(length=50)
    for sched in due:
        try:
            await _execute_schedule(db, sched)
        except Exception:
            log.exception(f"Schedule execution failed for {sched.get('schedule_id')}")


async def _execute_schedule(db, sched: dict):
    log.info(f"Executing schedule {sched['schedule_id']} for {sched['domain']}")
    result = await analyze_domain(sched["domain"], extended_ports=sched.get("extended_ports", False))
    now_iso = datetime.now(timezone.utc).isoformat()
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    await db.scans.insert_one({
        "scan_id": scan_id,
        "user_id": sched["user_id"],
        "domain": result["domain"],
        "created_at": now_iso,
        "extended_ports": sched.get("extended_ports", False),
        "result": result,
        "source": "scheduled",
        "schedule_id": sched["schedule_id"],
    })

    # Automatic takeover re-check on scheduled scans
    try:
        from integrations.takeover_scanner import scan_takeovers
        subs = [s["subdomain"] for s in (result.get("subdomains") or {}).get("found", [])]
        takeover = await scan_takeovers(subs, result["domain"])
        await db.scans.update_one({"scan_id": scan_id}, {"$set": {"takeover": takeover}})
    except Exception:
        log.exception("Auto takeover recheck failed")
        takeover = None

    # Detect diff vs last scan for this schedule
    prev_scan = None
    if sched.get("last_scan_id"):
        prev_scan = await db.scans.find_one({"scan_id": sched["last_scan_id"]}, {"_id": 0})

    alerts_created = []
    if prev_scan:
        changes = _detect_changes(prev_scan["result"], result, sched.get("alert_types", []))
        for ch in changes:
            aid = f"alt_{uuid.uuid4().hex[:12]}"
            doc = {
                "alert_id": aid, "user_id": sched["user_id"],
                "schedule_id": sched["schedule_id"], "scan_id": scan_id,
                "domain": sched["domain"], "type": ch["type"], "severity": ch["severity"],
                "title": ch["title"], "detail": ch["detail"],
                "created_at": now_iso, "read": False,
            }
            await db.alerts.insert_one(doc)
            alerts_created.append(ch)

        # Diff takeover: new vulnerable subdomains vs previous scan
        prev_take = prev_scan.get("takeover") or {}
        prev_vulns = {r["subdomain"] for r in (prev_take.get("results") or []) if r.get("vulnerable")}
        curr_vulns = {r["subdomain"] for r in ((takeover or {}).get("results") or []) if r.get("vulnerable")}
        newly_vulnerable = curr_vulns - prev_vulns
        for sub in newly_vulnerable:
            details = next((r for r in takeover["results"] if r["subdomain"] == sub), {})
            aid = f"alt_{uuid.uuid4().hex[:12]}"
            ch = {
                "type": "subdomain_takeover", "severity": "critical",
                "title": f"⚠ Nuevo Subdomain Takeover: {sub} ({details.get('service', '?')})",
                "detail": {"subdomain": sub, "service": details.get("service"),
                           "evidence": details.get("evidence"), "cname_chain": details.get("cname_chain")},
            }
            await db.alerts.insert_one({
                "alert_id": aid, "user_id": sched["user_id"],
                "schedule_id": sched["schedule_id"], "scan_id": scan_id,
                "domain": sched["domain"], **ch,
                "created_at": now_iso, "read": False,
            })
            alerts_created.append(ch)

    # Deliver via Slack if configured
    if alerts_created:
        user = await db.users.find_one({"user_id": sched["user_id"]}, {"_id": 0})
        if user and user.get("slack_webhook_url"):
            await _send_slack(user["slack_webhook_url"], sched["domain"], alerts_created)
        if user:
            tg = user.get("telegram") or {}
            if tg.get("bot_token") and tg.get("chat_id"):
                await _send_telegram(tg["bot_token"], tg["chat_id"], sched["domain"], alerts_created)
            # Email via Resend
            email_cfg = user.get("email_alerts") or {}
            if email_cfg.get("enabled") and email_cfg.get("address"):
                try:
                    from emailer import send_alerts_email
                    await send_alerts_email(email_cfg["address"], sched["domain"], alerts_created)
                except Exception:
                    log.exception("email alert delivery failed")

    next_run = _next_run(sched)
    await db.schedules.update_one(
        {"schedule_id": sched["schedule_id"]},
        {"$set": {"last_run_at": now_iso, "last_scan_id": scan_id,
                  "next_run_at": next_run.isoformat()}},
    )
    log.info(f"Schedule {sched['schedule_id']} done: {len(alerts_created)} alerts")


async def scheduler_loop(db, interval_seconds: int = 60):
    log.info("Scheduler loop started")
    while True:
        try:
            await _run_due_schedules(db)
        except Exception:
            log.exception("Scheduler loop iteration failed")
        await asyncio.sleep(interval_seconds)

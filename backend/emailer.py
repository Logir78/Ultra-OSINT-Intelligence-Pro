"""Resend email delivery for security alerts, scan completion, and risk-threshold breaches.

Non-blocking wrapper around the sync Resend SDK using asyncio.to_thread.
Emails are opt-in per user (settings.email_alerts.enabled + email_alerts.address).
"""
import asyncio
import logging
import os
from typing import Optional

import resend

log = logging.getLogger("emailer")

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "onboarding@resend.dev")

if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY


def is_configured() -> bool:
    return bool(RESEND_API_KEY)


def _html_wrapper(title: str, body_html: str, cta_url: Optional[str] = None,
                   cta_label: Optional[str] = None) -> str:
    cta = ""
    if cta_url and cta_label:
        cta = (
            f'<tr><td style="padding:16px 0"><a href="{cta_url}" '
            'style="background:#00E5FF;color:#0a0a0a;padding:12px 22px;'
            'text-decoration:none;font-weight:700;border-radius:6px;'
            f'font-family:monospace;">{cta_label}</a></td></tr>'
        )
    return f"""<!doctype html>
<html><body style="margin:0;padding:0;background:#0a0a0a;font-family:-apple-system,Segoe UI,sans-serif;color:#e8e8e8;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#0a0a0a;padding:32px 0;">
  <tr><td align="center">
    <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background:#0f0f10;border:1px solid #1f2937;border-radius:10px;overflow:hidden;">
      <tr><td style="padding:20px 28px;border-bottom:1px solid #1f2937;">
        <div style="color:#00E5FF;font-family:monospace;font-size:12px;letter-spacing:2px;">NOCTUA.osint</div>
        <div style="color:#e8e8e8;font-size:22px;font-weight:700;margin-top:4px;">{title}</div>
      </td></tr>
      <tr><td style="padding:24px 28px;color:#c9c9c9;font-size:15px;line-height:1.55;">
        {body_html}
        <table>{cta}</table>
      </td></tr>
      <tr><td style="padding:16px 28px;border-top:1px solid #1f2937;color:#666;font-size:12px;font-family:monospace;">
        Este correo fue enviado por NOCTUA.osint. Puedes desactivar las notificaciones desde Ajustes → Notificaciones.
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>"""


async def send_email(to: str, subject: str, html: str) -> dict:
    """Send an email via Resend. Returns {ok, id?, error?}."""
    if not is_configured():
        return {"ok": False, "error": "RESEND_API_KEY not configured"}
    if not to or "@" not in to:
        return {"ok": False, "error": "Invalid recipient"}
    params = {
        "from": SENDER_EMAIL,
        "to": [to],
        "subject": subject,
        "html": html,
    }
    try:
        result = await asyncio.to_thread(resend.Emails.send, params)
        return {"ok": True, "id": result.get("id") if isinstance(result, dict) else None}
    except Exception as e:
        log.warning(f"Resend send failed: {e}")
        return {"ok": False, "error": str(e)}


async def send_alerts_email(to: str, domain: str, alerts: list[dict]) -> dict:
    """Format and send a batch of scan-diff alerts."""
    if not alerts:
        return {"ok": False, "error": "No alerts"}
    sev_color = {"critical": "#FF3366", "high": "#FFB000", "medium": "#00E5FF", "low": "#666"}
    rows = []
    for a in alerts[:20]:
        color = sev_color.get(a.get("severity", "low"), "#666")
        rows.append(
            f'<tr><td style="padding:8px 0;border-bottom:1px solid #1f2937;">'
            f'<span style="background:{color};color:#0a0a0a;padding:2px 8px;'
            f'border-radius:3px;font-size:11px;font-weight:700;font-family:monospace;">'
            f'{a.get("severity","LOW").upper()}</span>'
            f' <span style="color:#e8e8e8">{a.get("title","")}</span></td></tr>'
        )
    body = (
        f'<p>Se detectaron <b>{len(alerts)}</b> cambio(s) críticos en <code style="color:#00E5FF">{domain}</code>:</p>'
        f'<table width="100%" cellspacing="0" cellpadding="0">{"".join(rows)}</table>'
    )
    html = _html_wrapper(f"🚨 Cambios detectados en {domain}", body)
    return await send_email(to, f"[NOCTUA] {len(alerts)} alerta(s) en {domain}", html)


async def send_blocked_login_email(to: str, blocked_email: str, ip: str, user_agent: str) -> dict:
    body = (
        f'<p>Un intento de acceso NO autorizado fue bloqueado por el whitelist de <b>Acceso Privado</b>.</p>'
        f'<table style="background:#0a0a0a;padding:12px;border-radius:6px;font-family:monospace;font-size:13px;color:#c9c9c9;width:100%;">'
        f'<tr><td>Email:</td><td style="color:#FF3366">{blocked_email}</td></tr>'
        f'<tr><td>IP:</td><td>{ip}</td></tr>'
        f'<tr><td>User-Agent:</td><td style="word-break:break-all">{user_agent[:200]}</td></tr>'
        f'</table>'
    )
    html = _html_wrapper("🛡️ Intento de acceso bloqueado", body)
    return await send_email(to, f"[NOCTUA] Bloqueo de acceso: {blocked_email}", html)


async def send_scan_complete_email(to: str, domain: str, risk_score: Optional[int], scan_url: Optional[str] = None) -> dict:
    risk_txt = f" · Riesgo: <b>{risk_score}/100</b>" if risk_score is not None else ""
    body = (
        f'<p>Tu escaneo de <code style="color:#00E5FF">{domain}</code> ha finalizado.{risk_txt}</p>'
        f'<p>Consulta el dashboard para el informe completo.</p>'
    )
    html = _html_wrapper(f"✅ Escaneo completado · {domain}", body,
                          cta_url=scan_url, cta_label="Ver informe" if scan_url else None)
    return await send_email(to, f"[NOCTUA] Escaneo completado: {domain}", html)

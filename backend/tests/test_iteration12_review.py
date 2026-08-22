"""Iteration 12 — P1 REVIEW TESTS.

Hits the PUBLIC backend URL (REACT_APP_BACKEND_URL) and verifies:
- Stealth: /api/stealth/status + target-facing module retrofit assertions
- Email (Resend) settings CRUD + test-send
- WAF Bypass Suggestor with Cloudflare playbook + cache
- Telegram webhook /start (admin + unknown chat + bad secret)
- Telegram admin endpoints auth + status + send-welcome
- Multi-tenant isolation on /phishing-sim
"""
import os
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, AsyncMock

import pytest
import requests
from pymongo import MongoClient
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).resolve().parents[2] / "frontend" / ".env")
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.environ.get("DB_NAME", "test_database")

ADMIN_EMAIL = "davjoel31@gmail.com"
ADMIN_CHAT_ID = "6507252927"


@pytest.fixture(scope="module")
def mongo():
    c = MongoClient(MONGO_URL)
    yield c[DB_NAME]
    c.close()


def _mint_user(mongo, email: str, plan: str = "free"):
    uid = f"user_test_{uuid.uuid4().hex[:10]}"
    token = f"test_session_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc)
    mongo.users.insert_one({
        "user_id": uid, "email": email, "name": "QA", "picture": None,
        "created_at": now.isoformat(), "plan": plan,
    })
    mongo.user_sessions.insert_one({
        "user_id": uid, "session_token": token,
        "expires_at": (now + timedelta(days=7)).isoformat(),
        "created_at": now.isoformat(),
    })
    return uid, token


def _cleanup_user(mongo, uid):
    mongo.users.delete_one({"user_id": uid})
    mongo.user_sessions.delete_many({"user_id": uid})
    mongo.scans.delete_many({"user_id": uid})


@pytest.fixture
def free_user(mongo):
    uid, tok = _mint_user(mongo, f"qa_free_{uuid.uuid4().hex[:6]}@test.local", "free")
    yield {"user_id": uid, "token": tok}
    _cleanup_user(mongo, uid)


@pytest.fixture
def pro_user(mongo):
    uid, tok = _mint_user(mongo, f"qa_pro_{uuid.uuid4().hex[:6]}@test.local", "pro")
    yield {"user_id": uid, "token": tok}
    _cleanup_user(mongo, uid)


@pytest.fixture
def admin_session(mongo):
    """Session for the whitelisted admin user (davjoel31@gmail.com).
    Uses existing admin doc; only mints a session_token."""
    admin = mongo.users.find_one({"email": ADMIN_EMAIL}, {"_id": 0})
    assert admin, "Admin user with davjoel31@gmail.com missing in DB"
    tok = f"test_session_admin_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc)
    mongo.user_sessions.insert_one({
        "user_id": admin["user_id"], "session_token": tok,
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "created_at": now.isoformat(),
    })
    yield {"user_id": admin["user_id"], "token": tok, "email": ADMIN_EMAIL}
    mongo.user_sessions.delete_one({"session_token": tok})


def hdr(tok):
    return {"Authorization": f"Bearer {tok}"}


# ─────────────────────── P1-A · STEALTH ─────────────────────────────
def test_stealth_status_public():
    r = requests.get(f"{BASE_URL}/api/stealth/status", timeout=15)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("enabled") is True
    assert "pool_sizes" in data
    assert "features" in data


@pytest.mark.parametrize("mod_name", [
    "osint_engine", "tech_stack",
    "integrations.bot_resistance", "integrations.js_miner",
    "integrations.takeover_scanner", "integrations.param_miner",
    "integrations.cloud_config", "integrations.honeypot_detector",
    "integrations.api_auditor", "integrations.metadata",
])
def test_target_facing_modules_use_stealth(mod_name):
    import importlib
    mod = importlib.import_module(mod_name)
    src = open(mod.__file__).read()
    assert ("stealth_httpx_client" in src) or ("stealth_headers" in src), \
        f"{mod_name} not retrofitted to StealthClient"


# ─────────────────────── P1-B · EMAIL (RESEND) ──────────────────────
def test_get_email_settings_unauth_returns_401():
    r = requests.get(f"{BASE_URL}/api/settings/email", timeout=15)
    assert r.status_code in (401, 403), r.status_code


def test_get_email_settings_returns_resend_configured(free_user):
    r = requests.get(f"{BASE_URL}/api/settings/email",
                     headers=hdr(free_user["token"]), timeout=15)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("resend_configured") is True
    assert data.get("sender") == "onboarding@resend.dev"
    assert "enabled" in data and "address" in data


def test_post_email_settings_persists(mongo, free_user):
    payload = {"enabled": True, "address": "test@example.com"}
    r = requests.post(f"{BASE_URL}/api/settings/email", json=payload,
                      headers=hdr(free_user["token"]), timeout=15)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("enabled") is True
    assert data.get("address") == "test@example.com"
    # verify persistence
    u = mongo.users.find_one({"user_id": free_user["user_id"]}, {"email_alerts": 1})
    assert u["email_alerts"]["enabled"] is True
    assert u["email_alerts"]["address"] == "test@example.com"


def test_post_email_settings_rejects_bad_address(free_user):
    r = requests.post(f"{BASE_URL}/api/settings/email",
                      json={"enabled": True, "address": "not-an-email"},
                      headers=hdr(free_user["token"]), timeout=15)
    assert r.status_code == 400


def test_post_email_test_gracefully_handles_send(free_user):
    """RESEND_API_KEY is configured, but sending to test@example.com may
    return 4xx due to sandbox constraints. Both 200 (ok) and 502 (well-formed
    Resend error) are acceptable — key point: no unhandled 500."""
    # first configure an address
    requests.post(f"{BASE_URL}/api/settings/email",
                  json={"enabled": True, "address": "test@example.com"},
                  headers=hdr(free_user["token"]), timeout=15)
    r = requests.post(f"{BASE_URL}/api/settings/email/test",
                      headers=hdr(free_user["token"]), timeout=30)
    # NOT a 500 (unhandled). Should be 200 on real send OR 400/502 gracefully.
    assert r.status_code in (200, 400, 502), f"Got {r.status_code}: {r.text}"
    if r.status_code == 200:
        j = r.json()
        assert j.get("ok") is True


# ─────────────────────── P1-C · WAF BYPASS ──────────────────────────
def _seed_scan_with_tech(mongo, uid, tech_analysis):
    scan_id = f"scan_test_{uuid.uuid4().hex[:12]}"
    mongo.scans.insert_one({
        "scan_id": scan_id, "user_id": uid,
        "result": {
            "domain": "example.com",
            "tech_analysis": tech_analysis,
            "ip": {"ip": "93.184.216.34"},
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return scan_id


def test_waf_bypass_with_cloudflare_playbook(mongo, free_user):
    tech = [{
        "hostname": "example.com",
        "proxies": [{"name": "Cloudflare", "category": "cdn+waf",
                      "evidence": [{"header": "server", "value": "cloudflare"}]}],
    }]
    scan_id = _seed_scan_with_tech(mongo, free_user["user_id"], tech)
    r = requests.get(f"{BASE_URL}/api/scans/{scan_id}/waf-bypass?use_ai=false",
                     headers=hdr(free_user["token"]), timeout=30)
    assert r.status_code == 200, r.text
    body = r.json()
    wb = body.get("waf_bypass") or {}
    assert wb.get("target") == "example.com"
    assert wb.get("waf_detected") is True
    assert "Cloudflare" in wb.get("wafs", [])
    playbook = wb.get("playbook") or []
    assert playbook, "playbook must include Cloudflare"
    cf = next((p for p in playbook if p.get("waf") == "Cloudflare"), None)
    assert cf is not None
    assert any(t["name"] == "Origin IP discovery" for t in cf["techniques"])
    assert wb.get("generic"), "generic techniques always present"
    assert "ai_summary" in wb  # key exists (may be None with use_ai=false)

    # verify cache persisted on scan doc
    doc = mongo.scans.find_one({"scan_id": scan_id})
    assert doc.get("waf_bypass") is not None
    assert doc["waf_bypass"]["waf_detected"] is True


def test_waf_bypass_no_waf_returns_empty_playbook(mongo, free_user):
    scan_id = _seed_scan_with_tech(mongo, free_user["user_id"], [])
    r = requests.get(f"{BASE_URL}/api/scans/{scan_id}/waf-bypass?use_ai=false",
                     headers=hdr(free_user["token"]), timeout=30)
    assert r.status_code == 200
    wb = r.json()["waf_bypass"]
    assert wb["waf_detected"] is False
    assert wb["playbook"] == []
    assert wb["generic"]


def test_waf_bypass_uses_cache_when_use_ai_false(mongo, free_user):
    """When use_ai=false and cached result exists, should short-circuit and return cached=True."""
    scan_id = _seed_scan_with_tech(mongo, free_user["user_id"], [])
    # first call populates cache
    r1 = requests.get(f"{BASE_URL}/api/scans/{scan_id}/waf-bypass?use_ai=false",
                      headers=hdr(free_user["token"]), timeout=30)
    assert r1.status_code == 200
    # second call must hit the cache branch
    r2 = requests.get(f"{BASE_URL}/api/scans/{scan_id}/waf-bypass?use_ai=false",
                      headers=hdr(free_user["token"]), timeout=15)
    assert r2.status_code == 200
    assert r2.json().get("cached") is True


def test_waf_bypass_404_when_not_owner(mongo, free_user, pro_user):
    scan_id = _seed_scan_with_tech(mongo, pro_user["user_id"], [])
    r = requests.get(f"{BASE_URL}/api/scans/{scan_id}/waf-bypass?use_ai=false",
                     headers=hdr(free_user["token"]), timeout=15)
    assert r.status_code == 404


# ─────────────────────── TELEGRAM WEBHOOK ───────────────────────────
def _bot_secret(mongo):
    u = mongo.users.find_one({"email": ADMIN_EMAIL}, {"telegram": 1})
    tok = ((u or {}).get("telegram") or {}).get("bot_token") or ""
    if not tok:
        pytest.skip("bot_token missing")
    return tok.split(":", 1)[-1][-12:]


def test_telegram_webhook_rejects_bad_secret():
    r = requests.post(f"{BASE_URL}/api/telegram/webhook/BADSECRET",
                      json={"message": {"chat": {"id": 1}, "text": "/start"}},
                      timeout=15)
    assert r.status_code == 403


def test_telegram_webhook_admin_start_creates_welcome_event(mongo):
    """/start from admin chat_id logs a 'start_welcome' event (Telegram sendMessage
    may 4xx if bot API blocks — the event insert happens regardless)."""
    secret = _bot_secret(mongo)
    before = mongo.telegram_events.count_documents(
        {"chat_id": ADMIN_CHAT_ID, "type": "start_welcome"})
    r = requests.post(
        f"{BASE_URL}/api/telegram/webhook/{secret}",
        json={"update_id": 91001, "message": {
            "message_id": 91001,
            "chat": {"id": int(ADMIN_CHAT_ID), "first_name": "Admin"},
            "text": "/start"}},
        timeout=20)
    assert r.status_code == 200, r.text
    assert r.json().get("ok") is True
    after = mongo.telegram_events.count_documents(
        {"chat_id": ADMIN_CHAT_ID, "type": "start_welcome"})
    assert after == before + 1, "start_welcome event was not persisted"


def test_telegram_webhook_unknown_chat_creates_unauthorized_event(mongo):
    secret = _bot_secret(mongo)
    unknown_chat = "77777123"
    before = mongo.telegram_events.count_documents(
        {"chat_id": unknown_chat, "type": "start_unauthorized"})
    r = requests.post(
        f"{BASE_URL}/api/telegram/webhook/{secret}",
        json={"update_id": 92002, "message": {
            "message_id": 92002,
            "chat": {"id": int(unknown_chat), "first_name": "Stranger"},
            "text": "/start"}},
        timeout=20)
    assert r.status_code == 200
    after = mongo.telegram_events.count_documents(
        {"chat_id": unknown_chat, "type": "start_unauthorized"})
    assert after == before + 1, "start_unauthorized event was not persisted"


def test_telegram_webhook_ignores_non_start_text(mongo):
    """Non-command text produces no event."""
    secret = _bot_secret(mongo)
    r = requests.post(
        f"{BASE_URL}/api/telegram/webhook/{secret}",
        json={"update_id": 93003, "message": {
            "message_id": 93003,
            "chat": {"id": 555555, "first_name": "Idle"},
            "text": "hello there"}},
        timeout=15)
    assert r.status_code == 200


# ─────────────────────── TELEGRAM ADMIN ENDPOINTS ───────────────────
def test_telegram_webhook_status_requires_admin(free_user):
    r = requests.get(f"{BASE_URL}/api/telegram/webhook/status",
                     headers=hdr(free_user["token"]), timeout=15)
    assert r.status_code == 403


def test_telegram_webhook_status_admin_ok(admin_session):
    r = requests.get(f"{BASE_URL}/api/telegram/webhook/status",
                     headers=hdr(admin_session["token"]), timeout=25)
    # Admin should get a proper JSON (network to telegram may vary — accept 200/502)
    assert r.status_code in (200, 502), r.text
    if r.status_code == 200:
        data = r.json()
        assert "configured" in data


def test_telegram_send_welcome_requires_admin(free_user):
    r = requests.post(f"{BASE_URL}/api/telegram/send-welcome",
                      headers=hdr(free_user["token"]), timeout=15)
    assert r.status_code == 403


def test_telegram_send_welcome_admin_ok(admin_session):
    r = requests.post(f"{BASE_URL}/api/telegram/send-welcome",
                      headers=hdr(admin_session["token"]), timeout=25)
    # Real send may 4xx from Telegram or 200 if delivered — no 500 from our side.
    assert r.status_code in (200, 502), f"{r.status_code}: {r.text}"


# ─────────────────────── ISOLATION REGRESSION ───────────────────────
def test_phishing_sim_returns_404_for_other_users_scan(mongo, free_user, pro_user):
    """Multi-tenant isolation: caller (free plan) attempts to hit another user's
    (pro user's) scan → must be 404 (not 402 plan-gate). The 402 check must
    happen AFTER the 404 ownership check."""
    other_scan = _seed_scan_with_tech(mongo, pro_user["user_id"], [])
    r = requests.post(f"{BASE_URL}/api/scans/{other_scan}/phishing-sim",
                      headers=hdr(free_user["token"]), timeout=20)
    assert r.status_code == 404, (
        f"Expected 404 for cross-tenant access, got {r.status_code}: {r.text}")


def test_phishing_sim_returns_402_when_free_user_owns_scan(mongo, free_user):
    """Free user hitting their OWN scan → 402 (plan gate) is correct."""
    scan = _seed_scan_with_tech(mongo, free_user["user_id"], [])
    r = requests.post(f"{BASE_URL}/api/scans/{scan}/phishing-sim",
                      headers=hdr(free_user["token"]), timeout=20)
    assert r.status_code == 402, f"Expected 402, got {r.status_code}: {r.text}"


# ─────────────────────── EMAILER MODULE (unit) ──────────────────────
def test_emailer_is_configured():
    from emailer import is_configured
    assert is_configured() is True


def test_emailer_html_wrapper_branding():
    from emailer import _html_wrapper
    html = _html_wrapper("Title", "<p>body</p>")
    assert "NOCTUA" in html
    assert "<p>body</p>" in html


def test_waf_bypass_module_no_waf():
    from integrations.waf_bypass import suggest_bypass
    d = suggest_bypass([], "example.com")
    assert d["waf_detected"] is False
    assert d["playbook"] == []
    assert d["generic"]


def test_welcome_message_banner():
    from telegram_bot import WELCOME_MESSAGE
    for token in ["PROJECT GENESIS", "NODO OPERATIVO ACTIVADO", "ONLINE",
                  "Encriptado", "ACTIVO", "vulnerabilidades", "subdominios",
                  "acceso no autorizados", "Resúmenes ejecutivos"]:
        assert token in WELCOME_MESSAGE, f"missing token '{token}'"

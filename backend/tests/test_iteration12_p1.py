"""Iteration 12 — P1 features:
- Stealth retrofit: verifies key target-facing modules use rotating User-Agents.
- Emailer (Resend): factory + fallback when RESEND_API_KEY missing.
- WAF Bypass Suggestor: playbook generation.
- Telegram Bot webhook: /start welcome, chat_id hint, secret enforcement.
"""
import os
from unittest.mock import patch, AsyncMock

import pytest
import requests
from pymongo import MongoClient

BASE_URL = "http://localhost:8001"


# ─────────────────────── STEALTH RETROFIT ─────────────────────────────
def test_stealth_headers_are_deterministic_per_target():
    from integrations.stealth import stealth_headers
    h1 = stealth_headers("example.com")
    h2 = stealth_headers("example.com")
    h3 = stealth_headers("other.com")
    assert h1 == h2, "Same target must yield same headers (deterministic session)"
    assert h1["User-Agent"] != h3["User-Agent"] or h1["Accept-Language"] != h3["Accept-Language"], \
        "Different targets should get different fingerprints"


def test_stealth_httpx_client_returns_configured_client():
    import asyncio
    from integrations.stealth import stealth_httpx_client
    import httpx

    async def _run():
        async with stealth_httpx_client("example.com") as c:
            assert isinstance(c, httpx.AsyncClient)
            assert "User-Agent" in c.headers
            ua = c.headers["User-Agent"]
            assert any(t in ua for t in ("Mozilla", "Firefox", "Safari", "Chrome"))

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_run())
    finally:
        loop.close()


def test_target_facing_modules_import_stealth_client():
    """Ensure retrofit was applied — critical modules must import stealth_httpx_client."""
    modules_to_check = [
        "osint_engine", "tech_stack",
        "integrations.bot_resistance", "integrations.js_miner",
        "integrations.takeover_scanner", "integrations.param_miner",
        "integrations.cloud_config", "integrations.honeypot_detector",
        "integrations.api_auditor", "integrations.metadata",
    ]
    for name in modules_to_check:
        import importlib
        mod = importlib.import_module(name)
        src = open(mod.__file__).read()
        assert "stealth_httpx_client" in src or "stealth_headers" in src, \
            f"Module {name} was not retrofitted to use StealthClient"


# ────────────────────────── EMAIL (RESEND) ─────────────────────────────
def test_emailer_is_configured_when_key_present():
    from emailer import is_configured
    # In this environment RESEND_API_KEY is set
    assert is_configured() is True, "RESEND_API_KEY should be present in .env"


def test_emailer_gracefully_fails_on_bad_recipient():
    import asyncio
    from emailer import send_email
    loop = asyncio.new_event_loop()
    try:
        r = loop.run_until_complete(send_email("", "s", "<p>t</p>"))
        assert r["ok"] is False and "recipient" in r["error"].lower()
    finally:
        loop.close()


def test_emailer_html_wrapper_includes_branding():
    from emailer import _html_wrapper
    html = _html_wrapper("Title", "<p>body</p>")
    assert "NOCTUA" in html
    assert "<p>body</p>" in html
    assert "0a0a0a" in html.lower()  # dark bg


# ────────────────────────── WAF BYPASS SUGGESTOR ────────────────────────
def test_waf_bypass_produces_playbook_for_cloudflare():
    from integrations.waf_bypass import suggest_bypass
    tech = [{
        "hostname": "example.com",
        "proxies": [{"name": "Cloudflare", "category": "cdn+waf",
                      "evidence": [{"header": "server", "value": "cloudflare"}]}],
    }]
    data = suggest_bypass(tech, "example.com")
    assert data["waf_detected"] is True
    assert "Cloudflare" in data["wafs"]
    assert data["playbook"], "Playbook should contain Cloudflare tactics"
    assert any(t["name"] == "Origin IP discovery"
                for t in data["playbook"][0]["techniques"])
    assert data["generic"], "Generic techniques should always be provided"


def test_waf_bypass_gracefully_handles_no_waf():
    from integrations.waf_bypass import suggest_bypass
    data = suggest_bypass([], "example.com")
    assert data["waf_detected"] is False
    assert data["playbook"] == []
    assert data["generic"], "Generic techniques still provided"


# ────────────────────────── TELEGRAM BOT WEBHOOK ────────────────────────
class TestTelegramBot:

    @pytest.fixture
    def mongo(self):
        m = MongoClient("mongodb://localhost:27017")
        yield m[os.environ.get("DB_NAME", "test_database")]
        m.close()

    @pytest.fixture
    def bot_secret(self, mongo):
        # secret = last 12 chars of admin bot_token
        u = mongo.users.find_one({"email": "davjoel31@gmail.com"}, {"telegram": 1})
        token = ((u or {}).get("telegram") or {}).get("bot_token") or ""
        if not token:
            pytest.skip("Admin bot_token not configured")
        return token.split(":", 1)[-1][-12:]

    def test_webhook_rejects_bad_secret(self):
        r = requests.post(f"{BASE_URL}/api/telegram/webhook/BADSECRET",
                          json={"message": {"chat": {"id": 1}, "text": "/start"}})
        assert r.status_code == 403

    def test_webhook_accepts_valid_secret(self, bot_secret):
        with patch("telegram_bot.send_message", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = {"ok": True}
            r = requests.post(f"{BASE_URL}/api/telegram/webhook/{bot_secret}",
                              json={"update_id": 999, "message": {
                                  "message_id": 999,
                                  "chat": {"id": 12345, "first_name": "Test"},
                                  "text": "/start"}})
            assert r.status_code == 200

    def test_webhook_logs_start_events(self, mongo, bot_secret):
        before = mongo.telegram_events.count_documents({"chat_id": "888888"})
        requests.post(f"{BASE_URL}/api/telegram/webhook/{bot_secret}",
                       json={"update_id": 1000, "message": {
                           "message_id": 1000,
                           "chat": {"id": 888888, "first_name": "Auditor"},
                           "text": "/start"}})
        after = mongo.telegram_events.count_documents({"chat_id": "888888"})
        assert after == before + 1
        ev = mongo.telegram_events.find_one({"chat_id": "888888"},
                                             sort=[("at", -1)])
        assert ev["type"] in ("start_unauthorized", "start_welcome")

    def test_welcome_message_contains_required_banner(self):
        from telegram_bot import WELCOME_MESSAGE
        for token in ["PROJECT GENESIS", "NODO OPERATIVO ACTIVADO",
                      "ONLINE", "Encriptado", "ACTIVO",
                      "vulnerabilidades", "subdominios", "acceso no autorizados",
                      "Resúmenes ejecutivos"]:
            assert token in WELCOME_MESSAGE, f"Welcome message missing '{token}'"

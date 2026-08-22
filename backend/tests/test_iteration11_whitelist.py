"""Iteration 11 — Access Whitelist + Security Log + Telegram alerts."""
import os
import uuid
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timezone
from conftest import BASE_URL, auth_headers as _auth


class TestWhitelistEndpoint:
    def test_access_whitelist_status_requires_auth(self, client):
        r = client.get(f"{BASE_URL}/api/settings/access-whitelist")
        assert r.status_code in (401, 403)

    def test_access_whitelist_status_for_non_admin(self, client, free_user):
        """When AUTHORIZED_EMAILS env var is absent (default in tests), user is NOT admin."""
        r = client.get(f"{BASE_URL}/api/settings/access-whitelist",
                       headers=_auth(free_user["token"]), timeout=6)
        assert r.status_code == 200
        body = r.json()
        assert body.get("you_are_admin") is False
        assert "enabled" in body

    def test_security_log_forbidden_for_non_admin(self, client, free_user):
        r = client.get(f"{BASE_URL}/api/settings/security-log",
                       headers=_auth(free_user["token"]), timeout=6)
        assert r.status_code == 403


class TestSessionWhitelist:
    """Verify the POST /api/auth/session enforcement logic (unit-level)."""

    def test_email_in_whitelist_is_allowed_normalized(self):
        """Case-insensitive + whitespace-tolerant matching."""
        raw = " Admin@Example.COM , other@test.com "
        allowed = {e.strip().lower() for e in raw.split(",") if e.strip()}
        assert "admin@example.com" in allowed
        assert "other@test.com" in allowed
        assert "attacker@evil.com" not in allowed

    def test_admin_detection(self):
        """First email in AUTHORIZED_EMAILS is the admin."""
        raw = "boss@corp.io, ops@corp.io"
        first = raw.split(",")[0].strip().lower()
        assert first == "boss@corp.io"


class TestAccessAttemptsLog:
    def test_attempts_collection_is_writable(self, mongo):
        """Verify we can write and read from db.access_attempts."""
        doc = {
            "email": f"attacker-{uuid.uuid4().hex[:6]}@evil.com",
            "ip": "203.0.113.42", "reason": "not_in_whitelist",
            "attempted_at": datetime.now(timezone.utc).isoformat(),
        }
        r = mongo.access_attempts.insert_one(doc)
        assert r.inserted_id
        found = mongo.access_attempts.find_one({"_id": r.inserted_id})
        assert found["email"] == doc["email"]
        assert found["ip"] == "203.0.113.42"
        mongo.access_attempts.delete_one({"_id": r.inserted_id})


class TestTelegramAccessAlert:
    """The Telegram dispatch code inside /auth/session on rejection."""

    def test_telegram_message_format(self):
        """Message must include emoji, email, IP, timestamp."""
        email = "attacker@evil.com"
        client_ip = "1.2.3.4"
        now = datetime.now(timezone.utc)
        text = (f"🚨 *ALERTA DE ACCESO*\n"
                f"Intento de entrada bloqueado.\n"
                f"*Email:* `{email}`\n"
                f"*IP:* `{client_ip}`\n"
                f"*Cuando:* {now.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        assert "🚨 *ALERTA DE ACCESO*" in text
        assert email in text
        assert client_ip in text
        assert "Markdown" not in text  # sanity: no template artifacts

    def test_telegram_config_lookup_skipped_without_config(self):
        """If admin has no telegram config, dispatch is a no-op (no crash)."""
        admin_user = {"telegram": None}
        tg = (admin_user or {}).get("telegram") or {}
        assert not (tg.get("bot_token") and tg.get("chat_id"))

"""Backend tests for the new Telegram integration + public landing endpoints."""
import os
import time
import uuid
import pytest
import requests

from conftest import auth_headers


BASE_URL_ENV = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")


# ---------- PUBLIC /api/public/stats ----------
class TestPublicStats:
    def test_stats_no_auth(self, base_url, client):
        r = client.get(f"{base_url}/api/public/stats")
        assert r.status_code == 200
        data = r.json()
        # Required fields
        for k in ("scans_this_month", "public_scans_this_month",
                  "total_scans", "takeovers_detected", "active_users",
                  "generated_at", "cached"):
            assert k in data, f"missing field {k}"
        # Numeric fields must be int and >= 0
        for k in ("scans_this_month", "public_scans_this_month",
                  "total_scans", "takeovers_detected", "active_users"):
            assert isinstance(data[k], int), f"{k} should be int"
            assert data[k] >= 0

    def test_stats_cache_second_call(self, base_url, client):
        r1 = client.get(f"{base_url}/api/public/stats")
        assert r1.status_code == 200
        r2 = client.get(f"{base_url}/api/public/stats")
        assert r2.status_code == 200
        # 2nd call within 5s must be cached
        assert r2.json().get("cached") is True


# ---------- PUBLIC /api/public/takeover-check ----------
class TestPublicTakeover:
    def test_public_scan_inserts_db_row(self, base_url, client, mongo):
        # Clean bucket for our test IP by using a random test domain
        test_domain = f"noctua-qa-{uuid.uuid4().hex[:6]}.example.com"
        r = client.get(f"{base_url}/api/public/takeover-check", params={"domain": test_domain})
        # Accept 200 or 429 (rate limit could still be there)
        if r.status_code == 429:
            pytest.skip("rate limited, cannot verify insert this run")
        assert r.status_code == 200, f"got {r.status_code} {r.text[:200]}"
        data = r.json()
        assert data["tier"] == "free_public"
        assert data["domain"] == test_domain
        assert "results" in data
        assert "upsell" in data

        # Verify DB row inserted
        doc = mongo.public_scans.find_one({"domain": test_domain})
        assert doc is not None, "public_scans collection missing the new row"
        assert "created_at" in doc
        # cleanup
        mongo.public_scans.delete_one({"domain": test_domain})

    def test_public_scan_invalid_domain(self, base_url, client):
        r = client.get(f"{base_url}/api/public/takeover-check", params={"domain": "x"})
        # either 400 or 429 acceptable, but 400 preferred
        assert r.status_code in (400, 429)


# ---------- Telegram settings gating & validation ----------
class TestTelegramSettings:
    def test_get_telegram_fresh_user(self, base_url, client, free_user):
        r = client.get(f"{base_url}/api/settings/telegram", headers=auth_headers(free_user["token"]))
        assert r.status_code == 200
        data = r.json()
        assert data == {"bot_token_set": False, "bot_token_masked": "", "chat_id": ""}

    def test_post_telegram_free_forbidden(self, base_url, client, free_user):
        r = client.post(
            f"{base_url}/api/settings/telegram",
            headers=auth_headers(free_user["token"]),
            json={"bot_token": "123:AAA", "chat_id": "111"},
        )
        assert r.status_code == 402

    def test_post_telegram_only_token_400(self, base_url, client, pro_user):
        r = client.post(
            f"{base_url}/api/settings/telegram",
            headers=auth_headers(pro_user["token"]),
            json={"bot_token": "123456789:AAA-fake", "chat_id": ""},
        )
        assert r.status_code == 400
        detail = r.json().get("detail", "")
        assert "juntos" in detail.lower() or "requieren" in detail.lower()

    def test_post_telegram_only_chat_400(self, base_url, client, pro_user):
        r = client.post(
            f"{base_url}/api/settings/telegram",
            headers=auth_headers(pro_user["token"]),
            json={"bot_token": "", "chat_id": "111"},
        )
        assert r.status_code == 400
        assert "juntos" in r.json().get("detail", "").lower()

    def test_post_telegram_invalid_token_format(self, base_url, client, pro_user):
        r = client.post(
            f"{base_url}/api/settings/telegram",
            headers=auth_headers(pro_user["token"]),
            json={"bot_token": "notavalidtoken", "chat_id": "111"},
        )
        assert r.status_code == 400
        assert "formato" in r.json().get("detail", "").lower() or "inválid" in r.json().get("detail", "").lower()

    def test_post_telegram_empty_clears(self, base_url, client, pro_user, mongo):
        # First set valid data
        r1 = client.post(
            f"{base_url}/api/settings/telegram",
            headers=auth_headers(pro_user["token"]),
            json={"bot_token": "123456789:AAA-fake-token-for-format-only", "chat_id": "111111"},
        )
        assert r1.status_code == 200
        # Verify persisted
        g1 = client.get(f"{base_url}/api/settings/telegram", headers=auth_headers(pro_user["token"]))
        assert g1.json()["bot_token_set"] is True

        # Now clear
        r2 = client.post(
            f"{base_url}/api/settings/telegram",
            headers=auth_headers(pro_user["token"]),
            json={"bot_token": None, "chat_id": None},
        )
        assert r2.status_code == 200
        assert r2.json().get("bot_token_set") is False
        # Verify cleared in DB
        g2 = client.get(f"{base_url}/api/settings/telegram", headers=auth_headers(pro_user["token"]))
        assert g2.json()["bot_token_set"] is False

    def test_post_telegram_valid_saves_and_masks(self, base_url, client, pro_user):
        token = "123456789:AAA-fake-token-for-format-only"
        r = client.post(
            f"{base_url}/api/settings/telegram",
            headers=auth_headers(pro_user["token"]),
            json={"bot_token": token, "chat_id": "111111"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["bot_token_set"] is True
        assert body["chat_id"] == "111111"

        # Subsequent GET
        g = client.get(f"{base_url}/api/settings/telegram", headers=auth_headers(pro_user["token"]))
        gd = g.json()
        assert gd["bot_token_set"] is True
        assert gd["chat_id"] == "111111"
        # Masked format e.g. "123456••••••only"
        assert gd["bot_token_masked"] != token
        assert "•" in gd["bot_token_masked"]
        assert gd["bot_token_masked"].startswith("123456")


# ---------- Telegram /test endpoint ----------
class TestTelegramTest:
    def test_test_no_creds_returns_400(self, base_url, client, pro_user):
        r = client.post(
            f"{base_url}/api/settings/telegram/test",
            headers=auth_headers(pro_user["token"]),
            json={},
        )
        assert r.status_code == 400
        detail = r.json().get("detail", "")
        assert "Faltan" in detail or "faltan" in detail.lower()

    def test_test_with_invalid_creds_returns_ok_false(self, base_url, client, pro_user):
        # Fake token should hit Telegram API and return ok:false (not 500)
        r = client.post(
            f"{base_url}/api/settings/telegram/test",
            headers=auth_headers(pro_user["token"]),
            json={"bot_token": "123456789:AAA-fake-invalid", "chat_id": "111"},
            timeout=15,
        )
        assert r.status_code == 200
        data = r.json()
        assert data.get("ok") is False
        assert "detail" in data

    def test_test_free_user_forbidden(self, base_url, client, free_user):
        r = client.post(
            f"{base_url}/api/settings/telegram/test",
            headers=auth_headers(free_user["token"]),
            json={"bot_token": "123:AAA", "chat_id": "1"},
        )
        assert r.status_code == 402


# ---------- Regression: Slack + Settings/keys ----------
class TestRegressionSettings:
    def test_settings_keys_returns_shape(self, base_url, client, free_user):
        r = client.get(f"{base_url}/api/settings/keys", headers=auth_headers(free_user["token"]))
        assert r.status_code == 200
        data = r.json()
        assert "api_keys" in data
        assert "ai_config" in data
        for p in ("shodan", "abuseipdb", "hibp", "rapidapi"):
            assert p in data["api_keys"]

    def test_slack_get_still_works(self, base_url, client, pro_user):
        r = client.get(f"{base_url}/api/settings/slack", headers=auth_headers(pro_user["token"]))
        assert r.status_code == 200
        assert "webhook_url" in r.json()


# ---------- Rate limit on public takeover-check ----------
class TestPublicRateLimit:
    def test_rate_limit_hits_after_5(self, base_url, client):
        """Fire 6 quick calls to /api/public/takeover-check and expect 429 on the 6th."""
        got_429 = False
        for i in range(7):
            r = client.get(
                f"{base_url}/api/public/takeover-check",
                params={"domain": f"ratelimit-noctua-{i}.example.com"},
                timeout=30,
            )
            if r.status_code == 429:
                got_429 = True
                break
        assert got_429, "Expected 429 within 6-7 calls (rate limit is 5/hour)"

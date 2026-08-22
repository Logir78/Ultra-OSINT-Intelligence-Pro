"""Iteration 14 — Claude AI Models integration.

Verifies:
- CLAUDE_TIERS map is correct (Haiku 4.5, Sonnet 4.6, Opus 4.8)
- resolve_claude_model() honors overrides and user preferences
- GET/POST /api/settings/claude endpoints work + persist to user prefs
- Invalid tier returns 400
- intel.generate_intel_summary accepts claude_tier arg
- WAF bypass uses Claude Sonnet 4.6 (not gpt-4o-mini)
"""
import os
import time
from datetime import datetime, timezone, timedelta

import pytest
import requests
from pymongo import MongoClient

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL_TEST") or "http://localhost:8001"


@pytest.fixture
def mongo():
    m = MongoClient("mongodb://localhost:27017")
    yield m[os.environ.get("DB_NAME", "test_database")]
    m.close()


@pytest.fixture
def admin_session(mongo):
    """Mint a fresh admin session (bypass whitelist via davjoel31@gmail.com email)."""
    uid = f"user_qa_claude_{int(time.time()*1000)}"
    token = f"tok_qa_claude_{int(time.time()*1000)}"
    mongo.users.insert_one({
        "user_id": uid, "email": "davjoel31@gmail.com",
        "name": "QA", "picture": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    mongo.user_sessions.insert_one({
        "user_id": uid, "session_token": token,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    yield {"user_id": uid, "token": token}
    mongo.users.delete_one({"user_id": uid})
    mongo.user_sessions.delete_one({"user_id": uid})


class TestClaudeModelsModule:
    def test_tiers_map_current_models(self):
        from claude_models import CLAUDE_TIERS
        assert CLAUDE_TIERS["fast"] == "claude-haiku-4-5-20251001"
        assert CLAUDE_TIERS["balanced"] == "claude-sonnet-4-6"
        assert CLAUDE_TIERS["deep"] == "claude-opus-4-8"

    def test_resolve_default(self):
        from claude_models import resolve_claude_model
        assert resolve_claude_model() == "claude-sonnet-4-6"

    def test_resolve_override_wins(self):
        from claude_models import resolve_claude_model
        assert resolve_claude_model(tier_override="deep") == "claude-opus-4-8"

    def test_resolve_from_user_prefs(self):
        from claude_models import resolve_claude_model
        u = {"preferences": {"claude_tier": "fast"}}
        assert resolve_claude_model(user=u) == "claude-haiku-4-5-20251001"

    def test_resolve_invalid_tier_falls_back_to_default(self):
        from claude_models import resolve_claude_model
        assert resolve_claude_model(tier_override="unknown") == "claude-sonnet-4-6"

    def test_meta_has_all_three_tiers(self):
        from claude_models import CLAUDE_TIER_META
        ids = {t["id"] for t in CLAUDE_TIER_META}
        assert ids == {"fast", "balanced", "deep"}
        for t in CLAUDE_TIER_META:
            assert t["model"] and t["label"] and t["desc"]


class TestClaudeAPIEndpoints:
    def test_get_claude_returns_default_and_tiers(self, admin_session):
        h = {"Authorization": f"Bearer {admin_session['token']}"}
        r = requests.get(f"{BASE_URL}/api/settings/claude", headers=h, timeout=8)
        assert r.status_code == 200
        d = r.json()
        assert d["active"] == "balanced"
        assert d["default"] == "balanced"
        assert len(d["tiers"]) == 3
        assert {t["id"] for t in d["tiers"]} == {"fast", "balanced", "deep"}

    def test_set_claude_persists(self, admin_session, mongo):
        h = {"Authorization": f"Bearer {admin_session['token']}"}
        r = requests.post(f"{BASE_URL}/api/settings/claude",
                          headers=h, json={"tier": "deep"}, timeout=8)
        assert r.status_code == 200
        assert r.json()["active"] == "deep"
        assert r.json()["model"] == "claude-opus-4-8"
        # Verify persisted
        u = mongo.users.find_one({"user_id": admin_session["user_id"]},
                                   {"preferences": 1})
        assert u["preferences"]["claude_tier"] == "deep"

    def test_set_claude_invalid_returns_400(self, admin_session):
        h = {"Authorization": f"Bearer {admin_session['token']}"}
        r = requests.post(f"{BASE_URL}/api/settings/claude",
                          headers=h, json={"tier": "NOT_A_TIER"}, timeout=8)
        assert r.status_code == 400
        assert "inválido" in r.json()["detail"].lower() or "invalid" in r.json()["detail"].lower()

    def test_set_claude_requires_auth(self):
        r = requests.post(f"{BASE_URL}/api/settings/claude",
                          json={"tier": "fast"}, timeout=8)
        assert r.status_code in (401, 403)


class TestIntelHonorsTier:
    def test_intel_signature_accepts_claude_tier(self):
        import inspect
        from intel import generate_intel_summary
        sig = inspect.signature(generate_intel_summary)
        assert "claude_tier" in sig.parameters, \
            "generate_intel_summary must accept claude_tier keyword arg"


class TestWafBypassUsesClaude:
    def test_waf_bypass_imports_claude_tiers(self):
        src = open("/app/backend/integrations/waf_bypass.py").read()
        assert "claude_models" in src
        assert 'CLAUDE_TIERS["balanced"]' in src


class TestUserSettingsUpgradedModel:
    def test_anthropic_ping_uses_haiku_4_5(self):
        """User-provided Anthropic key validation should probe Haiku 4.5 (fast + cheap)."""
        src = open("/app/backend/user_settings.py").read()
        assert "claude-haiku-4-5-20251001" in src
        # legacy model should be gone
        assert "claude-3-5-haiku-20241022" not in src

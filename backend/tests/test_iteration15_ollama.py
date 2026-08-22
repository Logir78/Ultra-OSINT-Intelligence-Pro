"""Iteration 15 — Ollama AI provider integration.

Verifies:
- 'ollama' is a valid AI_PROVIDERS choice
- get_ai_config() returns ollama_url + ollama_model when configured
- POST /api/settings/ai with provider=ollama validates URL + model
- POST /api/settings/ai rejects bad URL / missing model
- test_ai_provider('ollama', url) probes /api/tags and returns model list
- intel.generate_intel_summary accepts ollama_url + ollama_model
- Emergent Google Auth: comment reminder present in Login.jsx and AuthCallback.jsx (playbook compliance)
"""
import os
import time
from datetime import datetime, timezone, timedelta

import pytest
import requests
from pymongo import MongoClient

BASE_URL = "http://localhost:8001"


@pytest.fixture
def mongo():
    m = MongoClient("mongodb://localhost:27017")
    yield m[os.environ.get("DB_NAME", "test_database")]
    m.close()


@pytest.fixture
def admin_session(mongo):
    uid = f"user_qa_ollama_{int(time.time()*1000)}"
    token = f"tok_qa_ollama_{int(time.time()*1000)}"
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


class TestOllamaConfig:
    def test_ollama_in_ai_providers(self):
        from user_settings import AI_PROVIDERS
        assert "ollama" in AI_PROVIDERS

    def test_get_ai_config_returns_ollama_fields(self):
        from user_settings import get_ai_config
        user = {"ai_config": {"provider": "ollama",
                                "ollama_url": "https://x.ngrok.app",
                                "ollama_model": "llama3.1", "mode": "precision"}}
        cfg = get_ai_config(user)
        assert cfg["provider"] == "ollama"
        assert cfg["ollama_url"] == "https://x.ngrok.app"
        assert cfg["ollama_model"] == "llama3.1"

    def test_get_ai_config_ollama_fields_none_by_default(self):
        from user_settings import get_ai_config
        cfg = get_ai_config({"ai_config": {"provider": "openai", "key": "sk-xxx"}})
        assert cfg["ollama_url"] is None
        assert cfg["ollama_model"] is None


class TestOllamaTest:
    def test_ollama_test_rejects_non_http_url(self):
        import asyncio
        from user_settings import test_ai_provider
        r = asyncio.run(test_ai_provider("ollama", "not-a-url"))
        assert r["ok"] is False
        assert "http" in r["detail"].lower()

    def test_ollama_test_returns_error_on_unreachable_url(self):
        import asyncio
        from user_settings import test_ai_provider
        # Use a definitely-unreachable but well-formed URL
        r = asyncio.run(test_ai_provider("ollama", "http://127.0.0.1:1"))
        assert r["ok"] is False


class TestOllamaAPIEndpoints:
    def test_save_ai_ollama_requires_url(self, admin_session):
        h = {"Authorization": f"Bearer {admin_session['token']}"}
        r = requests.post(f"{BASE_URL}/api/settings/ai",
                          headers=h,
                          json={"provider": "ollama", "mode": "precision",
                                 "ollama_model": "llama3.1"},
                          timeout=8)
        assert r.status_code == 400
        assert "URL" in r.json()["detail"] or "url" in r.json()["detail"]

    def test_save_ai_ollama_requires_model(self, admin_session):
        h = {"Authorization": f"Bearer {admin_session['token']}"}
        r = requests.post(f"{BASE_URL}/api/settings/ai",
                          headers=h,
                          json={"provider": "ollama", "mode": "precision",
                                 "ollama_url": "https://x.ngrok.app"},
                          timeout=8)
        assert r.status_code == 400
        assert "modelo" in r.json()["detail"].lower()

    def test_save_ai_ollama_rejects_non_http(self, admin_session):
        h = {"Authorization": f"Bearer {admin_session['token']}"}
        r = requests.post(f"{BASE_URL}/api/settings/ai",
                          headers=h,
                          json={"provider": "ollama", "mode": "precision",
                                 "ollama_url": "ftp://foo", "ollama_model": "llama3.1"},
                          timeout=8)
        assert r.status_code == 400

    def test_save_ai_ollama_rejects_unreachable_url_on_change(self, admin_session):
        """When URL changes, backend probes /api/tags; unreachable → 400."""
        h = {"Authorization": f"Bearer {admin_session['token']}"}
        r = requests.post(f"{BASE_URL}/api/settings/ai",
                          headers=h,
                          json={"provider": "ollama", "mode": "precision",
                                 "ollama_url": "http://127.0.0.1:1",
                                 "ollama_model": "llama3.1"},
                          timeout=12)
        assert r.status_code == 400


class TestIntelHonorsOllama:
    def test_intel_signature_accepts_ollama_args(self):
        import inspect
        from intel import generate_intel_summary
        sig = inspect.signature(generate_intel_summary)
        assert "ollama_url" in sig.parameters
        assert "ollama_model" in sig.parameters

    def test_call_ai_signature_accepts_ollama(self):
        import inspect
        from intel import _call_ai
        sig = inspect.signature(_call_ai)
        assert "ollama_url" in sig.parameters
        assert "ollama_model" in sig.parameters


class TestEmergentAuthPlaybookCompliance:
    """Verify existing Emergent Google Auth honors the playbook (no hardcoded URLs, reminder comment)."""

    def test_login_uses_window_location_origin(self):
        src = open("/app/frontend/src/pages/Login.jsx").read()
        assert "window.location.origin" in src, \
            "Login must use window.location.origin (playbook rule)"
        assert "auth.emergentagent.com" in src

    def test_login_has_reminder_comment(self):
        src = open("/app/frontend/src/pages/Login.jsx").read()
        assert "DO NOT HARDCODE" in src, "Missing REMINDER comment"

    def test_auth_callback_uses_useref(self):
        src = open("/app/frontend/src/pages/AuthCallback.jsx").read()
        assert "hasProcessed = useRef" in src
        assert "session_id" in src

    def test_auth_callback_has_reminder_comment(self):
        src = open("/app/frontend/src/pages/AuthCallback.jsx").read()
        assert "DO NOT HARDCODE" in src

    def test_backend_exchanges_session_id_correctly(self):
        src = open("/app/backend/server.py").read()
        assert "demobackend.emergentagent.com/auth/v1/env/oauth/session-data" in src
        assert "X-Session-ID" in src

    def test_backend_stores_session_with_utc_expiry(self):
        src = open("/app/backend/server.py").read()
        assert "session_token" in src
        assert "user_sessions" in src
        assert "timezone.utc" in src

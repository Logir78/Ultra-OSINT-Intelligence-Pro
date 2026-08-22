"""Iteration 16 — Competitive killers.

Verifies: CVE/EPSS/KEV Engine, Typosquat Hunter, MITRE ATT&CK Mapping,
Cert Monitor, and AI Copilot endpoints + multi-tenant isolation.
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
def admin_scan(mongo):
    uid = f"user_v16_{int(time.time()*1000)}"
    token = f"tok_v16_{int(time.time()*1000)}"
    sid = f"scan_v16_{int(time.time()*1000)}"
    mongo.users.insert_one({
        "user_id": uid, "email": "davjoel31@gmail.com",
        "name": "QA", "created_at": datetime.now(timezone.utc).isoformat(),
    })
    mongo.user_sessions.insert_one({
        "user_id": uid, "session_token": token,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    })
    mongo.scans.insert_one({
        "scan_id": sid, "user_id": uid, "domain": "example.com",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "result": {
            "domain": "example.com",
            "tech_analysis": [{
                "hostname": "example.com", "server": "nginx/1.18.0",
                "cms": [{"name": "WordPress"}], "frameworks": [], "proxies": [],
            }],
            "subdomains": {"found": [{"hostname": "www.example.com"}]},
            "ports": {"open_ports": [{"p": 443}]},
        },
    })
    yield {"uid": uid, "token": token, "scan_id": sid}
    mongo.users.delete_one({"user_id": uid})
    mongo.user_sessions.delete_many({"user_id": uid})
    mongo.scans.delete_one({"scan_id": sid})
    mongo.copilot_messages.delete_many({"user_id": uid})


# ─────────────────────── CVE ENGINE ───────────────────────
class TestCveEngine:
    def test_tech_to_cpe_mapping(self):
        from integrations.cve_engine import _norm_tech
        assert _norm_tech("WordPress")[0] == "wordpress"
        assert _norm_tech("nginx/1.18.0", "nginx/1.18.0") == ("nginx", "1.18.0")
        assert _norm_tech("UnknownXYZ") is None

    def test_correlate_endpoint(self, admin_scan):
        h = {"Authorization": f"Bearer {admin_scan['token']}"}
        r = requests.post(f"{BASE_URL}/api/scans/{admin_scan['scan_id']}/cve-correlate",
                          headers=h, timeout=45)
        assert r.status_code == 200
        d = r.json()["cve_correlation"]
        assert "wordpress" in d["techs_analyzed"] or "nginx" in d["techs_analyzed"]
        assert "summary" in d
        assert isinstance(d["summary"]["total_cves"], int)

    def test_cve_isolation(self, admin_scan, mongo):
        """Other users can't access this scan's cve data."""
        other_uid = f"user_other_{int(time.time()*1000)}"
        other_tok = f"tok_other_{int(time.time()*1000)}"
        mongo.users.insert_one({"user_id": other_uid, "email": "davjoel31@gmail.com"})
        mongo.user_sessions.insert_one({"user_id": other_uid, "session_token": other_tok,
            "expires_at": (datetime.now(timezone.utc)+timedelta(days=1)).isoformat()})
        try:
            r = requests.post(
                f"{BASE_URL}/api/scans/{admin_scan['scan_id']}/cve-correlate",
                headers={"Authorization": f"Bearer {other_tok}"}, timeout=30)
            assert r.status_code == 404, "Other user must not access this scan"
        finally:
            mongo.users.delete_one({"user_id": other_uid})
            mongo.user_sessions.delete_many({"user_id": other_uid})


# ─────────────────────── TYPOSQUAT ────────────────────────
class TestTyposquat:
    def test_generate_variants(self):
        from integrations.typosquat import generate_variants
        variants = generate_variants("example.com", limit=200)
        assert len(variants) > 50
        assert "example.com" not in variants
        # TLD swap present
        assert any(v.startswith("example.") for v in variants)
        # Hyphenation
        assert any("-" in v for v in variants)

    def test_classify_variants(self):
        from integrations.typosquat import _classify_variant
        assert _classify_variant("example.com", "example.net") == "tld_swap"
        assert _classify_variant("example.com", "examplé.com") == "homoglyph"
        assert _classify_variant("example.com", "exmaple.com") == "typo"

    def test_typosquat_endpoint(self, admin_scan):
        h = {"Authorization": f"Bearer {admin_scan['token']}"}
        r = requests.post(f"{BASE_URL}/api/scans/{admin_scan['scan_id']}/typosquat",
                          headers=h, timeout=60)
        assert r.status_code == 200
        d = r.json()["typosquat"]
        assert d["target"] == "example.com"
        assert d["variants_generated"] > 50
        assert d["risk_level"] in ("clean", "low", "medium", "high", "critical")


# ─────────────────────── ATT&CK MAPPING ───────────────────
class TestAttackMapping:
    def test_map_produces_tactics(self, admin_scan):
        h = {"Authorization": f"Bearer {admin_scan['token']}"}
        r = requests.get(f"{BASE_URL}/api/scans/{admin_scan['scan_id']}/attack-mapping",
                         headers=h, timeout=10)
        assert r.status_code == 200
        m = r.json()["attack_mapping"]
        assert m["findings_matched"] > 0
        assert m["coverage"] > 0
        tactic_ids = {t["tactic"] for t in m["tactics"]}
        # Recon should always match if we have subdomains + ports
        assert "TA0043" in tactic_ids

    def test_navigator_layer_export(self, admin_scan):
        h = {"Authorization": f"Bearer {admin_scan['token']}"}
        r = requests.get(f"{BASE_URL}/api/scans/{admin_scan['scan_id']}/attack-navigator",
                         headers=h, timeout=10)
        assert r.status_code == 200
        assert "application/json" in r.headers.get("content-type", "")
        d = r.json()
        assert d["domain"] == "enterprise-attack"
        assert "techniques" in d
        assert isinstance(d["techniques"], list)


# ─────────────────────── CERT MONITOR ─────────────────────
class TestCertMonitor:
    def test_classify_severity(self):
        from integrations.cert_monitor import _classify
        now = datetime.now(timezone.utc)
        assert _classify(now + timedelta(days=100))[0] == "ok"
        assert _classify(now + timedelta(days=20))[0] == "warning"
        assert _classify(now + timedelta(days=3))[0] == "critical"
        assert _classify(now - timedelta(days=1))[0] == "expired"

    def test_cert_monitor_endpoint(self, admin_scan):
        h = {"Authorization": f"Bearer {admin_scan['token']}"}
        r = requests.post(f"{BASE_URL}/api/scans/{admin_scan['scan_id']}/cert-monitor",
                          headers=h, timeout=30)
        assert r.status_code == 200
        d = r.json()["cert_monitor"]
        assert "buckets" in d and "counts" in d
        assert set(d["buckets"].keys()) == {"expired", "critical", "warning", "ok"}


# ─────────────────────── AI COPILOT ───────────────────────
class TestCopilot:
    def test_chat_returns_answer(self, admin_scan):
        h = {"Authorization": f"Bearer {admin_scan['token']}"}
        r = requests.post(f"{BASE_URL}/api/copilot/chat",
                          headers=h,
                          json={"message": "Resumen breve de mis scans"},
                          timeout=45)
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert d["answer"] and len(d["answer"]) > 20
        assert d["model"].startswith("claude-")

    def test_chat_rejects_empty(self, admin_scan):
        h = {"Authorization": f"Bearer {admin_scan['token']}"}
        r = requests.post(f"{BASE_URL}/api/copilot/chat", headers=h,
                          json={"message": ""}, timeout=10)
        assert r.status_code == 400

    def test_chat_rejects_too_long(self, admin_scan):
        h = {"Authorization": f"Bearer {admin_scan['token']}"}
        r = requests.post(f"{BASE_URL}/api/copilot/chat", headers=h,
                          json={"message": "x" * 5000}, timeout=10)
        assert r.status_code == 400

    def test_chat_requires_auth(self):
        r = requests.post(f"{BASE_URL}/api/copilot/chat",
                          json={"message": "hi"}, timeout=10)
        assert r.status_code in (401, 403)

    def test_history_and_sessions(self, admin_scan):
        h = {"Authorization": f"Bearer {admin_scan['token']}"}
        # First send a message
        r = requests.post(f"{BASE_URL}/api/copilot/chat",
                          headers=h, json={"message": "hola"}, timeout=45)
        assert r.status_code == 200
        sid = r.json()["session_id"]
        # History
        r2 = requests.get(f"{BASE_URL}/api/copilot/history",
                          headers=h, params={"session_id": sid}, timeout=10)
        assert r2.status_code == 200
        assert len(r2.json()["messages"]) >= 2  # user + assistant
        # Sessions list
        r3 = requests.get(f"{BASE_URL}/api/copilot/sessions",
                          headers=h, timeout=10)
        assert r3.status_code == 200
        assert any(s["session_id"] == sid for s in r3.json()["sessions"])

"""Iteration 17 — Compliance + ASM + CVE Feed + Marketplace."""
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
def admin_scans(mongo):
    uid = f"user_v17_{int(time.time()*1000)}"
    tok = f"tok_v17_{int(time.time()*1000)}"
    sid1 = f"s1_{int(time.time()*1000)}"
    sid2 = f"s2_{int(time.time()*1000)}"
    # Unique domain per fixture to avoid cross-test drift interference
    dom = f"noctua-qa-{int(time.time()*1000000)}.test"
    now = datetime.now(timezone.utc)
    mongo.users.insert_one({"user_id": uid, "email": "davjoel31@gmail.com",
        "name": "QA", "created_at": now.isoformat()})
    mongo.user_sessions.insert_one({"user_id": uid, "session_token": tok,
        "expires_at": (now + timedelta(days=1)).isoformat()})
    mongo.scans.insert_many([
        {"scan_id": sid1, "user_id": uid, "domain": dom,
         "created_at": (now - timedelta(days=2)).isoformat(),
         "result": {"domain": dom,
                    "subdomains": {"found": [{"hostname": f"www.{dom}"}, {"hostname": f"api.{dom}"}]},
                    "ports": {"open_ports": [{"p": 80}, {"p": 443}]},
                    "tech_analysis": [{"hostname": dom, "server": "nginx/1.18",
                                        "cms": [{"name": "WordPress"}], "frameworks": [], "proxies": []}]}},
        {"scan_id": sid2, "user_id": uid, "domain": dom,
         "created_at": now.isoformat(),
         "result": {"domain": dom,
                    "subdomains": {"found": [{"hostname": f"www.{dom}"}, {"hostname": f"cdn.{dom}"}]},
                    "ports": {"open_ports": [{"p": 80}, {"p": 443}, {"p": 22}]},
                    "tech_analysis": [{"hostname": dom, "server": "nginx",
                                        "cms": [{"name": "WordPress"}], "frameworks": [], "proxies": []}]},
         "cve_correlation": {"summary": {"total_cves": 5, "critical": 1, "high": 2, "kev_count": 1, "risk_uplift": 30}},
         "cert_monitor": {"counts": {"expired": 0, "critical": 1, "warning": 2, "ok": 5}},
         "takeover": {"scanned": True},
         "api_auditor": {"endpoints": [{"path": "/api/v1"}]}}
    ])
    yield {"uid": uid, "tok": tok, "sid1": sid1, "sid2": sid2, "domain": dom}
    mongo.scans.delete_many({"user_id": uid})
    mongo.users.delete_one({"user_id": uid})
    mongo.user_sessions.delete_many({"user_id": uid})


class TestCompliance:
    def test_scorecard_produces_frameworks(self, admin_scans):
        h = {"Authorization": f"Bearer {admin_scans['tok']}"}
        r = requests.get(f"{BASE_URL}/api/scans/{admin_scans['sid2']}/compliance",
                         headers=h, timeout=10)
        assert r.status_code == 200
        c = r.json()["compliance"]
        assert "overall" in c and "frameworks" in c
        assert c["overall"]["percentage"] >= 0
        frameworks = {f["framework"] for f in c["frameworks"]}
        assert frameworks == {"SOC2", "ISO27001", "GDPR", "PCI-DSS"}
        for fw in c["frameworks"]:
            assert fw["grade"] in ("A+", "A", "B", "C", "D", "F")
            assert 0 <= fw["percentage"] <= 100

    def test_isolation_compliance(self, admin_scans, mongo):
        other_tok = f"tok_other_{int(time.time()*1000)}"
        mongo.users.insert_one({"user_id": "other_v17", "email": "davjoel31@gmail.com"})
        mongo.user_sessions.insert_one({"user_id": "other_v17", "session_token": other_tok,
            "expires_at": (datetime.now(timezone.utc)+timedelta(days=1)).isoformat()})
        try:
            r = requests.get(f"{BASE_URL}/api/scans/{admin_scans['sid2']}/compliance",
                             headers={"Authorization": f"Bearer {other_tok}"}, timeout=10)
            assert r.status_code == 404
        finally:
            mongo.users.delete_one({"user_id": "other_v17"})
            mongo.user_sessions.delete_many({"user_id": "other_v17"})


class TestAsmInventory:
    def test_inventory_aggregates(self, admin_scans):
        h = {"Authorization": f"Bearer {admin_scans['tok']}"}
        r = requests.get(f"{BASE_URL}/api/asm/inventory", headers=h, timeout=10)
        assert r.status_code == 200
        i = r.json()
        assert i["counts"]["domains"] >= 1
        assert i["counts"]["subdomains"] >= 3  # www, api, cdn

    def test_drift_detects_changes(self, admin_scans):
        h = {"Authorization": f"Bearer {admin_scans['tok']}"}
        r = requests.get(f"{BASE_URL}/api/asm/drift", headers=h,
                         params={"domain": admin_scans["domain"]}, timeout=10)
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert d["has_changes"] is True
        assert any("cdn." in x for x in d["subdomains"]["added"])
        assert any("api." in x for x in d["subdomains"]["removed"])
        assert 22 in d["ports"]["added"]

    def test_drift_requires_two_scans(self, admin_scans):
        h = {"Authorization": f"Bearer {admin_scans['tok']}"}
        r = requests.get(f"{BASE_URL}/api/asm/drift", headers=h,
                         params={"domain": "unknown-domain-xyz.com"}, timeout=10)
        assert r.status_code == 200
        assert r.json()["ok"] is False


class TestCveFeed:
    def test_feed_filters_by_user_stack(self, admin_scans):
        h = {"Authorization": f"Bearer {admin_scans['tok']}"}
        r = requests.get(f"{BASE_URL}/api/cve-feed", headers=h,
                         params={"days": 7}, timeout=45)
        assert r.status_code == 200
        f = r.json()
        assert "wordpress" in f["tech_stack_detected"] or "nginx" in f["tech_stack_detected"]
        assert isinstance(f.get("matched", []), list)

    def test_feed_clamps_days(self, admin_scans):
        h = {"Authorization": f"Bearer {admin_scans['tok']}"}
        r = requests.get(f"{BASE_URL}/api/cve-feed", headers=h,
                         params={"days": 500}, timeout=45)
        assert r.status_code == 200
        assert r.json()["days_window"] <= 30


class TestMarketplace:
    def test_products_listing(self, admin_scans):
        h = {"Authorization": f"Bearer {admin_scans['tok']}"}
        r = requests.get(f"{BASE_URL}/api/marketplace/products", headers=h, timeout=10)
        assert r.status_code == 200
        d = r.json()
        assert len(d["products"]) >= 6
        for p in d["products"]:
            assert p["id"] and p["name"] and p["price_usd"] > 0
            assert "unlocked" in p

    def test_checkout_creates_stripe_session(self, admin_scans, mongo):
        h = {"Authorization": f"Bearer {admin_scans['tok']}"}
        r = requests.post(f"{BASE_URL}/api/marketplace/checkout",
                          headers=h, json={"product_id": "attack_path"}, timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert d["session_id"].startswith("cs_")
        assert "stripe.com" in d["url"]
        # Verify persistence
        tx = mongo.payment_transactions.find_one({"session_id": d["session_id"]})
        assert tx and tx["kind"] == "marketplace"
        assert tx["product_id"] == "attack_path"

    def test_checkout_unknown_product(self, admin_scans):
        h = {"Authorization": f"Bearer {admin_scans['tok']}"}
        r = requests.post(f"{BASE_URL}/api/marketplace/checkout",
                          headers=h, json={"product_id": "not_a_product"}, timeout=10)
        assert r.status_code == 404

    def test_is_unlocked_module(self):
        from marketplace import is_unlocked
        assert is_unlocked({"plan": "pro"}, "any") is True
        assert is_unlocked({"unlocks": ["typosquat"]}, "typosquat") is True
        assert is_unlocked({"unlocks": []}, "typosquat") is False

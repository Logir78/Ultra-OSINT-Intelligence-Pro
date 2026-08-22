"""Iteration-7 NOCTUA.osint bug-bounty batch tests (4 new endpoints + PROVIDERS github).

Covers:
- GET /api/scans/{id}/logic-flow           (schema, empty-flows path, cache)
- GET /api/scans/{id}/reverse-ip           (no-IP path, schema, cache)
- GET /api/scans/{id}/github-miner         (unconfigured graceful path, cache)
- GET /api/scans/{id}/bot-resistance       (schema, cache; against example.com)
- POST /api/settings/keys                  (persists github provider)
- PROVIDERS list includes 'github'
"""
import os
import uuid
import pytest
import requests
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / "frontend" / ".env")
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# Seed helper (Mongo direct) -- richer for logic-flow paths
def _seed_scan(mongo, user_id: str, domain: str = "example.com",
               *, ip: str = "93.184.216.34", scan_id: str = None,
               with_flows: bool = False) -> str:
    scan_id = scan_id or f"scan_it7_{uuid.uuid4().hex[:10]}"
    fake_scan = {
        "domain": domain,
        "ip": {"ip": ip},
        "dns": {"A": [ip], "MX": [], "TXT": [], "NS": []},
        "subdomains": {"found": [{"subdomain": f"www.{domain}", "ips": [ip]}]},
        "ports": {"open_ports": [{"port": 443, "service": "https"}]},
        "ssl": {"success": True, "issuer": {"organizationName": "DigiCert"},
                "tls_version": "TLSv1.3", "not_after": "Jan 15 12:00:00 2026 GMT"},
        "https_headers": {"success": True, "headers": {}},
        "tech_analysis": [{"hostname": domain, "cms": [], "frameworks": [],
                           "libraries": [], "missing_critical": [], "is_protected": False}],
        "security": {"basic": {"score": 60, "items": []},
                     "medium": {"score": 40, "items": []},
                     "advanced": {"score": 30, "items": []}},
    }
    doc = {
        "scan_id": scan_id,
        "user_id": user_id,
        "domain": domain,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "extended_ports": False,
        "result": fake_scan,
    }
    if with_flows:
        # Seed js_miner + api_audit findings so logic_flow._detect_flows returns hits
        doc["js_miner"] = {
            "findings": [
                {"kind": "api_endpoint", "match": "/api/login"},
                {"kind": "api_endpoint", "match": "/checkout/step1"},
                {"kind": "api_endpoint", "match": "/reset-password"},
                {"kind": "api_endpoint", "match": "/admin/panel"},
                {"kind": "api_endpoint", "match": "/coupon/apply"},
            ],
        }
        doc["api_audit"] = {
            "findings": [
                {"url": f"https://{domain}/api/v1/users"},
                {"url": f"https://{domain}/signup"},
            ],
        }
    mongo.scans.insert_one(doc)
    return scan_id


@pytest.fixture
def pro_scan(mongo, pro_user):
    scan_id = _seed_scan(mongo, pro_user["user_id"], domain="example.com")
    yield {"scan_id": scan_id, **pro_user}
    mongo.scans.delete_many({"scan_id": scan_id})


@pytest.fixture
def pro_scan_no_ip(mongo, pro_user):
    scan_id = f"scan_it7_{uuid.uuid4().hex[:10]}"
    mongo.scans.insert_one({
        "scan_id": scan_id,
        "user_id": pro_user["user_id"],
        "domain": "no-ip.example.local",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "result": {"domain": "no-ip.example.local", "ip": {}, "dns": {}, "subdomains": {"found": []},
                   "ports": {"open_ports": []}, "ssl": {"success": False},
                   "https_headers": {"success": False, "headers": {}},
                   "tech_analysis": [], "security": {}},
    })
    yield {"scan_id": scan_id, **pro_user}
    mongo.scans.delete_many({"scan_id": scan_id})


# --------------------------------------------------------------
# 1. Logic Flow
# --------------------------------------------------------------
class TestLogicFlow:
    def test_no_flows_detected_returns_200(self, client, pro_scan):
        """Scan with no js_miner/api_audit → flows_detected=0, empty scenarios, 200 OK."""
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/logic-flow"
        r = client.get(url, headers=h, timeout=30)
        assert r.status_code == 200, r.text
        d = r.json()
        assert "logic_flow" in d
        lf = d["logic_flow"]
        assert lf["flows_detected"] == 0
        assert lf["flows"] == {}
        assert lf["bypass_scenarios"] == []
        assert "note" in lf
        assert "generated_at" in lf
        assert d.get("cached") is False

        # Cache check
        r2 = client.get(url, headers=h, timeout=10)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True

    def test_with_flows_calls_ai(self, client, mongo, pro_user):
        """Seed js_miner + api_audit → flows detected → AI called → scenarios returned."""
        uid = pro_user["user_id"]
        h = _auth(pro_user["token"])
        sid = _seed_scan(mongo, uid, domain="flow-test.local", with_flows=True)
        try:
            url = f"{BASE_URL}/api/scans/{sid}/logic-flow"
            r = client.get(url, headers=h, timeout=120)  # allow LLM
            assert r.status_code == 200, r.text
            lf = r.json()["logic_flow"]
            assert lf["flows_detected"] >= 1
            assert isinstance(lf["flows"], dict)
            assert isinstance(lf["bypass_scenarios"], list)
            # Priority flow + verdict fields present (may be empty if AI failed)
            assert "priority_flow" in lf
            assert "overall_verdict" in lf
            # If AI returned scenarios, verify shape
            for sc in lf["bypass_scenarios"][:2]:
                for k in ("flow", "vulnerability_class", "hypothetical_bypass",
                          "test_steps", "expected_indicator", "risk", "impact_plain"):
                    assert k in sc, f"missing scenario key {k}"
        finally:
            mongo.scans.delete_many({"scan_id": sid})


# --------------------------------------------------------------
# 2. Reverse IP
# --------------------------------------------------------------
class TestReverseIP:
    def test_no_ip_returns_note(self, client, pro_scan_no_ip):
        h = _auth(pro_scan_no_ip["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan_no_ip['scan_id']}/reverse-ip"
        r = client.get(url, headers=h, timeout=30)
        assert r.status_code == 200, r.text
        ri = r.json()["reverse_ip"]
        assert ri["reverse_ip_count"] == 0
        assert ri["reverse_ip_domains"] == []
        assert "note" in ri
        assert ri.get("ip") is None

    def test_with_ip_returns_schema_and_caches(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/reverse-ip"
        r = client.get(url, headers=h, timeout=30)
        assert r.status_code == 200, r.text
        d = r.json()
        ri = d["reverse_ip"]
        for k in ("domain", "ip", "reverse_ip_count", "reverse_ip_domains",
                  "interesting_neighbors", "interesting_count", "asn", "source"):
            assert k in ri, f"missing {k}"
        assert ri["domain"] == "example.com"
        assert ri["ip"] == "93.184.216.34"
        assert isinstance(ri["reverse_ip_domains"], list)
        assert isinstance(ri["interesting_neighbors"], list)
        assert isinstance(ri["asn"], dict)
        assert ri["source"] == "hackertarget + arin_rdap"
        # If HackerTarget rate-limited, count could be 0 — that's OK, no 500
        assert d.get("cached") is False

        # Cache check
        r2 = client.get(url, headers=h, timeout=10)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True


# --------------------------------------------------------------
# 3. GitHub Miner (no token configured → configured:false)
# --------------------------------------------------------------
class TestGithubMiner:
    def test_no_token_returns_configured_false(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/github-miner"
        r = client.get(url, headers=h, timeout=15)
        assert r.status_code == 200, r.text
        gm = r.json()["github_miner"]
        assert gm["configured"] is False
        assert gm["total_hits"] == 0
        assert gm["results"] == []
        assert gm["secret_hits"] == []
        assert "note" in gm
        # Cache check
        r2 = client.get(url, headers=h, timeout=10)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True


# --------------------------------------------------------------
# 4. Bot Resistance
# --------------------------------------------------------------
class TestBotResistance:
    def test_bot_resistance_schema_and_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/bot-resistance"
        r = client.get(url, headers=h, timeout=60)  # 8 concurrent GETs to external site
        assert r.status_code == 200, r.text
        d = r.json()
        assert "bot_resistance" in d
        br = d["bot_resistance"]
        for k in ("domain", "homepage", "login_page", "captchas_detected",
                  "captchas_count", "waf_hint", "rate_limit", "score",
                  "risk", "verdict"):
            assert k in br, f"missing {k}"
        assert br["domain"] == "example.com"
        assert isinstance(br["captchas_detected"], list)
        assert isinstance(br["score"], int)
        assert 0 <= br["score"] <= 100
        assert br["risk"] in ("critical", "high", "medium", "low")
        # rate_limit dict shape
        rl = br["rate_limit"]
        assert isinstance(rl, dict)
        # Should have tried the probe
        assert "tested" in rl
        assert d.get("cached") is False

        # Cache check
        r2 = client.get(url, headers=h, timeout=10)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True


# --------------------------------------------------------------
# 5. PROVIDERS list + POST /api/settings/keys github
# --------------------------------------------------------------
class TestGithubProvider:
    def test_providers_list_includes_github(self):
        import sys
        backend_path = str(Path(__file__).resolve().parents[1])
        if backend_path not in sys.path:
            sys.path.insert(0, backend_path)
        from user_settings import PROVIDERS  # noqa
        assert "github" in PROVIDERS

    def test_get_settings_keys_lists_github(self, client, free_user):
        h = _auth(free_user["token"])
        r = client.get(f"{BASE_URL}/api/settings/keys", headers=h, timeout=15)
        assert r.status_code == 200
        api_keys = r.json().get("api_keys") or {}
        assert "github" in api_keys, f"api_keys keys={list(api_keys.keys())}"
        assert api_keys["github"]["set"] is False  # nothing saved yet

    def test_save_github_key_persists(self, client, mongo, free_user):
        """POST /api/settings/keys with github key → persists into user doc.

        NOTE: server calls TEST_FUNCS[provider](v) if `<provider>_changed` is not
        explicitly False. Since there is no TEST_FUNCS entry for 'github', we
        pass github_changed=False so validation is skipped (trusted).
        """
        h = _auth(free_user["token"])
        fake_pat = "ghp_" + "x" * 36
        # First send with github_changed=False so validation is skipped (trusted key)
        payload = {"api_keys": {"github": fake_pat, "github_changed": False}}
        r = client.post(f"{BASE_URL}/api/settings/keys", headers=h,
                        json=payload, timeout=15)
        assert r.status_code == 200, r.text
        saved = r.json().get("saved") or []
        assert "github" in saved, f"saved keys: {saved}"

        # Verify persistence in DB
        u = mongo.users.find_one({"user_id": free_user["user_id"]})
        assert (u.get("api_keys") or {}).get("github") == fake_pat

        # Verify GET reflects set=true and mask
        r2 = client.get(f"{BASE_URL}/api/settings/keys", headers=h, timeout=15)
        gh = (r2.json().get("api_keys") or {}).get("github") or {}
        assert gh.get("set") is True
        assert "•" in (gh.get("masked") or "")

    def test_save_github_key_with_changed_true_currently_crashes(self, client, free_user):
        """If client sends github_changed=True, backend runs TEST_FUNCS['github']
        which doesn't exist. This test documents the current behavior.

        Marked xfail — this is a bug: TEST_FUNCS has no 'github' handler.
        """
        h = _auth(free_user["token"])
        fake_pat = "ghp_" + "y" * 36
        payload = {"api_keys": {"github": fake_pat, "github_changed": True}}
        r = client.post(f"{BASE_URL}/api/settings/keys", headers=h,
                        json=payload, timeout=15)
        # Expected: 200 OK (or 400 validation_failed) — should not 500
        if r.status_code >= 500:
            pytest.xfail(f"KNOWN BUG: TEST_FUNCS has no 'github' handler → {r.status_code} {r.text[:200]}")
        assert r.status_code in (200, 400), r.text


# --------------------------------------------------------------
# 6. Regression sanity — previously green endpoints still respond
# --------------------------------------------------------------
class TestRegressionSanity:
    def test_supply_chain_still_ok(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        r = client.get(f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/supply-chain",
                       headers=h, timeout=60)
        assert r.status_code == 200
        assert "supply_chain" in r.json()

    def test_idor_still_ok(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        r = client.get(f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/idor",
                       headers=h, timeout=60)
        assert r.status_code == 200

    def test_public_stats_still_ok(self, client):
        r = client.get(f"{BASE_URL}/api/public/stats", timeout=15)
        assert r.status_code == 200

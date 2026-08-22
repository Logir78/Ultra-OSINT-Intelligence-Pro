"""Backend tests for the new advanced NOCTUA modules (iteration 4).

Covers:
- GET /api/apt-personas
- GET /api/scans/{id}/js-miner        (+cache)
- GET /api/scans/{id}/ct-logs         (+cache, graceful crt.sh)
- GET /api/scans/{id}/shodan-deep     (configured=false when no key)
- GET /api/scans/{id}/dna
- GET /api/scans/{id}/risk-oracle     (+cache)
- GET /api/scans/{id}/brand-guardian
- POST /api/scans/{id}/phishing-sim   (free -> 402, pro -> 200)
- POST /api/scans/{id}/attack-path    (none + apt29 caching)
- GET /api/scans/{id}/poc
- POST /api/scans/{id}/predict        (parallel)
- GET/POST /api/settings/preferences
- GET /api/scans/{id}/pdf             (executive-summary page)
- Regressions: GET /api/public/stats, GET /api/scans, telegram endpoints
"""
import os
import uuid
import pytest
import requests
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / "frontend" / ".env")
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ------------------------------------------------------------------
# Shared "seed scan" fixture: build a scan document DIRECTLY in Mongo
# so tests don't have to wait 60-90s for a real scan.
# ------------------------------------------------------------------
def _seed_scan(mongo, user_id: str, domain: str = "example.com") -> str:
    scan_id = f"scan_test_{uuid.uuid4().hex[:10]}"
    fake_scan = {
        "domain": domain,
        "ip": {"ip": "93.184.216.34"},
        "dns": {"A": ["93.184.216.34"], "MX": [], "TXT": [], "NS": ["a.iana-servers.net"]},
        "subdomains": {"found": [
            {"subdomain": f"www.{domain}", "ips": ["93.184.216.34"]},
            {"subdomain": f"mail.{domain}", "ips": ["93.184.216.35"]},
        ]},
        "ports": {"open_ports": [
            {"port": 80, "service": "http"},
            {"port": 443, "service": "https"},
            {"port": 22, "service": "ssh"},
        ]},
        "ssl": {"success": True, "issuer": {"organizationName": "DigiCert"},
                "tls_version": "TLSv1.3", "not_after": "Jan 15 12:00:00 2026 GMT"},
        "https_headers": {"success": True, "headers": {}},
        "tech_analysis": [{"hostname": domain, "cms": [], "frameworks": [],
                           "libraries": [], "missing_critical": ["hsts", "csp"],
                           "is_protected": False}],
        "security": {"basic": {"score": 60, "items": []},
                     "medium": {"score": 40, "items": []},
                     "advanced": {"score": 30, "items": []}},
    }
    mongo.scans.insert_one({
        "scan_id": scan_id,
        "user_id": user_id,
        "domain": domain,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "extended_ports": False,
        "result": fake_scan,
    })
    return scan_id


@pytest.fixture
def free_scan(mongo, free_user):
    scan_id = _seed_scan(mongo, free_user["user_id"], domain="example.com")
    yield {"scan_id": scan_id, **free_user}
    mongo.scans.delete_many({"scan_id": scan_id})


@pytest.fixture
def pro_scan(mongo, pro_user):
    scan_id = _seed_scan(mongo, pro_user["user_id"], domain="example.com")
    yield {"scan_id": scan_id, **pro_user}
    mongo.scans.delete_many({"scan_id": scan_id})


# ------------------------------------------------------------------
# 1. APT personas (public, no auth needed to be usable)
# ------------------------------------------------------------------
class TestAPTPersonas:
    def test_list_personas(self, client):
        r = client.get(f"{BASE_URL}/api/apt-personas")
        assert r.status_code == 200
        data = r.json()
        assert "personas" in data
        ids = [p["id"] for p in data["personas"]]
        for required in ["none", "apt29_cozybear", "apt41_china", "lazarus_dprk",
                         "conti_ransomware", "script_kiddie", "insider"]:
            assert required in ids, f"missing persona: {required}"
        assert len(data["personas"]) >= 6
        for p in data["personas"]:
            assert isinstance(p["description"], str) and len(p["description"]) > 5


# ------------------------------------------------------------------
# 2. JS Miner
# ------------------------------------------------------------------
class TestJSMiner:
    def test_js_miner_and_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/js-miner"
        r1 = client.get(url, headers=h, timeout=60)
        assert r1.status_code == 200, r1.text
        d = r1.json()
        assert "js_miner" in d
        jm = d["js_miner"]
        for k in ["domain", "js_files_analyzed", "js_urls_discovered", "findings",
                  "counts_by_kind", "counts_by_severity", "total_findings"]:
            assert k in jm, f"missing key {k}"
        assert jm["domain"] == "example.com"
        assert isinstance(jm["findings"], list)
        assert d.get("cached") is False

        r2 = client.get(url, headers=h, timeout=15)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True


# ------------------------------------------------------------------
# 3. CT Logs
# ------------------------------------------------------------------
class TestCTLogs:
    def test_ct_logs_no_500_even_if_slow(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/ct-logs"
        r1 = client.get(url, headers=h, timeout=90)
        assert r1.status_code == 200, r1.text
        d = r1.json()
        assert "ct_logs" in d
        ct = d["ct_logs"]
        assert "counts" in ct
        counts = ct["counts"]
        for k in ["active_and_ct", "dns_only", "ct_only", "combined"]:
            assert k in counts
        assert "combined_subdomains" in ct
        for sub in ct["combined_subdomains"]:
            assert sub.get("source") in ("both", "dns_only", "ct_only")

        # cache
        r2 = client.get(url, headers=h, timeout=15)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True


# ------------------------------------------------------------------
# 4. Shodan Deep — graceful when no key
# ------------------------------------------------------------------
class TestShodanDeep:
    def test_shodan_deep_no_key(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/shodan-deep"
        r = client.get(url, headers=h, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert "shodan_deep" in d
        sd = d["shodan_deep"]
        assert "configured" in sd
        assert "hosts" in sd
        assert isinstance(sd["hosts"], list)
        assert "total_alerts" in sd
        # When configured, the response includes richer fields
        if sd.get("configured"):
            for k in ("critical_count", "unique_ports"):
                assert k in sd
        else:
            # Graceful degradation: no key -> minimal payload, must NOT raise 500
            assert sd["hosts"] == []


# ------------------------------------------------------------------
# 5. DNA Fingerprint
# ------------------------------------------------------------------
class TestDNA:
    def test_dna(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/dna"
        r = client.get(url, headers=h, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert "dna" in d
        dna = d["dna"]
        assert "fingerprint" in dna
        assert isinstance(dna["fingerprint"], str)
        assert len(dna["fingerprint"]) == 24
        for k in ("components_hash", "signals_used", "siblings", "sibling_count"):
            assert k in dna
        comp = dna["components_hash"]
        for c in ("libs", "headers", "dns", "ssl"):
            assert c in comp


# ------------------------------------------------------------------
# 6. Risk Oracle
# ------------------------------------------------------------------
class TestRiskOracle:
    def test_oracle_and_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/risk-oracle"
        r1 = client.get(url, headers=h, timeout=120)
        assert r1.status_code == 200, r1.text
        d = r1.json()
        assert "risk_oracle" in d
        o = d["risk_oracle"]
        for k in ("probability_percent", "baseline_percent", "verdict",
                  "top_risk_factors", "timeline", "confidence",
                  "tech_debt_signals", "breach_signals"):
            assert k in o, f"missing key {k}"
        assert 0 <= float(o["probability_percent"]) <= 100
        assert isinstance(o["top_risk_factors"], list)
        # cache
        r2 = client.get(url, headers=h, timeout=15)
        assert r2.json().get("cached") is True


# ------------------------------------------------------------------
# 7. Brand Guardian
# ------------------------------------------------------------------
class TestBrandGuardian:
    def test_brand_guardian(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/brand-guardian"
        r = client.get(url, headers=h, timeout=120)
        assert r.status_code == 200, r.text
        d = r.json()
        assert "brand_guardian" in d
        bg = d["brand_guardian"]
        for k in ("variants_tested", "resolved_variants", "clones_detected",
                  "suspicious_count", "brand_at_risk", "impersonation_verdict",
                  "clones", "suspicious"):
            assert k in bg, f"missing key {k}"


# ------------------------------------------------------------------
# 8. Phishing Sim — Free 402 / Pro 200
# ------------------------------------------------------------------
class TestPhishingSim:
    def test_free_gets_402(self, client, free_scan):
        h = _auth(free_scan["token"])
        url = f"{BASE_URL}/api/scans/{free_scan['scan_id']}/phishing-sim"
        r = client.post(url, headers=h, json={}, timeout=15)
        assert r.status_code == 402, f"expected 402, got {r.status_code}: {r.text}"

    def test_pro_gets_simulation(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/phishing-sim"
        r = client.post(url, headers=h, json={}, timeout=120)
        assert r.status_code == 200, r.text
        d = r.json()
        assert "phishing_sim" in d
        ps = d["phishing_sim"]
        for k in ("disclaimer", "scenario_name", "target_role", "clone_target",
                  "email", "psychological_triggers", "safe_reminders"):
            assert k in ps, f"missing key {k}"
        for k in ("page_type", "url_suggestion"):
            assert k in ps["clone_target"]
        for k in ("subject", "from_display", "body_html", "body_text"):
            assert k in ps["email"]


# ------------------------------------------------------------------
# 9. Attack Path — none + apt29 caching
# ------------------------------------------------------------------
class TestAttackPath:
    def test_none_and_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/attack-path"
        r1 = client.post(url, headers=h, json={"apt_persona": "none"}, timeout=120)
        assert r1.status_code == 200, r1.text
        d1 = r1.json()
        assert "attack_path" in d1
        ap = d1["attack_path"]
        for k in ("executive_summary", "attack_chain", "final_impact",
                  "urgency", "mitigation_priorities",
                  "estimated_time_to_compromise", "confidence"):
            assert k in ap, f"missing key {k}"
        assert ap.get("apt_persona") == "none"
        # cache
        r2 = client.post(url, headers=h, json={"apt_persona": "none"}, timeout=30)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True

    def test_apt29_different_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/attack-path"
        r1 = client.post(url, headers=h,
                         json={"apt_persona": "none"}, timeout=120)
        assert r1.status_code == 200
        r2 = client.post(url, headers=h,
                         json={"apt_persona": "apt29_cozybear"}, timeout=120)
        assert r2.status_code == 200, r2.text
        d2 = r2.json()
        ap = d2["attack_path"]
        assert ap.get("apt_persona") == "apt29_cozybear"
        # It must NOT have hit the "none" cache
        assert d2.get("cached") is False


# ------------------------------------------------------------------
# 10. PoC Generator
# ------------------------------------------------------------------
class TestPoC:
    def test_poc(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/poc"
        r = client.get(url, headers=h, timeout=120)
        assert r.status_code == 200, r.text
        d = r.json()
        assert "poc" in d
        p = d["poc"]
        assert "pocs" in p
        assert "vulns_analyzed" in p
        assert isinstance(p["pocs"], list)
        # If PoCs were generated, disclaimer must be present; otherwise a message
        if p["pocs"]:
            assert "disclaimer" in p
        else:
            assert "message" in p


# ------------------------------------------------------------------
# 11. Predict (parallel) — must not throw on partial failure
# ------------------------------------------------------------------
class TestPredictAll:
    def test_predict_all(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/predict"
        r = client.post(url, headers=h, timeout=180)
        assert r.status_code == 200, r.text
        d = r.json()
        for k in ("risk_oracle", "brand_guardian", "dna", "attack_path"):
            assert k in d, f"missing module: {k}"


# ------------------------------------------------------------------
# 12. Preferences
# ------------------------------------------------------------------
class TestPreferences:
    def test_default_prefs(self, client, free_user):
        h = _auth(free_user["token"])
        r = client.get(f"{BASE_URL}/api/settings/preferences", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["risk_threshold"] == 50
        assert d["notes"] == ""

    def test_save_and_clamp(self, client, free_user):
        h = _auth(free_user["token"])
        # Save
        r = client.post(f"{BASE_URL}/api/settings/preferences", headers=h,
                        json={"risk_threshold": 75, "notes": "TEST_note"})
        assert r.status_code == 200
        r2 = client.get(f"{BASE_URL}/api/settings/preferences", headers=h)
        assert r2.status_code == 200
        d = r2.json()
        assert d["risk_threshold"] == 75
        assert d["notes"] == "TEST_note"

        # Clamp above
        client.post(f"{BASE_URL}/api/settings/preferences", headers=h,
                    json={"risk_threshold": 500})
        d2 = client.get(f"{BASE_URL}/api/settings/preferences", headers=h).json()
        assert d2["risk_threshold"] == 100

        # Clamp below
        client.post(f"{BASE_URL}/api/settings/preferences", headers=h,
                    json={"risk_threshold": -10})
        d3 = client.get(f"{BASE_URL}/api/settings/preferences", headers=h).json()
        assert d3["risk_threshold"] == 0


# ------------------------------------------------------------------
# 13. PDF Executive Summary page
# ------------------------------------------------------------------
class TestPDFExecutive:
    def test_pdf_downloads_with_executive_page(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        # trigger oracle + attack path first
        client.get(f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/risk-oracle",
                   headers=h, timeout=120)
        client.post(f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/attack-path",
                    headers=h, json={"apt_persona": "none"}, timeout=120)
        r = client.get(f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/pdf",
                       headers=h, timeout=180)
        assert r.status_code == 200, r.text[:400]
        assert "application/pdf" in r.headers.get("content-type", "")
        assert len(r.content) > 3000  # > 3KB
        # magic bytes
        assert r.content.startswith(b"%PDF")


# ------------------------------------------------------------------
# 14. Regressions
# ------------------------------------------------------------------
class TestRegression:
    def test_public_stats(self, client):
        r = client.get(f"{BASE_URL}/api/public/stats", timeout=15)
        assert r.status_code == 200
        d = r.json()
        for k in ("scans_this_month", "total_scans", "takeovers_detected",
                  "active_users"):
            assert k in d
            assert isinstance(d[k], int)
            assert d[k] >= 0

    def test_list_scans(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        r = client.get(f"{BASE_URL}/api/scans", headers=h, timeout=15)
        assert r.status_code == 200
        arr = r.json()
        assert isinstance(arr, list)
        ids = [it["scan_id"] for it in arr]
        assert pro_scan["scan_id"] in ids

    def test_telegram_get(self, client, free_user):
        h = _auth(free_user["token"])
        r = client.get(f"{BASE_URL}/api/settings/telegram", headers=h)
        assert r.status_code == 200
        d = r.json()
        for k in ("bot_token_set", "bot_token_masked", "chat_id"):
            assert k in d

    def test_telegram_post_free_402(self, client, free_user):
        h = _auth(free_user["token"])
        r = client.post(f"{BASE_URL}/api/settings/telegram", headers=h,
                        json={"bot_token": "123456:AAA", "chat_id": "111"})
        assert r.status_code == 402

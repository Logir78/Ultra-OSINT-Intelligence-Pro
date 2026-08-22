"""Iteration-8 Project Genesis tests + github save bug regression.

Covers:
- FIX: POST /api/settings/keys with github_changed=true no longer 500s
- GET /api/stealth/status (public, no auth)
- GET /api/scans/{id}/jarm             (62-char hex + cache)
- GET /api/scans/{id}/honeypot         (schema + cache)
- GET /api/scans/{id}/evidence-seal    (chain_hash deterministic)
- GET /api/scans/{id}/sleeping-infra   (heuristic schema)
- GET /api/scans/{id}/org-map          (AI, schema + cache)
- GET /api/scans/{id}/dev-profile      (AI, schema + cache)
"""
import os
import uuid
import time
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


def _seed_scan(mongo, user_id: str, domain: str = "example.com",
               *, ip: str = "93.184.216.34", scan_id: str = None) -> str:
    scan_id = scan_id or f"scan_it8_{uuid.uuid4().hex[:10]}"
    fake_scan = {
        "domain": domain,
        "ip": {"ip": ip},
        "dns": {"A": [ip], "MX": [], "TXT": [], "NS": []},
        "subdomains": {"found": [
            {"subdomain": f"www.{domain}", "ips": [ip]},
            {"subdomain": f"dev.{domain}", "ips": [ip]},
            {"subdomain": f"marketing.{domain}", "ips": [ip]},
        ]},
        "ports": {"open_ports": [{"port": 443, "service": "https"}]},
        "ssl": {"success": True, "issuer": {"organizationName": "DigiCert"},
                "tls_version": "TLSv1.3", "not_after": "Jan 15 12:00:00 2026 GMT",
                "not_before": "Jan 15 12:00:00 2024 GMT"},
        "https_headers": {"success": True, "headers": {}},
        "tech_analysis": [{"hostname": domain, "cms": [], "frameworks": [],
                           "libraries": [], "missing_critical": [], "is_protected": False}],
        "security": {"basic": {"score": 60, "items": []},
                     "medium": {"score": 40, "items": []},
                     "advanced": {"score": 30, "items": []}},
        "whois": {"data": {"org": "Example Org Inc", "registrant_organization": "Example Org Inc"}},
    }
    doc = {
        "scan_id": scan_id,
        "user_id": user_id,
        "domain": domain,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "extended_ports": False,
        "result": fake_scan,
    }
    mongo.scans.insert_one(doc)
    return scan_id


@pytest.fixture
def pro_scan(mongo, pro_user):
    scan_id = _seed_scan(mongo, pro_user["user_id"], domain="example.com")
    yield {"scan_id": scan_id, **pro_user}
    mongo.scans.delete_many({"scan_id": scan_id})


# -----------------------------------------------------------------
# 1. GITHUB KEY SAVE BUG FIX (was 500 KeyError in iteration_7)
# -----------------------------------------------------------------
class TestGithubKeySaveFixed:
    def test_save_github_key_with_changed_true_no_longer_crashes(self, client, free_user):
        """github_changed=true now hits test_github (registered) → 200 or 400
        (validation_failed for a fake token) — but NEVER 500 KeyError anymore."""
        h = _auth(free_user["token"])
        fake_pat = "ghp_faketoken12345"
        payload = {"api_keys": {"github": fake_pat, "github_changed": True}}
        r = client.post(f"{BASE_URL}/api/settings/keys", headers=h,
                        json=payload, timeout=20)
        # Regression: no more 500 KeyError
        assert r.status_code != 500, f"Bug regressed — still crashes with 500: {r.text[:300]}"
        # New behavior: server either accepts (200) or rejects the token (400
        # with validation_failed.github). Both prove the KeyError is fixed.
        assert r.status_code in (200, 400), f"Unexpected status {r.status_code}: {r.text[:300]}"
        body = r.json()
        if r.status_code == 400:
            # Validation-fail path — must mention github and the 401 from api.github.com
            detail = body.get("detail") or {}
            vf = detail.get("validation_failed") or {}
            assert "github" in vf, f"validation_failed missing github: {detail}"
            assert "401" in vf["github"] or "HTTP" in vf["github"], f"unexpected: {vf}"
        else:
            tr = body.get("test_results") or {}
            assert "github" in tr, f"github not in test_results: {tr}"
            assert tr["github"].get("ok") is False, f"unexpected github result: {tr['github']}"

    def test_test_funcs_has_github(self):
        """Ensure user_settings.TEST_FUNCS has a 'github' entry (regression against iter-7 bug)."""
        import sys
        backend_path = str(Path(__file__).resolve().parents[1])
        if backend_path not in sys.path:
            sys.path.insert(0, backend_path)
        from user_settings import TEST_FUNCS
        assert "github" in TEST_FUNCS


# -----------------------------------------------------------------
# 2. STEALTH STATUS (public, no auth)
# -----------------------------------------------------------------
class TestStealthStatus:
    def test_stealth_status_public(self, client):
        r = client.get(f"{BASE_URL}/api/stealth/status", timeout=15)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("enabled") is True
        ps = d.get("pool_sizes") or {}
        assert ps.get("user_agents", 0) >= 10, f"user_agents pool too small: {ps}"
        assert ps.get("languages", 0) >= 5
        assert ps.get("accepts", 0) >= 3
        dd = d.get("default_delay_ms") or {}
        assert dd.get("min") == 100 and dd.get("max") == 800
        feats = d.get("features") or []
        assert len(feats) >= 6
        assert "rotating_user_agent_per_scan" in feats
        assert d.get("human_pause_chance") == 0.1
        assert "note" in d


# -----------------------------------------------------------------
# 3. JARM Fingerprint
# -----------------------------------------------------------------
class TestJarm:
    def test_jarm_returns_62_char_fingerprint_and_caches(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/jarm"
        r = client.get(url, headers=h, timeout=90)  # 10 TLS handshakes to example.com
        assert r.status_code == 200, r.text
        d = r.json()
        assert "jarm" in d
        j = d["jarm"]
        assert j["host"] == "example.com"
        assert j["port"] == 443
        fp = j["jarm_fingerprint"]
        assert isinstance(fp, str) and len(fp) == 62, f"fingerprint length={len(fp)} value={fp}"
        # hex chars only
        int(fp, 16)  # will raise if not hex
        assert j["handshakes_attempted"] == 10
        assert j["handshakes_successful"] >= 1, f"no successful handshakes: {j}"
        assert isinstance(j["observed_tls_versions"], list)
        assert isinstance(j["observed_ciphers"], list)
        assert "raw_signature" in j
        assert d.get("cached") is False

        # Cache check
        r2 = client.get(url, headers=h, timeout=15)
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2.get("cached") is True
        assert d2["jarm"]["jarm_fingerprint"] == fp


# -----------------------------------------------------------------
# 4. Honeypot Detector
# -----------------------------------------------------------------
class TestHoneypot:
    def test_honeypot_schema_and_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/honeypot"
        r = client.get(url, headers=h, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        hp = d["honeypot"]
        for k in ("domain", "ip", "suspicion_score", "risk", "verdict",
                  "signals_detected", "generated_at"):
            assert k in hp, f"missing {k}"
        assert 0 <= hp["suspicion_score"] <= 100
        assert hp["risk"] in ("critical", "high", "low", "medium")
        # example.com is not a honeypot → low + score close to 0
        assert hp["risk"] == "low", f"example.com should be low risk, got {hp['risk']}"
        assert hp["suspicion_score"] < 30
        assert isinstance(hp["signals_detected"], list)

        r2 = client.get(url, headers=h, timeout=15)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True


# -----------------------------------------------------------------
# 5. Evidence Sealing
# -----------------------------------------------------------------
class TestEvidenceSeal:
    def test_evidence_seal_empty_findings_deterministic(self, client, pro_scan):
        """No critical findings → sealed_findings=[], chain_hash = sha256('[]') and DETERMINISTIC."""
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/evidence-seal"
        r1 = client.get(url, headers=h, timeout=30)
        assert r1.status_code == 200, r1.text
        e1 = r1.json()["evidence"]
        for k in ("scan_id", "domain", "sealed_at", "total_findings_sealed",
                  "chain_hash", "algorithm", "custody_note", "sealed_findings"):
            assert k in e1, f"missing {k}"
        assert e1["total_findings_sealed"] == 0
        assert e1["sealed_findings"] == []
        assert isinstance(e1["chain_hash"], str) and len(e1["chain_hash"]) == 64
        int(e1["chain_hash"], 16)  # hex check
        assert e1["algorithm"] == "SHA-256 over canonical JSON"

        # Deterministic: 2nd call same chain_hash (list is empty, so no time-based hashes)
        r2 = client.get(url, headers=h, timeout=30)
        assert r2.status_code == 200
        e2 = r2.json()["evidence"]
        assert e2["chain_hash"] == e1["chain_hash"], \
            f"chain_hash NOT deterministic: {e1['chain_hash']} vs {e2['chain_hash']}"


# -----------------------------------------------------------------
# 6. Sleeping Infrastructure Hunter (pure heuristic — no AI, no external)
# -----------------------------------------------------------------
class TestSleepingInfra:
    def test_sleeping_infra_schema(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/sleeping-infra"
        r = client.get(url, headers=h, timeout=20)
        assert r.status_code == 200, r.text
        d = r.json()
        si = d["sleeping_infra"]
        for k in ("domain", "total_findings", "counts_by_severity", "findings", "note"):
            assert k in si, f"missing {k}"
        assert isinstance(si["findings"], list)
        assert isinstance(si["counts_by_severity"], dict)
        assert si["domain"] == "example.com"
        # Seeded dev.example.com + marketing.example.com → at least one finding expected
        assert si["total_findings"] >= 1
        # Verify a finding shape
        f0 = si["findings"][0]
        for k in ("asset", "type", "reason", "severity"):
            assert k in f0, f"missing finding key {k}"


# -----------------------------------------------------------------
# 7. Organizational Mapping (AI)
# -----------------------------------------------------------------
class TestOrgMap:
    def test_org_map_schema_and_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/org-map"
        r = client.get(url, headers=h, timeout=90)  # AI can take 20-40s
        assert r.status_code == 200, r.text
        d = r.json()
        om = d["org_map"]
        for k in ("signals_used", "organization_name", "org_type",
                  "key_people", "high_exposure_targets", "attack_surface_summary"):
            assert k in om, f"missing {k}"
        assert isinstance(om["key_people"], list)
        assert len(om["key_people"]) <= 10
        assert isinstance(om["high_exposure_targets"], list)
        assert len(om["high_exposure_targets"]) <= 5

        # Cache check
        r2 = client.get(url, headers=h, timeout=15)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True


# -----------------------------------------------------------------
# 8. Dev Style Profiler (AI)
# -----------------------------------------------------------------
class TestDevProfile:
    def test_dev_profile_schema_and_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/dev-profile"
        r = client.get(url, headers=h, timeout=90)
        assert r.status_code == 200, r.text
        d = r.json()
        dp = d["dev_profile"]
        for k in ("maturity_score", "maturity_label", "signals", "team_profile",
                  "logic_bug_probability", "bug_hunting_verdict",
                  "recommended_focus_areas"):
            assert k in dp, f"missing {k}"
        assert 0 <= dp["maturity_score"] <= 100
        assert dp["maturity_label"] in ("maduro", "estándar", "descuidado", "caótico")
        assert isinstance(dp["signals"], dict)
        assert isinstance(dp["recommended_focus_areas"], list)

        r2 = client.get(url, headers=h, timeout=15)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True


# -----------------------------------------------------------------
# 9. Regression smoke: previously green endpoints still 200
# -----------------------------------------------------------------
class TestRegressionSmoke:
    @pytest.mark.parametrize("path", [
        "supply-chain", "idor", "logic-flow", "reverse-ip",
        "github-miner", "bot-resistance",
    ])
    def test_previous_endpoints_still_200(self, client, pro_scan, path):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/{path}"
        r = client.get(url, headers=h, timeout=90)
        assert r.status_code == 200, f"{path} → {r.status_code}: {r.text[:200]}"

"""Backend tests for iteration-5 batch — NOCTUA.osint bug-bounty toolkit + collab features.

Covers:
- GET  /api/scans/{id}/param-miner            (+cache)
- GET  /api/scans/{id}/cloud-config           (+cache)
- GET  /api/scans/{id}/api-audit              (+cache)
- GET  /api/scans/{id}/diff                   (no history -> available:false)
- GET  /api/scans/{id}/diff?vs={other}        (same domain -> diff, different domain -> 400)
- GET  /api/scans/history/{domain}            (sorted desc)
- POST /api/scans/{id}/auto-tag               (+cache)  [LLM]
- POST /api/scans/{id}/tags                   (only ontology tags kept)
- GET  /api/scans/{id}/correlate              (+cache, flagged_by_someone cross-user)
- POST /api/scans/{id}/flag                   (flag flag persists cross-user)
- GET  /api/scans/{id}/version-track          (no history -> empty)
- CRUD /api/bounty/reports                    (POST, GET, PATCH, DELETE, filters, 400/404)
- GET  /api/scans                             (tags, flagged, primary_category surfaced)
- schedules._detect_changes -> new_subdomains alert has '🎯 NUEVO ACTIVO' prefix + severity=high
- Regressions: attack-path (persona), oracle, dna, brand-guardian, phishing-sim, poc,
  /predict, /apt-personas, js-miner, ct-logs, shodan-deep, /settings/preferences,
  /settings/telegram, /public/stats, /public/takeover-check.
"""
import os
import uuid
import time
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


# ---------------------------------------------------------------------------
# Shared seeding helper (Mongo direct so we don't wait 60-90s per scan)
# ---------------------------------------------------------------------------
def _seed_scan(mongo, user_id: str, domain: str = "example.com",
               *, ip: str = "93.184.216.34", scan_id: str = None,
               created_at: str = None, ports=None, subdomains=None,
               tech_versions=None, ssl_fp: str = None,
               ssl_org: str = "DigiCert Inc") -> str:
    scan_id = scan_id or f"scan_test_{uuid.uuid4().hex[:10]}"
    ports = ports if ports is not None else [
        {"port": 80, "service": "http"},
        {"port": 443, "service": "https"},
    ]
    subs = subdomains if subdomains is not None else [
        {"subdomain": f"www.{domain}", "ips": [ip]},
        {"subdomain": f"mail.{domain}", "ips": [ip]},
    ]
    tech = []
    if tech_versions:
        libs = [{"name": n, "version": v} for n, v in tech_versions.items()]
        tech.append({"hostname": domain, "cms": [], "frameworks": [], "libraries": libs,
                     "missing_critical": [], "is_protected": False})
    else:
        tech.append({"hostname": domain, "cms": [], "frameworks": [], "libraries": [],
                     "missing_critical": ["hsts", "csp"], "is_protected": False})

    fake_scan = {
        "domain": domain,
        "ip": {"ip": ip},
        "dns": {"A": [ip], "MX": [], "TXT": [], "NS": ["a.iana-servers.net"]},
        "subdomains": {"found": subs},
        "ports": {"open_ports": ports},
        "ssl": {"success": True, "issuer": {"organizationName": ssl_org},
                "tls_version": "TLSv1.3", "not_after": "Jan 15 12:00:00 2026 GMT",
                **({"fingerprint": ssl_fp} if ssl_fp else {})},
        "https_headers": {"success": True, "headers": {}},
        "tech_analysis": tech,
        "security": {"basic": {"score": 60, "items": []},
                     "medium": {"score": 40, "items": []},
                     "advanced": {"score": 30, "items": []}},
    }
    mongo.scans.insert_one({
        "scan_id": scan_id,
        "user_id": user_id,
        "domain": domain,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "extended_ports": False,
        "result": fake_scan,
    })
    return scan_id


@pytest.fixture
def pro_scan(mongo, pro_user):
    scan_id = _seed_scan(mongo, pro_user["user_id"], domain="example.com")
    yield {"scan_id": scan_id, **pro_user}
    mongo.scans.delete_many({"scan_id": scan_id})


@pytest.fixture
def free_scan(mongo, free_user):
    scan_id = _seed_scan(mongo, free_user["user_id"], domain="example.com")
    yield {"scan_id": scan_id, **free_user}
    mongo.scans.delete_many({"scan_id": scan_id})


# ---------------------------------------------------------------------------
# 1. Parameter Miner
# ---------------------------------------------------------------------------
class TestParamMiner:
    def test_param_miner_and_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/param-miner"
        r1 = client.get(url, headers=h, timeout=60)
        assert r1.status_code == 200, r1.text
        d = r1.json()
        assert "param_miner" in d
        pm = d["param_miner"]
        for k in ("domain", "total_discovered", "counts_by_priority",
                  "candidates", "note"):
            assert k in pm, f"missing key {k}"
        assert pm["domain"] == "example.com"
        assert isinstance(pm["candidates"], list)
        for lvl in ("critical", "high", "medium"):
            assert lvl in pm["counts_by_priority"]
        # Wordlist seeds ensure candidates > 0
        assert pm["total_discovered"] >= 10
        for c in pm["candidates"][:5]:
            for k in ("name", "priority", "sources", "candidate_url"):
                assert k in c
        assert d.get("cached") is False

        r2 = client.get(url, headers=h, timeout=15)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True


# ---------------------------------------------------------------------------
# 2. Cloud & Dev Config Hunter
# ---------------------------------------------------------------------------
class TestCloudConfig:
    def test_cloud_config_and_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/cloud-config"
        r1 = client.get(url, headers=h, timeout=120)
        assert r1.status_code == 200, r1.text
        d = r1.json()
        assert "cloud_config" in d
        cc = d["cloud_config"]
        for k in ("domain", "targets_probed", "paths_probed",
                  "total_findings", "counts_by_severity", "findings"):
            assert k in cc, f"missing {k}"
        assert cc["domain"] == "example.com"
        assert isinstance(cc["findings"], list)
        assert cc["paths_probed"] >= 20
        assert d.get("cached") is False

        r2 = client.get(url, headers=h, timeout=15)
        assert r2.json().get("cached") is True


# ---------------------------------------------------------------------------
# 3. API Auditor
# ---------------------------------------------------------------------------
class TestAPIAudit:
    def test_api_audit_and_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/api-audit"
        r1 = client.get(url, headers=h, timeout=120)
        assert r1.status_code == 200, r1.text
        d = r1.json()
        assert "api_audit" in d
        aa = d["api_audit"]
        for k in ("domain", "active_api_bases", "active_bases_count",
                  "sensitive_endpoints_probed", "findings_total",
                  "counts_by_severity", "findings", "graphql"):
            assert k in aa, f"missing {k}"
        assert aa["domain"] == "example.com"
        assert isinstance(aa["findings"], list)
        assert isinstance(aa["active_api_bases"], list)
        assert d.get("cached") is False

        r2 = client.get(url, headers=h, timeout=15)
        assert r2.json().get("cached") is True


# ---------------------------------------------------------------------------
# 4. Diff — no history / same domain / different domain
# ---------------------------------------------------------------------------
class TestDiff:
    def test_diff_no_history(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/diff"
        r = client.get(url, headers=h, timeout=30)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("available") is False
        assert "reason" in d
        assert "escaneo anterior" in d["reason"].lower()

    def test_diff_same_domain(self, client, mongo, pro_user):
        """Seed 2 scans of the SAME domain, verify diff picks up the change."""
        uid = pro_user["user_id"]
        h = _auth(pro_user["token"])
        older_at = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        newer_at = datetime.now(timezone.utc).isoformat()

        # Previous scan: only port 80
        prev_id = _seed_scan(mongo, uid, domain="diff-example.local",
                             created_at=older_at,
                             ports=[{"port": 80, "service": "http"}],
                             subdomains=[{"subdomain": "www.diff-example.local",
                                          "ips": ["1.2.3.4"]}])
        # Current scan: adds port 22 (should raise severity to critical)
        curr_id = _seed_scan(mongo, uid, domain="diff-example.local",
                             created_at=newer_at,
                             ports=[{"port": 80, "service": "http"},
                                    {"port": 22, "service": "ssh"}],
                             subdomains=[{"subdomain": "www.diff-example.local",
                                          "ips": ["1.2.3.4"]},
                                         {"subdomain": "new.diff-example.local",
                                          "ips": ["1.2.3.5"]}])
        try:
            url = f"{BASE_URL}/api/scans/{curr_id}/diff"
            # Auto (no vs) — picks the previous scan
            r1 = client.get(url, headers=h, timeout=30)
            assert r1.status_code == 200, r1.text
            d = r1.json()
            assert d.get("available") is True
            diff = d["diff"]
            for k in ("changed", "severity", "ports", "subdomains", "tech",
                      "ip_change", "tls_change", "security_headers"):
                assert k in diff, f"missing {k}"
            assert diff["changed"] is True
            assert 22 in diff["ports"]["added"]
            assert diff["ports"]["prev_count"] == 1
            assert diff["ports"]["current_count"] == 2
            assert "new.diff-example.local" in diff["subdomains"]["added"]
            # Port 22 is on the dangerous list -> severity critical
            assert diff["severity"] == "critical"

            # Explicit vs param
            r2 = client.get(url, headers=h, params={"vs": prev_id}, timeout=30)
            assert r2.status_code == 200
            assert r2.json()["available"] is True

        finally:
            mongo.scans.delete_many({"scan_id": {"$in": [prev_id, curr_id]}})

    def test_diff_different_domain_400(self, client, mongo, pro_user):
        uid = pro_user["user_id"]
        h = _auth(pro_user["token"])
        a = _seed_scan(mongo, uid, domain="alpha.local")
        b = _seed_scan(mongo, uid, domain="beta.local")
        try:
            r = client.get(f"{BASE_URL}/api/scans/{a}/diff",
                           headers=h, params={"vs": b}, timeout=15)
            assert r.status_code == 400, r.text
        finally:
            mongo.scans.delete_many({"scan_id": {"$in": [a, b]}})


# ---------------------------------------------------------------------------
# 5. Scan history by domain
# ---------------------------------------------------------------------------
class TestScanHistory:
    def test_history_returns_scans_desc(self, client, mongo, pro_user):
        uid = pro_user["user_id"]
        h = _auth(pro_user["token"])
        # Two scans of same domain + a third of a different domain
        older = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        newer = datetime.now(timezone.utc).isoformat()
        a1 = _seed_scan(mongo, uid, domain="hist.local", created_at=older)
        a2 = _seed_scan(mongo, uid, domain="hist.local", created_at=newer)
        b = _seed_scan(mongo, uid, domain="other.local")
        try:
            r = client.get(f"{BASE_URL}/api/scans/history/hist.local",
                           headers=h, timeout=15)
            assert r.status_code == 200
            d = r.json()
            assert d["domain"] == "hist.local"
            ids = [s["scan_id"] for s in d["scans"]]
            assert a1 in ids and a2 in ids
            assert b not in ids
            # Verify desc order
            ts = [s["created_at"] for s in d["scans"]]
            assert ts == sorted(ts, reverse=True)
        finally:
            mongo.scans.delete_many({"scan_id": {"$in": [a1, a2, b]}})


# ---------------------------------------------------------------------------
# 6. Auto-tag + manual tags
# ---------------------------------------------------------------------------
class TestAutoTags:
    def test_auto_tag_and_cache(self, client, pro_scan):
        """LLM call — allow up to 90s."""
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/auto-tag"
        r1 = client.post(url, headers=h, json={}, timeout=90)
        assert r1.status_code == 200, r1.text
        d = r1.json()
        assert "tags" in d
        assert "tag_meta" in d
        assert isinstance(d["tags"], list)
        # meta contains reasoning + confidence + heuristic_tags + ai_tags
        meta = d["tag_meta"]
        for k in ("reasoning", "confidence", "heuristic_tags", "ai_tags"):
            assert k in meta, f"missing meta key {k}"
        assert d.get("cached") is False

        # Verify tags persisted -> appear in /api/scans list
        list_r = client.get(f"{BASE_URL}/api/scans", headers=h, timeout=15)
        assert list_r.status_code == 200
        arr = list_r.json()
        entry = next((it for it in arr if it["scan_id"] == pro_scan["scan_id"]), None)
        assert entry is not None
        assert "tags" in entry
        # Second call -> cached
        r2 = client.post(url, headers=h, json={}, timeout=15)
        assert r2.status_code == 200
        assert r2.json().get("cached") is True

    def test_manual_tags_ontology_filter(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/tags"
        r = client.post(url, headers=h,
                        json={"tags": ["e-commerce", "critical-infrastructure",
                                       "not-a-real-tag", "xxx"]}, timeout=15)
        assert r.status_code == 200, r.text
        d = r.json()
        # Unknown tags are silently ignored
        assert "e-commerce" in d["tags"]
        assert "critical-infrastructure" in d["tags"]
        assert "not-a-real-tag" not in d["tags"]
        assert "xxx" not in d["tags"]


# ---------------------------------------------------------------------------
# 7. Global correlation + flag flow across users
# ---------------------------------------------------------------------------
class TestGlobalCorrelation:
    def test_correlate_and_cache(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        url = f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/correlate"
        r1 = client.get(url, headers=h, timeout=30)
        assert r1.status_code == 200, r1.text
        d = r1.json()
        assert "correlation" in d
        corr = d["correlation"]
        for k in ("domain", "total_correlations", "flagged_neighbours_count",
                  "signals_checked", "correlations", "flagged_neighbours",
                  "risk_note"):
            assert k in corr, f"missing {k}"
        assert d.get("cached") is False

        r2 = client.get(url, headers=h, timeout=15)
        assert r2.json().get("cached") is True

    def test_flag_visible_across_users(self, client, mongo, pro_user, free_user):
        """User A flags a scan sharing IP 5.5.5.5 with User B's scan.
        User B's /correlate should surface flagged_by_someone=true."""
        ip = f"5.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}"
        dom_a = f"attacker-{uuid.uuid4().hex[:6]}.local"
        dom_b = f"victim-{uuid.uuid4().hex[:6]}.local"

        # User A's scan (will be flagged)
        a_scan_id = _seed_scan(mongo, pro_user["user_id"], domain=dom_a, ip=ip)
        # User B's scan of a different domain, same IP
        b_scan_id = _seed_scan(mongo, free_user["user_id"], domain=dom_b, ip=ip)

        try:
            # 1) User A flags their scan
            r_flag = client.post(f"{BASE_URL}/api/scans/{a_scan_id}/flag",
                                 headers=_auth(pro_user["token"]),
                                 json={"flagged": True, "reason": "test malicious"},
                                 timeout=15)
            assert r_flag.status_code == 200
            assert r_flag.json()["flagged"] is True

            # 2) User B calls correlate — should see the shared IP + flagged_by_someone
            r_corr = client.get(f"{BASE_URL}/api/scans/{b_scan_id}/correlate",
                                headers=_auth(free_user["token"]),
                                timeout=30)
            assert r_corr.status_code == 200, r_corr.text
            corr = r_corr.json()["correlation"]
            # Must include a shared_ip signal for dom_a and flagged_by_someone must be True
            matches = [c for c in corr["correlations"]
                       if c["signal"] == "shared_ip" and c["asset"] == dom_a]
            assert matches, f"no shared_ip correlation for {dom_a}: {corr}"
            assert matches[0]["flagged_by_someone"] is True
            assert corr["flagged_neighbours_count"] >= 1
        finally:
            mongo.scans.delete_many({"scan_id": {"$in": [a_scan_id, b_scan_id]}})


# ---------------------------------------------------------------------------
# 8. Version tracking
# ---------------------------------------------------------------------------
class TestVersionTrack:
    def test_version_track_no_history(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        r = client.get(f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/version-track",
                       headers=h, timeout=30)
        assert r.status_code == 200, r.text
        vt = r.json()["version_track"]
        assert "downgrades" in vt
        assert "upgrades" in vt
        assert vt["downgrades"] == []

    def test_version_track_detects_rollback(self, client, mongo, pro_user):
        """Seed prev jquery 3.6.0 then current jquery 3.4.0 -> downgrade."""
        uid = pro_user["user_id"]
        h = _auth(pro_user["token"])
        older = (datetime.now(timezone.utc) - timedelta(days=4)).isoformat()
        # Previous had jquery 3.6.0
        prev_id = _seed_scan(mongo, uid, domain="vt-test.local",
                             created_at=older,
                             tech_versions={"jquery": "3.6.0"})
        # Current has jquery 3.4.0 (older)
        curr_id = _seed_scan(mongo, uid, domain="vt-test.local",
                             tech_versions={"jquery": "3.4.0"})
        try:
            r = client.get(f"{BASE_URL}/api/scans/{curr_id}/version-track",
                           headers=h, timeout=30)
            assert r.status_code == 200
            vt = r.json()["version_track"]
            assert vt.get("downgrade_alert") is True
            products = [d["product"] for d in vt["downgrades"]]
            assert "jquery" in products
        finally:
            mongo.scans.delete_many({"scan_id": {"$in": [prev_id, curr_id]}})


# ---------------------------------------------------------------------------
# 9. Bug bounty report CRUD
# ---------------------------------------------------------------------------
class TestBountyReports:
    def test_full_crud(self, client, mongo, pro_scan):
        h = _auth(pro_scan["token"])
        finding_key = f"takeover:foo-{uuid.uuid4().hex[:6]}.example.com"
        payload = {
            "scan_id": pro_scan["scan_id"],
            "finding_key": finding_key,
            "program": "H1",
            "status": "submitted",
            "notes": "test",
            "severity": "high",
        }
        # Create
        r_create = client.post(f"{BASE_URL}/api/bounty/reports", headers=h,
                               json=payload, timeout=15)
        assert r_create.status_code == 200, r_create.text
        created = r_create.json()
        assert created["finding_key"] == finding_key
        assert created["scan_id"] == pro_scan["scan_id"]
        assert created["status"] == "submitted"

        # List
        r_list = client.get(f"{BASE_URL}/api/bounty/reports", headers=h, timeout=15)
        assert r_list.status_code == 200
        d = r_list.json()
        keys = [it["finding_key"] for it in d["reports"]]
        assert finding_key in keys

        # Filter by domain
        r_dom = client.get(f"{BASE_URL}/api/bounty/reports",
                           headers=h, params={"domain": "example.com"}, timeout=15)
        assert r_dom.status_code == 200
        assert any(it["finding_key"] == finding_key for it in r_dom.json()["reports"])

        # Filter by status
        r_stat = client.get(f"{BASE_URL}/api/bounty/reports",
                            headers=h, params={"status": "submitted"}, timeout=15)
        assert r_stat.status_code == 200
        assert any(it["finding_key"] == finding_key for it in r_stat.json()["reports"])

        # PATCH
        r_patch = client.patch(
            f"{BASE_URL}/api/bounty/reports/{finding_key}",
            headers=h,
            params={"scan_id": pro_scan["scan_id"]},
            json={"status": "accepted", "notes": "resolved"},
            timeout=15,
        )
        assert r_patch.status_code == 200, r_patch.text
        assert r_patch.json()["updated"] == 1

        # Verify update
        r_after = client.get(f"{BASE_URL}/api/bounty/reports", headers=h, timeout=15)
        it = next(x for x in r_after.json()["reports"] if x["finding_key"] == finding_key)
        assert it["status"] == "accepted"
        assert it["notes"] == "resolved"

        # DELETE
        r_del = client.delete(
            f"{BASE_URL}/api/bounty/reports/{finding_key}",
            headers=h, params={"scan_id": pro_scan["scan_id"]}, timeout=15)
        assert r_del.status_code == 200
        assert r_del.json().get("deleted") is True

        # Confirm gone
        r_gone = client.get(f"{BASE_URL}/api/bounty/reports", headers=h, timeout=15)
        assert all(x["finding_key"] != finding_key for x in r_gone.json()["reports"])

    def test_invalid_status_400(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        payload = {"scan_id": pro_scan["scan_id"],
                   "finding_key": f"bad:{uuid.uuid4().hex[:6]}",
                   "status": "totally-invalid"}
        r = client.post(f"{BASE_URL}/api/bounty/reports", headers=h,
                        json=payload, timeout=15)
        assert r.status_code == 400, r.text

    def test_someone_elses_scan_404(self, client, mongo, pro_user, free_user):
        # scan owned by USER A
        other_scan = _seed_scan(mongo, pro_user["user_id"], domain="owned-by-a.local")
        try:
            # try to file report as USER B
            h = _auth(free_user["token"])
            r = client.post(f"{BASE_URL}/api/bounty/reports", headers=h,
                            json={"scan_id": other_scan, "finding_key": "x:y",
                                  "status": "submitted"}, timeout=15)
            assert r.status_code == 404, r.text
        finally:
            mongo.scans.delete_many({"scan_id": other_scan})


# ---------------------------------------------------------------------------
# 10. /api/scans now surfaces tags/flagged/primary_category
# ---------------------------------------------------------------------------
class TestListScansEnrichment:
    def test_tags_flagged_surfaced(self, client, mongo, pro_user):
        uid = pro_user["user_id"]
        h = _auth(pro_user["token"])
        sid = _seed_scan(mongo, uid, domain="enriched.local")
        try:
            # Add tags + flag directly in Mongo (avoid an LLM call)
            mongo.scans.update_one({"scan_id": sid},
                                   {"$set": {"tags": ["saas", "cloud-native"],
                                             "primary_category": "saas",
                                             "flagged": True}})
            r = client.get(f"{BASE_URL}/api/scans", headers=h, timeout=15)
            assert r.status_code == 200
            it = next(x for x in r.json() if x["scan_id"] == sid)
            assert it["tags"] == ["saas", "cloud-native"]
            assert it["primary_category"] == "saas"
            assert it["flagged"] is True
        finally:
            mongo.scans.delete_many({"scan_id": sid})


# ---------------------------------------------------------------------------
# 11. Schedules — new_subdomains alert prefix + severity
# ---------------------------------------------------------------------------
class TestSchedulesDetectChanges:
    def test_new_subdomains_alert_high_severity(self):
        from importlib import util
        import sys
        # Ensure /app/backend is on path
        backend_path = str(Path(__file__).resolve().parents[1])
        if backend_path not in sys.path:
            sys.path.insert(0, backend_path)
        from schedules import _detect_changes  # noqa: E402
        prev = {"subdomains": {"found": [{"subdomain": "a.x.com"}]}}
        curr = {"subdomains": {"found": [{"subdomain": "a.x.com"},
                                          {"subdomain": "new.x.com"}]}}
        alerts = _detect_changes(prev, curr, ["new_subdomains"])
        assert any(a["type"] == "new_subdomains" for a in alerts)
        sub = next(a for a in alerts if a["type"] == "new_subdomains")
        assert sub["severity"] == "high"
        assert "🎯 NUEVO ACTIVO" in sub["title"]


# ---------------------------------------------------------------------------
# 12. Regressions
# ---------------------------------------------------------------------------
class TestRegressions:
    def test_apt_personas(self, client):
        r = client.get(f"{BASE_URL}/api/apt-personas", timeout=15)
        assert r.status_code == 200
        assert "personas" in r.json()

    def test_public_stats(self, client):
        r = client.get(f"{BASE_URL}/api/public/stats", timeout=15)
        assert r.status_code == 200
        for k in ("scans_this_month", "total_scans", "takeovers_detected",
                  "active_users"):
            assert k in r.json()

    def test_public_takeover_check(self, client):
        # GET-based public endpoint with ?domain=
        r = client.get(f"{BASE_URL}/api/public/takeover-check",
                       params={"domain": "example.com"}, timeout=30)
        assert r.status_code in (200, 400, 429), r.text

    def test_settings_preferences(self, client, free_user):
        h = _auth(free_user["token"])
        r = client.get(f"{BASE_URL}/api/settings/preferences", headers=h, timeout=15)
        assert r.status_code == 200

    def test_telegram_get(self, client, free_user):
        h = _auth(free_user["token"])
        r = client.get(f"{BASE_URL}/api/settings/telegram", headers=h, timeout=15)
        assert r.status_code == 200

    def test_shodan_deep_no_key_ok(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        r = client.get(f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/shodan-deep",
                       headers=h, timeout=60)
        assert r.status_code == 200

    def test_js_miner(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        r = client.get(f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/js-miner",
                       headers=h, timeout=60)
        assert r.status_code == 200
        assert "js_miner" in r.json()

    def test_dna(self, client, pro_scan):
        h = _auth(pro_scan["token"])
        r = client.get(f"{BASE_URL}/api/scans/{pro_scan['scan_id']}/dna",
                       headers=h, timeout=60)
        assert r.status_code == 200
        assert "dna" in r.json()

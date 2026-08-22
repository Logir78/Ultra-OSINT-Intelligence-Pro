"""Iteration-6 tests — IDOR analyzer, Supply-chain (OSV.dev), Takeover fingerprints DB size,
JS Miner .map probing behavior.

Run:
    pytest /app/backend/tests/test_iteration6_bounty.py -v
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


def _seed_scan(mongo, user_id: str, domain: str, *,
               scan_id: str | None = None,
               tech: list | None = None,
               js_findings: list | None = None,
               api_audit_findings: list | None = None,
               api_audit_bases: list | None = None,
               subdomains: list | None = None,
               ip: str = "93.184.216.34") -> str:
    scan_id = scan_id or f"scan_test_{uuid.uuid4().hex[:10]}"
    result = {
        "domain": domain,
        "ip": {"ip": ip},
        "dns": {"A": [ip], "MX": [], "TXT": [], "NS": ["a.iana-servers.net"]},
        "subdomains": {"found": subdomains if subdomains is not None else [
            {"subdomain": f"www.{domain}", "ips": [ip]},
        ]},
        "ports": {"open_ports": [{"port": 80, "service": "http"},
                                  {"port": 443, "service": "https"}]},
        "ssl": {"success": True, "issuer": {"organizationName": "DigiCert"},
                "tls_version": "TLSv1.3", "not_after": "Jan 15 12:00:00 2026 GMT"},
        "https_headers": {"success": True, "headers": {}},
        "tech_analysis": tech if tech is not None else [
            {"hostname": domain, "cms": [], "frameworks": [], "libraries": [],
             "missing_critical": [], "is_protected": False}
        ],
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
        "result": result,
    }
    if js_findings is not None:
        doc["js_miner"] = {"targets_processed": 1, "counts_by_severity": {},
                            "total_findings": len(js_findings),
                            "sources": [f"https://{domain}/app.js"],
                            "findings": js_findings}
    if api_audit_findings is not None or api_audit_bases is not None:
        doc["api_audit"] = {
            "domain": domain,
            "active_api_bases": api_audit_bases or [],
            "active_bases_count": len(api_audit_bases or []),
            "sensitive_endpoints_probed": 0,
            "findings_total": len(api_audit_findings or []),
            "counts_by_severity": {},
            "findings": api_audit_findings or [],
            "graphql": {},
        }
    mongo.scans.insert_one(doc)
    return scan_id


# ============================================================================
# 1. Takeover Fingerprints — expanded DB
# ============================================================================
class TestTakeoverFingerprints:
    def test_fingerprints_count_at_least_75(self):
        """Import and count FINGERPRINTS list — must be >= 75."""
        import sys
        sys.path.insert(0, "/app/backend")
        from integrations.takeover_scanner import FINGERPRINTS
        assert isinstance(FINGERPRINTS, list)
        assert len(FINGERPRINTS) >= 75, f"expected >=75 fingerprints, got {len(FINGERPRINTS)}"
        # Basic structure sanity
        for entry in FINGERPRINTS[:5]:
            # Each entry is (service_name, cname_regex, body_regex, severity)
            assert len(entry) == 4
            assert isinstance(entry[0], str) and entry[0]
            assert isinstance(entry[3], str)

    def test_new_services_present(self):
        """Verify some of the new services listed in review (Acquia/Fly.io/Kajabi/Notion/Zoho)."""
        import sys
        sys.path.insert(0, "/app/backend")
        from integrations.takeover_scanner import FINGERPRINTS
        names = {e[0].lower() for e in FINGERPRINTS}
        # At least a couple of the newly added services should appear
        expected_any = {"acquia", "fly.io", "kajabi", "notion", "zoho",
                        "cloud foundry", "cloudfoundry"}
        matched = {n for n in names if any(x in n for x in expected_any)}
        assert matched, f"Expected new services not found. Names sample: {list(names)[:10]}"

    def test_takeover_scan_endpoint_ok(self, client, mongo, free_user):
        """Endpoint returns 200 even for a scan with no vulnerable CNAMEs."""
        scan_id = _seed_scan(mongo, free_user["user_id"], "example-notake.com",
                             subdomains=[{"subdomain": "www.example-notake.com",
                                          "ips": ["93.184.216.34"]}])
        try:
            r = client.get(f"{BASE_URL}/api/scans/{scan_id}/takeover",
                           headers=_auth(free_user["token"]), timeout=90)
            assert r.status_code == 200, r.text
            data = r.json()
            body = data.get("takeover") or data
            assert isinstance(body, dict)
            # Endpoint should surface at least a findings collection
            assert "findings" in body or "vulnerable" in body or "vulnerable_count" in body, \
                f"unexpected takeover keys: {list(body.keys())}"
        finally:
            mongo.scans.delete_many({"scan_id": scan_id})


# ============================================================================
# 2. JS Miner — .map probing
# ============================================================================
class TestJSMinerMapProbing:
    def test_discover_js_adds_map_urls(self, monkeypatch):
        """Unit test: _discover_js appends .map URLs for each .js discovered."""
        import sys, asyncio
        sys.path.insert(0, "/app/backend")
        import integrations.js_miner as jm

        html = """
        <html><body>
        <script src="/static/app.js"></script>
        <script src="/static/vendor.js"></script>
        <script>console.log('inline');</script>
        </body></html>
        """

        class FakeResp:
            def __init__(self, txt): self.text = txt; self.status_code = 200
        class FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def get(self, u, *a, **kw): return FakeResp(html)

        monkeypatch.setattr(jm.httpx, "AsyncClient", FakeClient)
        urls, inline = asyncio.get_event_loop().run_until_complete(
            jm._discover_js("example.com"))
        # Expect .js + corresponding .map urls
        assert any(u.endswith(".js") for u in urls)
        assert any(u.endswith(".map") for u in urls), f"no .map url found: {urls}"
        # Every discovered .js should have a matching .map
        js_files = {u for u in urls if u.endswith(".js")}
        map_files = {u for u in urls if u.endswith(".map")}
        assert len(map_files) >= min(2, len(js_files))

    def test_js_miner_endpoint_schema_unchanged(self, client, mongo, free_user):
        """Endpoint still returns same schema even with .map probing added."""
        scan_id = _seed_scan(mongo, free_user["user_id"], "example.com")
        try:
            r = client.get(f"{BASE_URL}/api/scans/{scan_id}/js-miner",
                           headers=_auth(free_user["token"]), timeout=90)
            assert r.status_code == 200, r.text
            body = r.json()
            jm = body.get("js_miner") or body
            for k in ("js_files_analyzed", "total_findings",
                      "counts_by_severity", "findings", "sources"):
                assert k in jm, f"missing key '{k}' in {list(jm.keys())}"
            assert isinstance(jm["findings"], list)
            assert isinstance(jm["sources"], list)
        finally:
            mongo.scans.delete_many({"scan_id": scan_id})


# ============================================================================
# 3. IDOR Analyzer
# ============================================================================
class TestIDORAnalyzer:
    def test_idor_free_user_no_findings(self, client, mongo, free_user):
        """Free user with empty scan → 200 with empty findings, not 500."""
        scan_id = _seed_scan(mongo, free_user["user_id"], "empty.local")
        try:
            r = client.get(f"{BASE_URL}/api/scans/{scan_id}/idor",
                           headers=_auth(free_user["token"]), timeout=60)
            assert r.status_code == 200, r.text
            d = r.json()
            assert "idor" in d
            idor = d["idor"]
            for k in ("endpoints_analyzed", "total_id_patterns",
                      "counts_by_risk", "findings", "ai_recommendations"):
                assert k in idor, f"missing '{k}'"
            assert idor["total_id_patterns"] == 0
            assert idor["findings"] == []
            assert d.get("cached") is False
        finally:
            mongo.scans.delete_many({"scan_id": scan_id})

    def test_idor_detects_numeric_and_uuid_patterns(self, client, mongo, free_user):
        """Seed api_audit findings with numeric + UUID URLs → verify patterns detected."""
        api_findings = [
            {"url": "https://api.example.com/api/v1/users/123", "severity": "info", "title": "u"},
            {"url": "https://api.example.com/api/v1/orders/999/details", "severity": "info", "title": "o"},
            {"url": "https://api.example.com/api/v2/profile/550e8400-e29b-41d4-a716-446655440000",
             "severity": "info", "title": "p"},
        ]
        scan_id = _seed_scan(mongo, free_user["user_id"], "idor-example.com",
                             api_audit_findings=api_findings)
        try:
            r = client.get(f"{BASE_URL}/api/scans/{scan_id}/idor",
                           headers=_auth(free_user["token"]), timeout=90)
            assert r.status_code == 200, r.text
            idor = r.json()["idor"]
            assert idor["endpoints_analyzed"] >= 3
            assert idor["total_id_patterns"] >= 3
            findings = idor["findings"]
            # Numeric IDs get ~10 variations (numeric branch), UUIDs get 3 boundaries
            numeric = [f for f in findings if f["id_type"] == "numeric"]
            uuid_f = [f for f in findings if f["id_type"] == "uuid"]
            assert numeric, "No numeric ID findings"
            assert uuid_f, "No UUID findings"
            # Numeric variations: -3..+3 (positives only if >0), 100, 1000, plus 0,1,-1
            # For value 123 → 120..126 positives, +100=223, +1000=1123, plus 0,1,-1 → 11 items
            # capped to 10 by _generate_variations[:10]
            first_num = numeric[0]
            assert 5 <= len(first_num["fuzz_ids"]) <= 12, \
                f"numeric fuzz_ids count out of range: {len(first_num['fuzz_ids'])}"
            assert len(first_num["fuzz_urls"]) <= 6, \
                f"fuzz_urls capped at 6: got {len(first_num['fuzz_urls'])}"
            # UUID exactly 3 boundary values
            first_uuid = uuid_f[0]
            assert len(first_uuid["fuzz_ids"]) == 3
            # Risk classification: 'users' → critical, 'orders' → critical, 'profile' → critical
            risks = {f["endpoint_context"]: f["risk"] for f in findings}
            assert any(v == "critical" for v in risks.values())
            # Verify fuzz_urls contain substituted values
            for fu in first_num["fuzz_urls"]:
                assert "/api/" in fu

        finally:
            mongo.scans.delete_many({"scan_id": scan_id})

    def test_idor_cached_on_second_call(self, client, mongo, free_user):
        api_findings = [{"url": "https://api.example.com/api/v1/account/42",
                         "severity": "info", "title": "a"}]
        scan_id = _seed_scan(mongo, free_user["user_id"], "idor-cache.com",
                             api_audit_findings=api_findings)
        try:
            h = _auth(free_user["token"])
            url = f"{BASE_URL}/api/scans/{scan_id}/idor"
            r1 = client.get(url, headers=h, timeout=60)
            assert r1.status_code == 200
            assert r1.json().get("cached") is False
            r2 = client.get(url, headers=h, timeout=15)
            assert r2.status_code == 200
            assert r2.json().get("cached") is True
        finally:
            mongo.scans.delete_many({"scan_id": scan_id})


# ============================================================================
# 4. Supply Chain (OSV.dev)
# ============================================================================
class TestSupplyChain:
    def test_supply_chain_no_libraries(self, client, mongo, free_user):
        """Scan with no libraries → libraries_analyzed=0, no error."""
        scan_id = _seed_scan(mongo, free_user["user_id"], "no-libs.local")
        try:
            r = client.get(f"{BASE_URL}/api/scans/{scan_id}/supply-chain",
                           headers=_auth(free_user["token"]), timeout=60)
            assert r.status_code == 200, r.text
            sc = r.json()["supply_chain"]
            assert sc["libraries_analyzed"] == 0
            assert "note" in sc
        finally:
            mongo.scans.delete_many({"scan_id": scan_id})

    def test_supply_chain_with_vulnerable_lib(self, client, mongo, free_user):
        """Seed scan with jquery 1.9.0 (known-vuln) and wordpress 4.6.0 — expect vulns.

        OSV.dev may not be reachable — degrade gracefully: assert 200 + schema.
        If OSV.dev IS reachable, assert total_vulnerabilities >= 1.
        """
        tech = [{
            "hostname": "target.local",
            "cms": [{"name": "wordpress", "version": "4.6.0"}],
            "frameworks": [],
            "libraries": [{"name": "jquery", "version": "1.9.0"}],
            "missing_critical": [], "is_protected": False,
        }]
        scan_id = _seed_scan(mongo, free_user["user_id"], "target.local", tech=tech)
        try:
            r = client.get(f"{BASE_URL}/api/scans/{scan_id}/supply-chain",
                           headers=_auth(free_user["token"]), timeout=60)
            assert r.status_code == 200, r.text
            body = r.json()
            sc = body["supply_chain"]
            # Schema
            for k in ("libraries_analyzed", "libraries_with_vulns",
                      "total_vulnerabilities", "counts_by_severity",
                      "vulnerable_libraries", "source"):
                assert k in sc, f"missing '{k}' in supply_chain keys: {list(sc.keys())}"
            assert sc["source"] == "osv.dev"
            assert sc["libraries_analyzed"] == 2
            # If OSV.dev reachable, at least jquery 1.9.0 should have known CVEs
            if sc["total_vulnerabilities"] > 0:
                vlib = sc["vulnerable_libraries"][0]
                for k in ("name", "version", "host", "ecosystem",
                          "worst_severity", "vuln_count", "vulnerabilities"):
                    assert k in vlib
                assert vlib["vuln_count"] >= 1
                assert vlib["vulnerabilities"], "vulnerabilities array empty"
                v0 = vlib["vulnerabilities"][0]
                for vk in ("id", "cves", "summary", "severity"):
                    assert vk in v0
            else:
                # Degraded — OSV unreachable; ensure graceful shape
                assert isinstance(sc["vulnerable_libraries"], list)
            assert body.get("cached") is False
        finally:
            mongo.scans.delete_many({"scan_id": scan_id})

    def test_supply_chain_cached_on_second_call(self, client, mongo, free_user):
        tech = [{"hostname": "cache.local",
                 "cms": [], "frameworks": [],
                 "libraries": [{"name": "lodash", "version": "4.17.11"}],
                 "missing_critical": [], "is_protected": False}]
        scan_id = _seed_scan(mongo, free_user["user_id"], "cache.local", tech=tech)
        try:
            url = f"{BASE_URL}/api/scans/{scan_id}/supply-chain"
            h = _auth(free_user["token"])
            r1 = client.get(url, headers=h, timeout=60)
            assert r1.status_code == 200
            assert r1.json().get("cached") is False
            r2 = client.get(url, headers=h, timeout=15)
            assert r2.status_code == 200
            assert r2.json().get("cached") is True
        finally:
            mongo.scans.delete_many({"scan_id": scan_id})

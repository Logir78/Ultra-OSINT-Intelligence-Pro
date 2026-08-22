"""Iteration 9 — RFC3161 timestamp (FreeTSA.org integration)."""
import pytest
import os
import sys
import uuid
from datetime import datetime, timezone
from conftest import BASE_URL, auth_headers as _auth

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _seed_scan(mongo, user_id, domain="example.com"):
    scan_id = f"test-{uuid.uuid4().hex[:8]}"
    mongo.scans.insert_one({
        "scan_id": scan_id, "user_id": user_id, "domain": domain,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "extended_ports": False,
        "result": {"domain": domain, "ip": {"ip": "93.184.216.34"},
                   "subdomains": {"found": []}, "ports": {"open_ports": []},
                   "ssl": {}, "https_headers": {}, "tech_analysis": []},
    })
    return scan_id


@pytest.fixture
def seeded_scan(mongo, free_user):
    sid = _seed_scan(mongo, free_user["user_id"])
    yield sid
    mongo.scans.delete_many({"scan_id": sid})


class TestRfc3161:
    def test_rfc3161_helper_direct(self):
        import asyncio
        from integrations.evidence_seal import request_rfc3161_timestamp
        digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        r = asyncio.run(request_rfc3161_timestamp(digest))
        if r.get("ok"):
            assert r["authority"] == "FreeTSA.org"
            assert r["sha256_input"] == digest
            assert r["tsr_size_bytes"] > 100
        else:
            assert "error" in r

    def test_rfc3161_helper_invalid_digest(self):
        import asyncio
        from integrations.evidence_seal import request_rfc3161_timestamp
        r = asyncio.run(request_rfc3161_timestamp("not-hex"))
        assert r.get("ok") is False
        assert "error" in r

    def test_rfc3161_endpoint_requires_auth(self, client):
        r = client.post(f"{BASE_URL}/api/scans/nonexistent/evidence-seal/timestamp")
        assert r.status_code in (401, 403)

    def test_rfc3161_endpoint_flow(self, client, free_user, seeded_scan):
        h = _auth(free_user["token"])
        r = client.post(f"{BASE_URL}/api/scans/{seeded_scan}/evidence-seal/timestamp",
                        headers=h, timeout=25)
        assert r.status_code == 200, f"Unexpected: {r.status_code} · {r.text[:200]}"
        body = r.json()
        assert "chain_hash" in body
        assert "rfc3161" in body
        tsr = body["rfc3161"]
        if tsr.get("ok"):
            assert tsr["authority"] == "FreeTSA.org"
            assert tsr["sha256_input"] == body["chain_hash"]
            assert tsr["tsr_size_bytes"] > 100
        else:
            assert "error" in tsr

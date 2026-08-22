"""Iteration 10 — Cross-user data isolation (multi-tenant security).

Verifies that User A cannot access any scan-derived resource that belongs to User B.
Covers ~35 endpoints: /scans/{id}, all /scans/{id}/* GETs and POSTs, /bounty/reports.
"""
import pytest
import uuid
from datetime import datetime, timezone
from conftest import BASE_URL, auth_headers as _auth


def _seed_scan(mongo, user_id, domain="example.com"):
    scan_id = f"iso-{uuid.uuid4().hex[:8]}"
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
def user_b(mongo):
    """A second, distinct user (uses free_user's factory pattern by direct DB insert)."""
    user_id = f"userb-{uuid.uuid4().hex[:8]}"
    email = f"{user_id}@iso.test"
    token = f"tok-{uuid.uuid4().hex}"
    mongo.users.insert_one({
        "user_id": user_id, "email": email, "name": "IsoUserB",
        "plan": "free", "created_at": datetime.now(timezone.utc).isoformat(),
    })
    mongo.user_sessions.insert_one({
        "session_token": token, "user_id": user_id,
        "expires_at": (datetime.now(timezone.utc).replace(year=2099)).isoformat(),
    })
    yield {"user_id": user_id, "email": email, "token": token}
    mongo.user_sessions.delete_many({"user_id": user_id})
    mongo.users.delete_many({"user_id": user_id})


@pytest.fixture
def scan_of_a(mongo, free_user):
    sid = _seed_scan(mongo, free_user["user_id"], domain="user-a-only.example")
    yield sid
    mongo.scans.delete_many({"scan_id": sid})


# ── Endpoints to hammer (verb, path template, needs body?) ────────────────
CROSS_USER_ENDPOINTS = [
    ("GET",  "/api/scans/{sid}",                       None),
    ("GET",  "/api/scans/{sid}/geoip",                 None),
    ("GET",  "/api/scans/{sid}/wayback",               None),
    ("GET",  "/api/scans/{sid}/intel",                 None),
    ("GET",  "/api/scans/{sid}/pdf",                   None),
    ("GET",  "/api/scans/{sid}/reputation",            None),
    ("GET",  "/api/scans/{sid}/shodan",                None),
    ("GET",  "/api/scans/{sid}/cloud",                 None),
    ("GET",  "/api/scans/{sid}/metadata",              None),
    ("GET",  "/api/scans/{sid}/takeover",              None),
    ("GET",  "/api/scans/{sid}/pastes",                None),
    ("GET",  "/api/scans/{sid}/threat-intel",          None),
    ("GET",  "/api/scans/{sid}/js-miner",              None),
    ("GET",  "/api/scans/{sid}/ct-logs",               None),
    ("GET",  "/api/scans/{sid}/shodan-deep",           None),
    ("GET",  "/api/scans/{sid}/dna",                   None),
    ("GET",  "/api/scans/{sid}/risk-oracle",           None),
    ("GET",  "/api/scans/{sid}/brand-guardian",        None),
    ("GET",  "/api/scans/{sid}/poc",                   None),
    ("GET",  "/api/scans/{sid}/param-miner",           None),
    ("GET",  "/api/scans/{sid}/cloud-config",          None),
    ("GET",  "/api/scans/{sid}/api-audit",             None),
    ("GET",  "/api/scans/{sid}/idor",                  None),
    ("GET",  "/api/scans/{sid}/supply-chain",          None),
    ("GET",  "/api/scans/{sid}/logic-flow",            None),
    ("GET",  "/api/scans/{sid}/reverse-ip",            None),
    ("GET",  "/api/scans/{sid}/github-miner",          None),
    ("GET",  "/api/scans/{sid}/bot-resistance",        None),
    ("GET",  "/api/scans/{sid}/jarm",                  None),
    ("GET",  "/api/scans/{sid}/honeypot",              None),
    ("GET",  "/api/scans/{sid}/evidence-seal",         None),
    ("POST", "/api/scans/{sid}/evidence-seal/timestamp", {}),
    ("GET",  "/api/scans/{sid}/sleeping-infra",        None),
    ("GET",  "/api/scans/{sid}/org-map",               None),
    ("GET",  "/api/scans/{sid}/dev-profile",           None),
    ("POST", "/api/scans/{sid}/attack-path",           {"apt_persona": "none"}),
    ("POST", "/api/scans/{sid}/phishing-sim",          {}),
    ("POST", "/api/scans/{sid}/predict",               {}),
    ("POST", "/api/scans/{sid}/auto-tag",              {}),
    ("POST", "/api/scans/{sid}/tags",                  {"tags": ["saas"]}),
    ("POST", "/api/scans/{sid}/flag",                  {"flagged": True}),
    ("GET",  "/api/scans/{sid}/version-track",         None),
    ("GET",  "/api/scans/{sid}/correlate",             None),
    ("GET",  "/api/scans/{sid}/diff",                  None),
    ("DELETE", "/api/scans/{sid}",                     None),
]


class TestCrossUserIsolation:
    """User B must NEVER be able to read/mutate User A's scan-derived resources."""

    @pytest.mark.parametrize("verb,path,body", CROSS_USER_ENDPOINTS,
                             ids=[f"{v}_{p.split('/')[-1] or 'root'}" for v, p, _ in CROSS_USER_ENDPOINTS])
    def test_user_b_cannot_access_user_a_scan_resource(
            self, client, user_b, scan_of_a, verb, path, body):
        h = _auth(user_b["token"])
        url = f"{BASE_URL}{path.format(sid=scan_of_a)}"
        if verb == "GET":
            r = client.get(url, headers=h, timeout=8)
        elif verb == "POST":
            r = client.post(url, headers=h, json=body, timeout=8)
        elif verb == "DELETE":
            r = client.delete(url, headers=h, timeout=8)
        # Must be 404 (or 401/403) — never 200 for another user's scan
        assert r.status_code in (401, 403, 404), (
            f"ISOLATION LEAK: {verb} {path} returned {r.status_code} for User B accessing User A's scan · body={r.text[:200]}"
        )

    def test_list_scans_never_returns_other_users_scans(self, client, user_b, scan_of_a, free_user):
        """GET /api/scans must only return the caller's scans."""
        # User B lists — must NOT contain scan_of_a
        r = client.get(f"{BASE_URL}/api/scans", headers=_auth(user_b["token"]), timeout=6)
        assert r.status_code == 200
        ids_b = {s["scan_id"] for s in r.json()}
        assert scan_of_a not in ids_b, "ISOLATION LEAK: User B sees User A's scan in list"
        # User A lists — must contain their own
        r = client.get(f"{BASE_URL}/api/scans", headers=_auth(free_user["token"]), timeout=6)
        assert r.status_code == 200
        ids_a = {s["scan_id"] for s in r.json()}
        assert scan_of_a in ids_a

    def test_history_endpoint_scoped_to_user(self, client, user_b, scan_of_a, free_user):
        """GET /api/scans/history/{domain} must be per-user."""
        r = client.get(f"{BASE_URL}/api/scans/history/user-a-only.example",
                       headers=_auth(user_b["token"]), timeout=6)
        assert r.status_code == 200
        assert r.json().get("count", 0) == 0, "User B sees User A's domain history"
        # User A does see it
        r = client.get(f"{BASE_URL}/api/scans/history/user-a-only.example",
                       headers=_auth(free_user["token"]), timeout=6)
        assert r.status_code == 200
        assert r.json().get("count", 0) >= 1

    def test_bounty_reports_isolated(self, client, mongo, user_b, free_user, scan_of_a):
        """Bug bounty reports are per-user; User B can't see User A's."""
        # User A creates a report
        r = client.post(f"{BASE_URL}/api/bounty/reports",
                        headers=_auth(free_user["token"]),
                        json={"scan_id": scan_of_a,
                              "finding_key": "takeover:leak.example",
                              "status": "submitted"},
                        timeout=6)
        assert r.status_code == 200, f"Setup failed: {r.text[:200]}"
        # User B lists — must see nothing
        r = client.get(f"{BASE_URL}/api/bounty/reports",
                       headers=_auth(user_b["token"]), timeout=6)
        assert r.status_code == 200
        assert r.json().get("count", 0) == 0, "ISOLATION LEAK: bounty reports"
        # User B tries to PATCH User A's finding_key
        r = client.patch(f"{BASE_URL}/api/bounty/reports/takeover:leak.example",
                         headers=_auth(user_b["token"]),
                         json={"status": "accepted"}, timeout=6)
        assert r.status_code == 404, "User B modified User A's report"
        # Cleanup
        mongo.bounty_reports.delete_many({"user_id": free_user["user_id"]})

    def test_settings_endpoints_isolated(self, client, user_b, free_user):
        """API keys, preferences, telegram: per-user isolation via session."""
        # User A saves a preference
        r = client.post(f"{BASE_URL}/api/settings/preferences",
                        headers=_auth(free_user["token"]),
                        json={"risk_threshold": 88, "notes": "user-a-secret-note"},
                        timeout=6)
        assert r.status_code == 200
        # User B reads their prefs — must NOT see user-a-secret-note
        r = client.get(f"{BASE_URL}/api/settings/preferences",
                       headers=_auth(user_b["token"]), timeout=6)
        assert r.status_code == 200
        assert "user-a-secret-note" not in (r.json().get("notes") or ""), \
            "ISOLATION LEAK: preferences"

    def test_unauthenticated_scan_endpoint_returns_401(self, client, scan_of_a):
        """No token = no access to scan-derived data."""
        for verb, path, body in CROSS_USER_ENDPOINTS[:5]:
            url = f"{BASE_URL}{path.format(sid=scan_of_a)}"
            r = client.get(url, timeout=5) if verb == "GET" else (
                client.post(url, json=body or {}, timeout=5) if verb == "POST"
                else client.delete(url, timeout=5))
            assert r.status_code in (401, 403), \
                f"UNAUTH LEAK: {verb} {path} returned {r.status_code}"

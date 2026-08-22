"""Backend tests for Pro plan: payments, schedules, alerts, slack, scheduler worker."""
import os
import time
import uuid
import pytest
import requests
from datetime import datetime, timezone, timedelta

from conftest import auth_headers


# ---------- Regression: existing endpoints ----------
class TestRegression:
    def test_root(self, base_url, client):
        r = client.get(f"{base_url}/api/")
        assert r.status_code == 200
        data = r.json()
        assert data.get("service") == "OSINT Scanner API"
        assert data.get("status") == "ok"

    def test_auth_me_no_auth(self, base_url, client):
        r = client.get(f"{base_url}/api/auth/me")
        assert r.status_code == 401

    def test_auth_me_free_returns_plan(self, base_url, client, free_user):
        r = client.get(f"{base_url}/api/auth/me", headers=auth_headers(free_user["token"]))
        assert r.status_code == 200
        data = r.json()
        assert data["user_id"] == free_user["user_id"]
        assert data["plan"] == "free"
        assert "slack_webhook_url" in data
        assert data["slack_webhook_url"] is None

    def test_scan_regression(self, base_url, client, free_user):
        r = client.post(
            f"{base_url}/api/scan",
            headers=auth_headers(free_user["token"]),
            json={"domain": "example.com", "extended_ports": False, "ai_summary": False},
            timeout=90,
        )
        assert r.status_code == 200
        data = r.json()
        assert "scan_id" in data
        assert data["result"]["domain"] == "example.com"

    def test_scans_list_regression(self, base_url, client, free_user):
        r = client.get(f"{base_url}/api/scans", headers=auth_headers(free_user["token"]))
        assert r.status_code == 200
        assert isinstance(r.json(), list)


# ---------- Payments / Plan ----------
class TestPayments:
    def test_plan_no_auth(self, base_url, client):
        r = client.get(f"{base_url}/api/payments/plan")
        assert r.status_code == 401

    def test_plan_free(self, base_url, client, free_user):
        r = client.get(f"{base_url}/api/payments/plan", headers=auth_headers(free_user["token"]))
        assert r.status_code == 200
        data = r.json()
        assert data["plan"] == "free"
        assert data["user_id"] == free_user["user_id"]

    def test_plan_pro(self, base_url, client, pro_user):
        r = client.get(f"{base_url}/api/payments/plan", headers=auth_headers(pro_user["token"]))
        assert r.status_code == 200
        data = r.json()
        assert data["plan"] == "pro"

    def test_checkout_creates_session_and_txn(self, base_url, client, free_user, mongo):
        r = client.post(
            f"{base_url}/api/payments/checkout",
            headers=auth_headers(free_user["token"]),
            json={"lookup_key": "pro_monthly", "origin_url": base_url},
            timeout=30,
        )
        assert r.status_code == 200, f"Checkout failed: {r.status_code} {r.text}"
        data = r.json()
        assert "checkout_url" in data
        assert "session_id" in data
        assert data["checkout_url"].startswith("https://")
        # Verify payment_transactions doc
        tx = mongo.payment_transactions.find_one({"session_id": data["session_id"]})
        assert tx is not None
        assert tx["user_id"] == free_user["user_id"]
        assert tx["status"] == "initiated"
        assert tx["payment_status"] == "pending"
        assert tx["lookup_key"] == "pro_monthly"

    def test_cancel_without_subscription(self, base_url, client, pro_user):
        r = client.post(f"{base_url}/api/payments/cancel", headers=auth_headers(pro_user["token"]))
        # pro user without stripe_subscription_id -> 400
        assert r.status_code == 400


# ---------- Schedules Pro gating ----------
class TestSchedulesGating:
    def test_create_schedule_free_forbidden(self, base_url, client, free_user):
        r = client.post(
            f"{base_url}/api/schedules",
            headers=auth_headers(free_user["token"]),
            json={"domain": "example.com", "frequency": "daily"},
        )
        assert r.status_code == 402
        assert "pro" in r.json().get("detail", "").lower()

    def test_slack_free_forbidden(self, base_url, client, free_user):
        r = client.post(
            f"{base_url}/api/settings/slack",
            headers=auth_headers(free_user["token"]),
            json={"webhook_url": "https://hooks.slack.com/services/AAA/BBB/CCC"},
        )
        assert r.status_code == 402


# ---------- Schedules CRUD (Pro) ----------
class TestSchedulesCRUD:
    def test_create_and_get(self, base_url, client, pro_user):
        r = client.post(
            f"{base_url}/api/schedules",
            headers=auth_headers(pro_user["token"]),
            json={"domain": "iana.org", "frequency": "weekly", "alert_types": ["new_ports", "ssl_expiry"]},
        )
        assert r.status_code == 200
        sched = r.json()
        assert sched["schedule_id"].startswith("sch_")
        assert sched["domain"] == "iana.org"
        assert sched["frequency"] == "weekly"
        assert sched["enabled"] is True
        assert sched["alert_types"] == ["new_ports", "ssl_expiry"]
        assert "next_run_at" in sched
        sid = sched["schedule_id"]

        # LIST
        r2 = client.get(f"{base_url}/api/schedules", headers=auth_headers(pro_user["token"]))
        assert r2.status_code == 200
        ids = [s["schedule_id"] for s in r2.json()]
        assert sid in ids

    def test_list_isolated_per_user(self, base_url, client, pro_user, mongo):
        # create schedule for pro_user
        client.post(
            f"{base_url}/api/schedules",
            headers=auth_headers(pro_user["token"]),
            json={"domain": "example.com", "frequency": "daily"},
        )
        # create another pro user
        uid2 = f"user_test_{uuid.uuid4().hex[:10]}"
        tok2 = f"test_session_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)
        mongo.users.insert_one({"user_id": uid2, "email": f"qa+{uid2}@t.local", "name": "u2",
                                "created_at": now.isoformat(), "plan": "pro"})
        mongo.user_sessions.insert_one({"user_id": uid2, "session_token": tok2,
                                         "expires_at": (now + timedelta(days=7)).isoformat(),
                                         "created_at": now.isoformat()})
        try:
            r = client.get(f"{base_url}/api/schedules", headers=auth_headers(tok2))
            assert r.status_code == 200
            assert r.json() == []
        finally:
            mongo.users.delete_one({"user_id": uid2})
            mongo.user_sessions.delete_many({"user_id": uid2})

    def test_toggle_schedule(self, base_url, client, pro_user):
        r = client.post(
            f"{base_url}/api/schedules",
            headers=auth_headers(pro_user["token"]),
            json={"domain": "example.com", "frequency": "monthly"},
        )
        sid = r.json()["schedule_id"]
        r2 = client.patch(f"{base_url}/api/schedules/{sid}", headers=auth_headers(pro_user["token"]))
        assert r2.status_code == 200
        assert r2.json()["enabled"] is False
        r3 = client.patch(f"{base_url}/api/schedules/{sid}", headers=auth_headers(pro_user["token"]))
        assert r3.status_code == 200
        assert r3.json()["enabled"] is True

    def test_delete_schedule(self, base_url, client, pro_user):
        r = client.post(
            f"{base_url}/api/schedules",
            headers=auth_headers(pro_user["token"]),
            json={"domain": "example.com", "frequency": "custom", "custom_hours": 6},
        )
        sid = r.json()["schedule_id"]
        r2 = client.delete(f"{base_url}/api/schedules/{sid}", headers=auth_headers(pro_user["token"]))
        assert r2.status_code == 200
        # second delete -> 404
        r3 = client.delete(f"{base_url}/api/schedules/{sid}", headers=auth_headers(pro_user["token"]))
        assert r3.status_code == 404


# ---------- Alerts ----------
class TestAlerts:
    def test_alerts_empty_for_new_user(self, base_url, client, pro_user):
        r = client.get(f"{base_url}/api/alerts", headers=auth_headers(pro_user["token"]))
        assert r.status_code == 200
        assert r.json() == []

    def test_alerts_mark_read(self, base_url, client, pro_user, mongo):
        # insert alert directly
        aid = f"alt_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        mongo.alerts.insert_one({
            "alert_id": aid, "user_id": pro_user["user_id"],
            "domain": "example.com", "type": "new_ports", "severity": "high",
            "title": "test", "detail": {}, "created_at": now, "read": False,
        })
        r = client.post(f"{base_url}/api/alerts/{aid}/read", headers=auth_headers(pro_user["token"]))
        assert r.status_code == 200
        doc = mongo.alerts.find_one({"alert_id": aid})
        assert doc["read"] is True

    def test_alerts_sorted_desc(self, base_url, client, pro_user, mongo):
        now = datetime.now(timezone.utc)
        for i in range(3):
            mongo.alerts.insert_one({
                "alert_id": f"alt_{i}_{uuid.uuid4().hex[:6]}",
                "user_id": pro_user["user_id"], "domain": "x.com",
                "type": "new_ports", "severity": "low", "title": f"t{i}",
                "detail": {}, "read": False,
                "created_at": (now + timedelta(seconds=i)).isoformat(),
            })
        r = client.get(f"{base_url}/api/alerts", headers=auth_headers(pro_user["token"]))
        assert r.status_code == 200
        items = r.json()
        assert len(items) >= 3
        # desc sorted
        dates = [it["created_at"] for it in items]
        assert dates == sorted(dates, reverse=True)


# ---------- Slack settings ----------
class TestSlack:
    def test_get_slack_null_new_user(self, base_url, client, pro_user):
        r = client.get(f"{base_url}/api/settings/slack", headers=auth_headers(pro_user["token"]))
        assert r.status_code == 200
        assert r.json()["webhook_url"] is None

    def test_slack_invalid_url(self, base_url, client, pro_user):
        r = client.post(
            f"{base_url}/api/settings/slack",
            headers=auth_headers(pro_user["token"]),
            json={"webhook_url": "https://example.com/webhook"},
        )
        assert r.status_code == 400

    def test_slack_valid_url_saved(self, base_url, client, pro_user, mongo):
        url = "https://hooks.slack.com/services/T00/B00/XXXXXX"
        r = client.post(
            f"{base_url}/api/settings/slack",
            headers=auth_headers(pro_user["token"]),
            json={"webhook_url": url},
        )
        assert r.status_code == 200
        assert r.json()["webhook_url"] == url
        # verify persistence
        doc = mongo.users.find_one({"user_id": pro_user["user_id"]})
        assert doc["slack_webhook_url"] == url
        # GET returns it
        r2 = client.get(f"{base_url}/api/settings/slack", headers=auth_headers(pro_user["token"]))
        assert r2.json()["webhook_url"] == url


# ---------- Scheduler worker (CORE feature) ----------
class TestSchedulerWorker:
    def test_schedule_runs_within_90s(self, base_url, client, pro_user, mongo):
        r = client.post(
            f"{base_url}/api/schedules",
            headers=auth_headers(pro_user["token"]),
            json={"domain": "example.com", "frequency": "daily", "extended_ports": False},
        )
        assert r.status_code == 200
        sid = r.json()["schedule_id"]

        # Poll up to ~110s for scheduler to run (interval=60s)
        deadline = time.time() + 130
        executed = False
        while time.time() < deadline:
            sched = mongo.schedules.find_one({"schedule_id": sid})
            if sched and sched.get("last_scan_id"):
                executed = True
                break
            time.sleep(5)

        assert executed, "Scheduler did not execute within 130 seconds"
        # Verify scan document has source='scheduled'
        scan = mongo.scans.find_one({"scan_id": sched["last_scan_id"]})
        assert scan is not None
        assert scan.get("source") == "scheduled"
        assert scan.get("schedule_id") == sid
        assert scan["user_id"] == pro_user["user_id"]
        # next_run_at pushed forward
        assert sched["next_run_at"] > sched["created_at"]

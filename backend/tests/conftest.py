"""Shared fixtures for backend tests."""
import os
import time
import uuid
import pytest
import requests
from pathlib import Path
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient
from dotenv import load_dotenv

# Load env files (frontend for REACT_APP_BACKEND_URL, backend for MONGO_URL + DB_NAME)
load_dotenv(Path(__file__).resolve().parents[2] / "frontend" / ".env")
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.environ.get("DB_NAME", "test_database")


@pytest.fixture(scope="session")
def base_url():
    assert BASE_URL, "REACT_APP_BACKEND_URL not set"
    return BASE_URL


@pytest.fixture(scope="session")
def mongo():
    c = MongoClient(MONGO_URL)
    yield c[DB_NAME]
    c.close()


def _create_user(mongo, plan: str = "free"):
    uid = f"user_test_{uuid.uuid4().hex[:10]}"
    token = f"test_session_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc)
    doc = {
        "user_id": uid,
        "email": f"qa+{uid}@test.local",
        "name": "QA Tester",
        "picture": None,
        "created_at": now.isoformat(),
        "plan": plan,
    }
    mongo.users.insert_one(doc)
    mongo.user_sessions.insert_one({
        "user_id": uid,
        "session_token": token,
        "expires_at": (now + timedelta(days=7)).isoformat(),
        "created_at": now.isoformat(),
    })
    return uid, token


@pytest.fixture
def free_user(mongo):
    uid, token = _create_user(mongo, plan="free")
    yield {"user_id": uid, "token": token}
    # cleanup
    mongo.users.delete_one({"user_id": uid})
    mongo.user_sessions.delete_many({"user_id": uid})
    mongo.schedules.delete_many({"user_id": uid})
    mongo.alerts.delete_many({"user_id": uid})
    mongo.scans.delete_many({"user_id": uid})
    mongo.payment_transactions.delete_many({"user_id": uid})


@pytest.fixture
def pro_user(mongo):
    uid, token = _create_user(mongo, plan="pro")
    yield {"user_id": uid, "token": token}
    mongo.users.delete_one({"user_id": uid})
    mongo.user_sessions.delete_many({"user_id": uid})
    mongo.schedules.delete_many({"user_id": uid})
    mongo.alerts.delete_many({"user_id": uid})
    mongo.scans.delete_many({"user_id": uid})
    mongo.payment_transactions.delete_many({"user_id": uid})


@pytest.fixture
def client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}

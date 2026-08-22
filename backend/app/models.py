"""Pydantic request/response models."""
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class ScanRequest(BaseModel):
    domain: str
    extended_ports: bool = False
    ai_summary: bool = True


class User(BaseModel):
    user_id: str
    email: str
    name: str
    picture: Optional[str] = None
    created_at: datetime


class UserPrefs(BaseModel):
    risk_threshold: Optional[int] = None   # 0-100
    notes: Optional[str] = None            # free-form context passed to AI


class ClaudeTierPref(BaseModel):
    tier: str  # fast | balanced | deep


class EmailPrefs(BaseModel):
    enabled: bool = False
    address: Optional[str] = None


class AttackPathBody(BaseModel):
    apt_persona: Optional[str] = "none"
    regenerate: Optional[bool] = False


class CopilotChat(BaseModel):
    message: str
    session_id: Optional[str] = None


class MarketplaceCheckout(BaseModel):
    product_id: str


class ManualTagsBody(BaseModel):
    tags: list[str]


class FlagScanBody(BaseModel):
    flagged: bool
    reason: Optional[str] = None


class BountyReportBody(BaseModel):
    scan_id: str
    finding_key: str            # e.g. "takeover:foo.example.com" or "js_miner:aws_access_key"
    program: Optional[str] = None
    report_id: Optional[str] = None
    status: str = "submitted"   # submitted|duplicate|accepted|informative|rejected
    notes: Optional[str] = None
    severity: Optional[str] = None


class BountyReportUpdate(BaseModel):
    status: Optional[str] = None
    report_id: Optional[str] = None
    program: Optional[str] = None
    notes: Optional[str] = None
    severity: Optional[str] = None

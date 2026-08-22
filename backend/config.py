"""Centralized configuration for the NOCTUA backend.

Added in the "Pro" pass. This is an *optional* convenience layer: existing code
still reads os.environ directly and keeps working. New code can import `settings`
for a single, typed, documented source of truth instead of scattering
os.environ lookups across ~50 modules.

    from config import settings
    client = AsyncIOMotorClient(settings.mongo_url)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


@dataclass(frozen=True)
class Settings:
    # ---- Core (required) ----
    mongo_url: str = field(default_factory=lambda: os.environ.get("MONGO_URL", ""))
    db_name: str = field(default_factory=lambda: os.environ.get("DB_NAME", ""))

    # ---- Networking ----
    cors_origins: list[str] = field(
        default_factory=lambda: _split(os.environ.get("CORS_ORIGINS", "http://localhost:3000"))
    )
    public_base_url: str = field(
        default_factory=lambda: os.environ.get("PUBLIC_BASE_URL", "http://localhost:8001")
    )

    # ---- AI ----
    emergent_llm_key: str = field(default_factory=lambda: os.environ.get("EMERGENT_LLM_KEY", ""))

    # ---- Access control ----
    authorized_emails: list[str] = field(
        default_factory=lambda: _split(os.environ.get("AUTHORIZED_EMAILS", ""))
    )

    # ---- Payments ----
    stripe_secret_key: str = field(default_factory=lambda: os.environ.get("STRIPE_SECRET_KEY", ""))
    stripe_webhook_secret: str = field(
        default_factory=lambda: os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    )

    # ---- Email ----
    resend_api_key: str = field(default_factory=lambda: os.environ.get("RESEND_API_KEY", ""))
    sender_email: str = field(default_factory=lambda: os.environ.get("SENDER_EMAIL", ""))

    # ---- OSINT providers ----
    shodan_key: str = field(default_factory=lambda: os.environ.get("SHODAN_KEY", ""))
    abuseipdb_key: str = field(default_factory=lambda: os.environ.get("ABUSEIPDB_KEY", ""))
    hibp_key: str = field(default_factory=lambda: os.environ.get("HIBP_KEY", ""))
    rapidapi_key: str = field(default_factory=lambda: os.environ.get("RAPIDAPI_KEY", ""))
    intelx_key: str = field(default_factory=lambda: os.environ.get("INTELX_KEY", ""))
    urlscan_key: str = field(default_factory=lambda: os.environ.get("URLSCAN_KEY", ""))

    # ---- Security ----
    ssrf_guard: bool = field(default_factory=lambda: os.environ.get("SSRF_GUARD", "1") == "1")

    def require_core(self) -> None:
        """Fail fast with a clear message if the mandatory vars are missing."""
        missing = [name for name in ("mongo_url", "db_name") if not getattr(self, name)]
        if missing:
            raise RuntimeError(
                "Missing required environment variables: "
                + ", ".join(m.upper() for m in missing)
                + ". Copy backend/.env.example to backend/.env and fill them in."
            )


settings = Settings()

"""Central Claude model selection.

Exposes 3 tiers mapped to the latest Anthropic models (Feb 2026):
  - fast  → claude-haiku-4-5-20251001 (cheap, low latency; key validation, brief summaries)
  - balanced → claude-sonnet-4-6 (default; exec summaries, WAF bypass, phishing sim)
  - deep  → claude-opus-4-8 (deepest reasoning; attack path, APT persona, PoC generator)

Also exposes a helper to resolve a model from user preferences.
"""
from typing import Optional

CLAUDE_TIERS = {
    "fast":     "claude-haiku-4-5-20251001",
    "balanced": "claude-sonnet-4-6",
    "deep":     "claude-opus-4-8",
}

# Human-friendly labels for the UI
CLAUDE_TIER_META = [
    {"id": "fast",     "model": CLAUDE_TIERS["fast"],
     "label": "Haiku 4.5 · Rápido",
     "desc": "Latencia mínima, coste bajo. Ideal para resúmenes cortos y validaciones."},
    {"id": "balanced", "model": CLAUDE_TIERS["balanced"],
     "label": "Sonnet 4.6 · Equilibrado (Recomendado)",
     "desc": "Mejor relación calidad/precio. Ideal para informes ejecutivos y análisis técnicos."},
    {"id": "deep",     "model": CLAUDE_TIERS["deep"],
     "label": "Opus 4.8 · Profundo",
     "desc": "Razonamiento más profundo. Ideal para Attack Path, APT persona y PoC generator."},
]

DEFAULT_TIER = "balanced"


def resolve_claude_model(user: Optional[dict] = None, tier_override: Optional[str] = None) -> str:
    """Return the Anthropic model id for the given user prefs or explicit override."""
    tier = tier_override
    if not tier and user:
        tier = ((user.get("preferences") or {}).get("claude_tier"))
    tier = tier or DEFAULT_TIER
    return CLAUDE_TIERS.get(tier, CLAUDE_TIERS[DEFAULT_TIER])

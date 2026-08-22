"""Stripe Marketplace — per-module one-time unlocks.

Complements the recurring Pro plan with individual features that can be
purchased à-la-carte (e.g. buy "Attack Path Analyzer" for $9 without a full
subscription). Uses Stripe Checkout with `mode=payment` and a lookup_key
per product. Unlocks persist to `users.unlocks[]`.
"""
from datetime import datetime, timezone

# Catálogo de módulos (Stripe lookup_key → módulo interno)
MARKETPLACE_CATALOG = [
    {"id": "attack_path",     "lookup_key": "mkt_attack_path",
     "name": "Attack Path Analyzer",  "price_usd": 9,
     "description": "Diagrama gráfico de rutas de ataque con 7 APT personas.",
     "modules_unlocked": ["attack_path"]},
    {"id": "waf_bypass_ai",   "lookup_key": "mkt_waf_bypass",
     "name": "WAF Bypass IA Táctica",  "price_usd": 12,
     "description": "Briefing táctico generado por Claude con técnicas de evasión.",
     "modules_unlocked": ["waf_bypass_ai"]},
    {"id": "typosquat_pro",   "lookup_key": "mkt_typosquat",
     "name": "Typosquatting Hunter Pro",  "price_usd": 15,
     "description": "500 variantes generadas + monitoreo diario de nuevos registros.",
     "modules_unlocked": ["typosquat"]},
    {"id": "compliance",      "lookup_key": "mkt_compliance",
     "name": "Compliance Scorecard Pack",  "price_usd": 29,
     "description": "SOC 2 · ISO 27001 · GDPR · PCI-DSS scorecards con PDF export.",
     "modules_unlocked": ["compliance"]},
    {"id": "cve_feed_pro",    "lookup_key": "mkt_cve_feed",
     "name": "CVE Feed en tiempo real",  "price_usd": 19,
     "description": "Alertas Telegram + Email cuando se publica una CVE de tu stack.",
     "modules_unlocked": ["cve_feed"]},
    {"id": "copilot_pro",     "lookup_key": "mkt_copilot",
     "name": "AI Copilot Pro",  "price_usd": 25,
     "description": "Claude Opus 4.8 en el Copilot + sesiones ilimitadas.",
     "modules_unlocked": ["copilot_pro"]},
]


def is_unlocked(user: dict, module_id: str) -> bool:
    """Return True if the user has unlocked the given module (or has Pro plan)."""
    if not user:
        return False
    if user.get("plan") == "pro":
        return True
    unlocks = user.get("unlocks") or []
    return module_id in unlocks


def get_product(product_id: str) -> dict | None:
    return next((p for p in MARKETPLACE_CATALOG if p["id"] == product_id), None)


async def apply_unlock(db, user_id: str, product_id: str) -> bool:
    """Add a module to user.unlocks after successful payment."""
    prod = get_product(product_id)
    if not prod:
        return False
    await db.users.update_one(
        {"user_id": user_id},
        {"$addToSet": {"unlocks": {"$each": prod["modules_unlocked"]}},
         "$push": {"marketplace_orders": {
             "product_id": product_id,
             "unlocked_at": datetime.now(timezone.utc).isoformat(),
         }}},
    )
    return True

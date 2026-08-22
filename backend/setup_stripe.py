"""Provision a claimable Stripe sandbox and set up the Pro catalog."""
import os
import json
import urllib.request
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent
load_dotenv(ROOT / ".env")

base = os.environ["INTEGRATION_PROXY_URL"]
job_id = "6aada785-459a-44a1-928a-6e0b540aeddd"
key = "sk-emergent-c32439205A79e4c5fB"

req = urllib.request.Request(
    base + "/stripe/sandboxes",
    data=json.dumps({"job_id": job_id}).encode(),
    headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req) as r:
    sandbox = json.load(r)

print("SANDBOX PROVISIONED:")
print("account_id:", sandbox["sandbox_account_id"])
print("onboarding_url:", sandbox["onboarding_url"])

env_path = ROOT / ".env"
existing = env_path.read_text()
# Remove any stale Stripe vars
lines = [l for l in existing.splitlines()
         if not any(l.startswith(k + "=") for k in
                    ["STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY",
                     "STRIPE_ACCOUNT_ID", "STRIPE_WEBHOOK_SECRET",
                     "STRIPE_MODE", "STRIPE_ONBOARDING_URL"])]
lines += [
    f'STRIPE_SECRET_KEY="{sandbox["sandbox_secret_key"]}"',
    f'STRIPE_PUBLISHABLE_KEY="{sandbox["sandbox_publishable_key"]}"',
    f'STRIPE_ACCOUNT_ID="{sandbox["sandbox_account_id"]}"',
    f'STRIPE_WEBHOOK_SECRET="{sandbox["preview_webhook_secret"]}"',
    f'STRIPE_MODE="test"',
    f'STRIPE_ONBOARDING_URL="{sandbox["onboarding_url"]}"',
]
env_path.write_text("\n".join(lines) + "\n")
print("\n.env updated.")

# Now setup the catalog
import stripe
stripe.api_key = sandbox["sandbox_secret_key"]

country = stripe.Account.retrieve()["country"]
print(f"\nAccount country: {country}")

# Ensure tax settings for full/SMP mode (US default address)
try:
    s = stripe.tax.Settings.retrieve()
    if not (s.head_office and getattr(s.head_office, "address", None)):
        stripe.tax.Settings.modify(
            head_office={"address": {"country": country or "US", "line1": "1 Market St",
                                     "city": "San Francisco", "state": "CA", "postal_code": "94103"}},
            defaults={"tax_behavior": "exclusive"},
        )
        print("Tax settings configured.")
except Exception as e:
    print("Tax setup skipped:", e)

CATALOG = [
    {
        "emergent_product_id": "noctua_pro",
        "name": "NOCTUA.osint Pro",
        "tax_code": "txcd_10103001",
        "prices": [
            {"lookup_key": "pro_monthly", "amount": 900, "currency": "usd", "interval": "month"},
        ],
    },
]

def get_or_create_product(entry):
    for p in stripe.Product.list(active=True).auto_paging_iter():
        if p.to_dict().get("metadata", {}).get("emergent_product_id") == entry["emergent_product_id"]:
            return p
    return stripe.Product.create(
        name=entry["name"],
        tax_code=entry.get("tax_code"),
        metadata={"managed_by": "emergent", "emergent_product_id": entry["emergent_product_id"]},
    )

for entry in CATALOG:
    prod = get_or_create_product(entry)
    print(f"Product: {prod.id} ({entry['name']})")
    for p in entry["prices"]:
        existing = stripe.Price.list(lookup_keys=[p["lookup_key"]], active=True, limit=1).data
        if existing and (existing[0].unit_amount != p["amount"] or existing[0].currency != p["currency"]):
            stripe.Price.modify(existing[0].id, active=False)
            existing = []
        if not existing:
            kwargs = dict(
                product=prod.id, unit_amount=p["amount"], currency=p["currency"],
                lookup_key=p["lookup_key"], transfer_lookup_key=True,
            )
            if p.get("interval"):
                kwargs["recurring"] = {"interval": p["interval"]}
            price = stripe.Price.create(**kwargs)
            print(f"  Price created: {price.id} ({p['lookup_key']})")
        else:
            print(f"  Price exists: {existing[0].id} ({p['lookup_key']})")

print("\nDone. Onboarding URL:", sandbox["onboarding_url"])

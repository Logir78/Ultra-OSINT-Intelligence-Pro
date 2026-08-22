"""Stripe payments module — Pro subscription."""
import os
import stripe
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

TAX_MODE = "full"  # SMP; ES is SMP-supported and SaaS is digital


def build_router(db, get_current_user):
    payments_router = APIRouter(prefix="/api")

    class CheckoutRequest(BaseModel):
        lookup_key: str = "pro_monthly"
        origin_url: str

    @payments_router.post("/payments/checkout")
    async def create_checkout(req: CheckoutRequest, user=Depends(get_current_user)):
        prices = stripe.Price.list(lookup_keys=[req.lookup_key], active=True, limit=1).data
        if not prices:
            raise HTTPException(500, f"Price not found: {req.lookup_key}")
        price = prices[0]
        kwargs = dict(
            line_items=[{"price": price.id, "quantity": 1}],
            mode="subscription" if price.recurring else "payment",
            success_url=f"{req.origin_url}/payment/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{req.origin_url}/payment/cancel",
            metadata={"user_id": user["user_id"], "lookup_key": req.lookup_key},
        )
        try:
            session = stripe.checkout.Session.create(**kwargs, managed_payments={"enabled": True})
        except stripe.error.InvalidRequestError as e:
            msg = (e.user_message or "").lower()
            if "managed payments" in msg or "ineligible" in msg:
                session = stripe.checkout.Session.create(
                    **kwargs, automatic_tax={"enabled": True}, billing_address_collection="required",
                )
            else:
                raise

        await db.payment_transactions.insert_one({
            "session_id": session.id,
            "user_id": user["user_id"],
            "lookup_key": req.lookup_key,
            "amount": (price.unit_amount or 0),
            "currency": price.currency,
            "status": "initiated",
            "payment_status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        return {"checkout_url": session.url, "session_id": session.id}

    async def _mark_paid(session_id: str, subscription_id: Optional[str], user_id: Optional[str]):
        await db.payment_transactions.update_one(
            {"session_id": session_id, "payment_status": {"$ne": "paid"}},
            {"$set": {
                "status": "completed",
                "payment_status": "paid",
                "stripe_subscription_id": subscription_id,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }},
        )
        if user_id:
            await db.users.update_one(
                {"user_id": user_id},
                {"$set": {
                    "plan": "pro",
                    "stripe_subscription_id": subscription_id,
                    "plan_updated_at": datetime.now(timezone.utc).isoformat(),
                }},
            )

    @payments_router.get("/payments/status/{session_id}")
    async def get_status(session_id: str):
        record = await db.payment_transactions.find_one({"session_id": session_id}, {"_id": 0})
        if not record:
            raise HTTPException(404, "Transaction not found")
        if record.get("payment_status") != "paid":
            try:
                s = stripe.checkout.Session.retrieve(session_id)
                if s.payment_status == "paid" or s.status == "complete":
                    await _mark_paid(session_id, s.subscription, record.get("user_id"))
                    record = await db.payment_transactions.find_one({"session_id": session_id}, {"_id": 0})
            except stripe.error.StripeError:
                pass
        return {
            "session_id": record["session_id"],
            "status": record["status"],
            "payment_status": record["payment_status"],
        }

    @payments_router.post("/stripe/webhook")
    async def stripe_webhook(request: Request):
        payload = await request.body()
        sig = request.headers.get("stripe-signature", "")
        try:
            event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
        except stripe.error.SignatureVerificationError:
            raise HTTPException(400, "Invalid signature")
        obj = event["data"]["object"]
        t = event["type"]

        if t == "checkout.session.completed":
            meta = obj.get("metadata", {}) or {}
            user_id = meta.get("user_id")
            # Marketplace one-time purchase
            if meta.get("kind") == "marketplace":
                product_id = meta.get("product_id")
                from marketplace import apply_unlock
                if user_id and product_id:
                    await apply_unlock(db, user_id, product_id)
                await db.payment_transactions.update_one(
                    {"session_id": obj["id"]},
                    {"$set": {"status": "completed", "payment_status": "paid",
                              "updated_at": datetime.now(timezone.utc).isoformat()}},
                )
            else:
                await _mark_paid(obj["id"], obj.get("subscription"), user_id)
        elif t == "checkout.session.async_payment_succeeded":
            await db.payment_transactions.update_one(
                {"session_id": obj["id"]},
                {"$set": {"payment_status": "paid", "updated_at": datetime.now(timezone.utc).isoformat()}},
            )
        elif t == "checkout.session.async_payment_failed":
            await db.payment_transactions.update_one(
                {"session_id": obj["id"]},
                {"$set": {"status": "failed", "payment_status": "failed",
                          "updated_at": datetime.now(timezone.utc).isoformat()}},
            )
        elif t == "customer.subscription.deleted":
            sub_id = obj.get("id")
            await db.users.update_one(
                {"stripe_subscription_id": sub_id},
                {"$set": {"plan": "free", "plan_updated_at": datetime.now(timezone.utc).isoformat()}},
            )
        return {"status": "ok"}

    @payments_router.get("/payments/plan")
    async def get_plan(user=Depends(get_current_user)):
        plan = user.get("plan", "free")
        return {"plan": plan, "user_id": user["user_id"]}

    @payments_router.post("/payments/cancel")
    async def cancel_subscription(user=Depends(get_current_user)):
        sub_id = user.get("stripe_subscription_id")
        if not sub_id:
            raise HTTPException(400, "No active subscription")
        try:
            stripe.Subscription.delete(sub_id)
        except stripe.error.StripeError as e:
            raise HTTPException(500, str(e))
        await db.users.update_one(
            {"user_id": user["user_id"]},
            {"$set": {"plan": "free", "plan_updated_at": datetime.now(timezone.utc).isoformat()}},
        )
        return {"ok": True, "plan": "free"}

    return payments_router

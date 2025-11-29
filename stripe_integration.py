"""
Stripe billing integration for BugBounty Arsenal.
Handles subscriptions, payments, and webhooks.
"""
import os
import stripe
from typing import Optional, Dict
from datetime import datetime

from models import SubscriptionTierEnum

# Stripe API key from environment
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_...")

# Stripe price IDs (replace with your actual price IDs from Stripe Dashboard)
STRIPE_PRICE_IDS = {
    SubscriptionTierEnum.FREE: None,  # No price for free tier
    SubscriptionTierEnum.BASIC: os.getenv("STRIPE_PRICE_BASIC", "price_1Basic..."),
    SubscriptionTierEnum.PRO: os.getenv("STRIPE_PRICE_PRO", "price_1Pro..."),
    SubscriptionTierEnum.ENTERPRISE: os.getenv("STRIPE_PRICE_ENT", "price_1Ent..."),
}

# Webhook secret for signature verification
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_...")


def create_checkout_session(
    user_email: str,
    tier: SubscriptionTierEnum,
    success_url: str,
    cancel_url: str,
    customer_id: Optional[str] = None
) -> Dict:
    """
    Create Stripe Checkout session for subscription purchase.
    
    Args:
        user_email: User's email address
        tier: Subscription tier (PRO or ENTERPRISE)
        success_url: URL to redirect on success
        cancel_url: URL to redirect on cancel
        customer_id: Existing Stripe customer ID (optional)
    
    Returns:
        Checkout session data with URL
    """
    if tier == SubscriptionTierEnum.FREE:
        raise ValueError("Cannot create checkout for FREE tier")
    
    price_id = STRIPE_PRICE_IDS.get(tier)
    if not price_id:
        raise ValueError(f"No price ID configured for tier {tier}")
    
    # Prepare session params
    session_params = {
        "mode": "subscription",
        "payment_method_types": ["card"],
        "line_items": [
            {
                "price": price_id,
                "quantity": 1,
            }
        ],
        "success_url": success_url,
        "cancel_url": cancel_url,
        "subscription_data": {
            "trial_period_days": 7,  # 7-day free trial
        },
        "metadata": {
            "tier": tier.value,
        }
    }
    
    # Use existing customer or create new
    if customer_id:
        session_params["customer"] = customer_id
    else:
        session_params["customer_email"] = user_email
    
    # Create checkout session
    session = stripe.checkout.Session.create(**session_params)
    
    return {
        "session_id": session.id,
        "url": session.url,
        "customer_id": session.customer,
    }


def create_customer_portal_session(
    customer_id: str,
    return_url: str
) -> Dict:
    """
    Create Stripe Customer Portal session for subscription management.
    
    Args:
        customer_id: Stripe customer ID
        return_url: URL to redirect after portal
    
    Returns:
        Portal session with URL
    """
    session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=return_url,
    )
    
    return {
        "url": session.url,
    }


def cancel_subscription(subscription_id: str) -> bool:
    """
    Cancel a Stripe subscription immediately.
    
    Args:
        subscription_id: Stripe subscription ID
    
    Returns:
        True if successful
    """
    try:
        stripe.Subscription.delete(subscription_id)
        return True
    except Exception as e:
        print(f"Error canceling subscription: {e}")
        return False


def verify_webhook_signature(payload: bytes, signature: str) -> Optional[Dict]:
    """
    Verify Stripe webhook signature and parse event.
    
    Args:
        payload: Raw request body
        signature: Stripe-Signature header value
    
    Returns:
        Parsed event data or None if invalid
    """
    try:
        event = stripe.Webhook.construct_event(
            payload, signature, STRIPE_WEBHOOK_SECRET
        )
        return event
    except ValueError:
        # Invalid payload
        return None
    except stripe.error.SignatureVerificationError:
        # Invalid signature
        return None


def get_subscription_details(subscription_id: str) -> Optional[Dict]:
    """
    Get details of a Stripe subscription.
    
    Args:
        subscription_id: Stripe subscription ID
    
    Returns:
        Subscription data
    """
    try:
        subscription = stripe.Subscription.retrieve(subscription_id)
        return {
            "id": subscription.id,
            "status": subscription.status,
            "current_period_start": datetime.fromtimestamp(subscription.current_period_start),
            "current_period_end": datetime.fromtimestamp(subscription.current_period_end),
            "trial_end": datetime.fromtimestamp(subscription.trial_end) if subscription.trial_end else None,
            "cancel_at_period_end": subscription.cancel_at_period_end,
        }
    except Exception as e:
        print(f"Error fetching subscription: {e}")
        return None


# Price mapping for UI display (in EUR)
TIER_PRICES = {
    SubscriptionTierEnum.FREE: {"monthly": 0, "currency": "EUR"},
    SubscriptionTierEnum.BASIC: {"monthly": 4.99, "currency": "EUR"},
    SubscriptionTierEnum.PRO: {"monthly": 9.99, "currency": "EUR"},
    SubscriptionTierEnum.ENTERPRISE: {"monthly": 49.99, "currency": "EUR"},
}

# Extra scans pricing (one-time purchase)
EXTRA_SCANS_PRICING = {
    "10_scans": {"amount": 2.99, "scans": 10, "currency": "EUR"},
    "25_scans": {"amount": 5.99, "scans": 25, "currency": "EUR"},
    "50_scans": {"amount": 9.99, "scans": 50, "currency": "EUR"},
    "100_scans": {"amount": 15.99, "scans": 100, "currency": "EUR"},
}


def get_tier_price(tier: SubscriptionTierEnum, billing_cycle: str = "monthly") -> int:
    """Get price for a tier and billing cycle"""
    return TIER_PRICES.get(tier, {}).get(billing_cycle, 0)


def create_extra_scans_checkout(
    user_email: str,
    package: str,
    success_url: str,
    cancel_url: str,
    customer_id: Optional[str] = None
) -> Dict:
    """
    Create Stripe Checkout session for extra scans purchase (one-time payment).
    
    Args:
        user_email: User's email address
        package: Package ID (e.g., "10_scans", "25_scans")
        success_url: URL to redirect on success
        cancel_url: URL to redirect on cancel
        customer_id: Existing Stripe customer ID (optional)
    
    Returns:
        Checkout session data with URL
    """
    if package not in EXTRA_SCANS_PRICING:
        raise ValueError(f"Invalid package: {package}")
    
    pricing = EXTRA_SCANS_PRICING[package]
    
    try:
        # Create or get customer
        if not customer_id:
            customer = stripe.Customer.create(email=user_email)
            customer_id = customer.id
        
        # Create checkout session for one-time payment
        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=["card"],
            mode="payment",  # One-time payment, not subscription
            line_items=[{
                "price_data": {
                    "currency": pricing["currency"].lower(),
                    "unit_amount": int(pricing["amount"] * 100),  # Convert to cents
                    "product_data": {
                        "name": f"{pricing['scans']} Extra Scans",
                        "description": f"Add {pricing['scans']} additional scans to your account",
                    },
                },
                "quantity": 1,
            }],
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={
                "type": "extra_scans",
                "package": package,
                "scans": pricing["scans"],
                "user_email": user_email,
            }
        )
        
        return {
            "session_id": session.id,
            "url": session.url,
            "customer_id": customer_id
        }
    except Exception as e:
        print(f"Error creating extra scans checkout: {e}")
        raise


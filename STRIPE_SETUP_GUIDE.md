# Stripe Billing Integration Guide

## Overview

BugBounty Arsenal uses Stripe for subscription payments. This guide covers the complete setup process.

## 1. Create Stripe Account

1. Go to [dashboard.stripe.com](https://dashboard.stripe.com)
2. Sign up for a free account
3. Complete business verification (required for production)

## 2. Get API Keys

### Test Mode Keys (for development)

1. Navigate to **Developers** → **API keys**
2. Copy your keys:
   - `Publishable key` (starts with `pk_test_`)
   - `Secret key` (starts with `sk_test_`)

### Add to Environment

Create `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env` and add your keys:

```env
STRIPE_SECRET_KEY=sk_test_your_key_here
STRIPE_PUBLISHABLE_KEY=pk_test_your_key_here
APP_URL=http://localhost:8000
```

## 3. Create Products and Prices

### Create PRO Product

1. Go to **Products** → **Add Product**
2. Fill in:
   - Name: `BugBounty Arsenal PRO`
   - Description: `For serious bug bounty hunters`
   - Pricing: **Recurring** → **Monthly** → `$39.00`
3. Click **Save product**
4. Copy the **Price ID** (starts with `price_`)
5. Add to `.env`:
   ```env
   STRIPE_PRICE_PRO=price_1abc123...
   ```

### Create ENTERPRISE Product

1. Go to **Products** → **Add Product**
2. Fill in:
   - Name: `BugBounty Arsenal ENTERPRISE`
   - Description: `For teams and professionals`
   - Pricing: **Recurring** → **Monthly** → `$119.00`
3. Click **Save product**
4. Copy the **Price ID**
5. Add to `.env`:
   ```env
   STRIPE_PRICE_ENT=price_1xyz789...
   ```

## 4. Configure Webhook

### Local Development (using Stripe CLI)

1. Install Stripe CLI:
   ```bash
   # macOS
   brew install stripe/stripe-cli/stripe
   
   # Linux
   wget https://github.com/stripe/stripe-cli/releases/download/v1.19.4/stripe_1.19.4_linux_x86_64.tar.gz
   tar -xvf stripe_1.19.4_linux_x86_64.tar.gz
   sudo mv stripe /usr/local/bin/
   ```

2. Login to Stripe CLI:
   ```bash
   stripe login
   ```

3. Forward webhooks to local server:
   ```bash
   stripe listen --forward-to localhost:8000/api/stripe-webhook
   ```

4. Copy the webhook signing secret (starts with `whsec_`) and add to `.env`:
   ```env
   STRIPE_WEBHOOK_SECRET=whsec_your_secret_here
   ```

### Production Setup

1. Go to **Developers** → **Webhooks** → **Add endpoint**
2. Endpoint URL: `https://yourdomain.com/api/stripe-webhook`
3. Select events to listen to:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
4. Click **Add endpoint**
5. Copy the **Signing secret** and add to production `.env`

## 5. Test the Integration

### Test Checkout Flow

1. Start the server:
   ```bash
   source .venv/bin/activate
   python -m uvicorn webapp:app --reload --host 0.0.0.0 --port 8000
   ```

2. In another terminal, start Stripe webhook forwarding:
   ```bash
   stripe listen --forward-to localhost:8000/api/stripe-webhook
   ```

3. Open browser: `http://localhost:8000`
4. Sign up for a new account
5. Click "Start Pro Trial" or "Start Enterprise Trial"
6. Use test card: `4242 4242 4242 4242`
   - Expiry: any future date
   - CVC: any 3 digits
   - ZIP: any 5 digits

### Test Subscription Management

1. Login to dashboard
2. Click "Manage Subscription" button
3. You'll be redirected to Stripe Customer Portal
4. Test:
   - Update payment method
   - Cancel subscription
   - View invoices

### Test Webhooks

1. Check terminal running `stripe listen`
2. You should see events:
   ```
   checkout.session.completed [evt_123...]
   customer.subscription.created [evt_456...]
   ```

3. Check database:
   ```bash
   python -c "from database import get_db_session; from models import Subscription; \
   with get_db_session() as db: \
       subs = db.query(Subscription).all(); \
       for s in subs: print(f'{s.user.email}: {s.tier.value} - {s.status.value}')"
   ```

## 6. Stripe Test Cards

### Successful Payments
- `4242 4242 4242 4242` - Succeeds
- `5555 5555 5555 4444` - Mastercard succeeds

### Failed Payments
- `4000 0000 0000 0002` - Card declined
- `4000 0000 0000 9995` - Insufficient funds

### 3D Secure
- `4000 0025 0000 3155` - Requires authentication

[Full list](https://stripe.com/docs/testing#cards)

## 7. Event Flow

### User Upgrades to PRO

1. User clicks "Start Pro Trial" on landing page
2. `POST /api/create-checkout-session` creates Stripe Checkout
3. User enters card details on Stripe-hosted page
4. Stripe processes payment
5. Stripe sends `checkout.session.completed` webhook
6. Backend updates `subscriptions` table:
   - `tier = PRO`
   - `status = TRIALING` (7-day trial)
   - `stripe_subscription_id = sub_123...`
7. User redirected to `/dashboard?checkout=success`
8. Dashboard shows PRO tier limits

### Subscription Renewed

1. Stripe automatically charges customer monthly
2. Stripe sends `invoice.payment_succeeded` webhook
3. Backend updates:
   - `status = ACTIVE`
   - `current_period_start` and `current_period_end`

### Payment Failed

1. Stripe fails to charge card
2. Stripe sends `invoice.payment_failed` webhook
3. Backend updates:
   - `status = PAST_DUE`
4. User gets email notification (if configured)
5. After multiple failures, Stripe cancels subscription
6. `customer.subscription.deleted` webhook received
7. Backend downgrades user to FREE tier

### User Cancels

1. User clicks "Manage Subscription" → "Cancel plan"
2. Stripe cancels subscription at period end
3. `customer.subscription.updated` webhook (cancel_at_period_end=true)
4. At period end: `customer.subscription.deleted` webhook
5. Backend downgrades to FREE tier

## 8. Database Schema

```sql
-- subscriptions table
CREATE TABLE subscriptions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    tier VARCHAR(20) DEFAULT 'FREE',  -- FREE, PRO, ENTERPRISE
    status VARCHAR(20) DEFAULT 'ACTIVE',  -- ACTIVE, TRIALING, PAST_DUE, CANCELED
    stripe_customer_id VARCHAR(255),
    stripe_subscription_id VARCHAR(255),
    current_period_start TIMESTAMP,
    current_period_end TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 9. Security Best Practices

### Webhook Signature Verification

✅ **Always verify webhook signatures** before processing events.

The code already does this in `stripe_integration.py`:

```python
def verify_webhook_signature(payload: bytes, signature: str) -> Optional[Dict]:
    try:
        event = stripe.Webhook.construct_event(
            payload, signature, STRIPE_WEBHOOK_SECRET
        )
        return event
    except stripe.error.SignatureVerificationError:
        return None  # Invalid signature - reject
```

### Environment Variables

🔒 **Never commit `.env` file** to git. Add to `.gitignore`:

```bash
echo ".env" >> .gitignore
```

### Production Checklist

- [ ] Use production API keys (starts with `sk_live_`)
- [ ] Set `DATABASE_URL` to PostgreSQL
- [ ] Configure real webhook endpoint (HTTPS required)
- [ ] Enable Stripe Radar for fraud detection
- [ ] Set up email notifications for payment failures
- [ ] Configure tax collection (if required)
- [ ] Add Terms of Service and Privacy Policy links
- [ ] Test subscription upgrades/downgrades
- [ ] Test trial period expiration
- [ ] Test payment failures and retries

## 10. Troubleshooting

### "No active subscription" error

**Cause**: User's subscription record missing or no `stripe_customer_id`

**Fix**:
```python
python -c "from database import get_db_session; from models import User, Subscription; \
with get_db_session() as db: \
    user = db.query(User).filter(User.email == 'user@example.com').first(); \
    if not user.subscription: \
        sub = Subscription(user_id=user.id); \
        db.add(sub); \
        db.commit(); \
        print('Created subscription')"
```

### Webhooks not working

1. Check webhook endpoint is publicly accessible (use ngrok for local testing)
2. Verify `STRIPE_WEBHOOK_SECRET` matches Stripe dashboard
3. Check webhook event types are configured
4. Look at webhook logs in Stripe dashboard

### "Invalid price ID" error

**Cause**: `STRIPE_PRICE_PRO` or `STRIPE_PRICE_ENT` not set correctly

**Fix**: Copy correct price IDs from Stripe dashboard → Products

## 11. Monitoring

### Stripe Dashboard

Monitor in real-time:
- **Payments** - successful/failed transactions
- **Customers** - active subscribers
- **Subscriptions** - MRR, churn rate
- **Webhooks** - event delivery status

### Database Queries

Check subscription stats:
```bash
python -c "from database import get_db_session; from models import Subscription, SubscriptionTierEnum; \
from sqlalchemy import func; \
with get_db_session() as db: \
    stats = db.query(Subscription.tier, func.count()).group_by(Subscription.tier).all(); \
    for tier, count in stats: print(f'{tier.value}: {count} users')"
```

Output:
```
FREE: 42 users
PRO: 15 users
ENTERPRISE: 3 users
```

## Support

- Stripe Documentation: https://stripe.com/docs
- Stripe Support: https://support.stripe.com
- Test Mode Dashboard: https://dashboard.stripe.com/test

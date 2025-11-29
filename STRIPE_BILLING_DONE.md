# Stripe Billing Integration - DONE ✅

## What's Implemented

### 1. Stripe Integration Module (`stripe_integration.py`)
- ✅ Checkout session creation with 7-day free trial
- ✅ Customer portal for subscription management
- ✅ Webhook signature verification
- ✅ Subscription lifecycle handling
- ✅ Price tier mapping (PRO $39/mo, ENTERPRISE $119/mo)

### 2. Backend Endpoints (`webapp.py`)
- ✅ `POST /api/create-checkout-session` - Initiate subscription purchase
- ✅ `GET /api/billing/portal` - Redirect to Stripe Customer Portal
- ✅ `POST /api/stripe-webhook` - Handle Stripe events

### 3. Webhook Events Handled
- ✅ `checkout.session.completed` - Payment successful, activate subscription
- ✅ `customer.subscription.updated` - Status/tier change
- ✅ `customer.subscription.deleted` - Downgrade to FREE
- ✅ `invoice.payment_succeeded` - Update billing period
- ✅ `invoice.payment_failed` - Mark as PAST_DUE

### 4. UI Updates
- ✅ Landing page "Upgrade" buttons with Stripe checkout
- ✅ Dashboard "Manage Subscription" button (for paid users)
- ✅ Dashboard "Upgrade Plan" button (for FREE users)
- ✅ Automatic tier display based on subscription status

### 5. Database Integration
- ✅ Stripe customer ID stored in `subscriptions.stripe_customer_id`
- ✅ Stripe subscription ID in `subscriptions.stripe_subscription_id`
- ✅ Billing period tracking (`current_period_start`, `current_period_end`)
- ✅ Subscription status enum (ACTIVE, TRIALING, PAST_DUE, CANCELED)
- ✅ Audit logs for all billing events

### 6. Security
- ✅ Webhook signature verification with `STRIPE_WEBHOOK_SECRET`
- ✅ Environment variable configuration (`.env.example` provided)
- ✅ JWT authentication required for checkout
- ✅ Audit logging for all subscription events

## Quick Start

### 1. Get Stripe Keys
```bash
# Sign up at https://dashboard.stripe.com
# Copy API keys from Developers > API keys
```

### 2. Configure Environment
```bash
cp .env.example .env
nano .env  # Add your Stripe keys
```

Required variables:
```env
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_PRO=price_...
STRIPE_PRICE_ENT=price_...
```

### 3. Create Products in Stripe
1. Go to Products > Add Product
2. Create "BugBounty Arsenal PRO" - $39/month
3. Create "BugBounty Arsenal ENTERPRISE" - $119/month
4. Copy Price IDs and add to `.env`

### 4. Set Up Webhook (Local Testing)
```bash
# Install Stripe CLI
brew install stripe/stripe-cli/stripe

# Login
stripe login

# Forward webhooks to local server
stripe listen --forward-to localhost:8000/api/stripe-webhook
```

### 5. Test the Flow
```bash
# Start server (already running)
# Open http://localhost:8000
# Click "Start Pro Trial"
# Use test card: 4242 4242 4242 4242
```

## Payment Flow

```
User clicks "Start Pro Trial"
    ↓
POST /api/create-checkout-session
    ↓
Stripe Checkout Page (Stripe-hosted)
    ↓
User enters card: 4242 4242 4242 4242
    ↓
Stripe processes payment
    ↓
checkout.session.completed webhook
    ↓
Backend updates:
  - tier = PRO
  - status = TRIALING (7-day trial)
  - stripe_subscription_id = sub_123...
    ↓
Redirect to /dashboard?checkout=success
    ↓
Dashboard shows PRO limits
```

## Subscription Lifecycle

### Trial → Active
- Day 0: User upgrades, starts 7-day trial (`status=TRIALING`)
- Day 7: First payment charged automatically
- Webhook: `invoice.payment_succeeded` → `status=ACTIVE`

### Active → Past Due
- Monthly payment fails
- Webhook: `invoice.payment_failed` → `status=PAST_DUE`
- Stripe retries payment automatically (3 attempts)

### Past Due → Canceled
- All retries fail
- Webhook: `customer.subscription.deleted`
- Backend: `tier=FREE`, `status=CANCELED`

### User Cancels
- User clicks "Manage Subscription" → "Cancel plan"
- Subscription continues until period end
- Then: `customer.subscription.deleted` → downgrade to FREE

## Test Cards

| Card Number | Description |
|------------|-------------|
| 4242 4242 4242 4242 | Successful payment |
| 4000 0000 0000 0002 | Card declined |
| 4000 0000 0000 9995 | Insufficient funds |
| 4000 0025 0000 3155 | Requires 3D Secure |

[Full list](https://stripe.com/docs/testing#cards)

## Monitoring

### Check Subscriptions
```bash
python -c "from database import get_db_session; from models import Subscription; \
with get_db_session() as db: \
    subs = db.query(Subscription).all(); \
    for s in subs: \
        print(f'{s.user.email}: {s.tier.value} ({s.status.value}) - Stripe: {s.stripe_subscription_id}')"
```

### View Audit Logs
```bash
python -c "from database import get_db_session; from models import AuditLog; \
with get_db_session() as db: \
    logs = db.query(AuditLog).filter(AuditLog.event_type.like('subscription%')).all(); \
    for log in logs[-10:]: \
        print(f'{log.created_at} - {log.event_type}: {log.description}')"
```

## Production Deployment

### Pre-launch Checklist
- [ ] Switch to production Stripe keys (`sk_live_`, `pk_live_`)
- [ ] Configure production webhook endpoint (HTTPS required)
- [ ] Set `DATABASE_URL` to PostgreSQL
- [ ] Enable Stripe Radar for fraud prevention
- [ ] Add Terms of Service and Refund Policy
- [ ] Test full payment flow with real card
- [ ] Set up monitoring for failed payments
- [ ] Configure email notifications (SMTP settings)

### Webhook Setup (Production)
1. Go to Stripe Dashboard > Developers > Webhooks
2. Add endpoint: `https://yourdomain.com/api/stripe-webhook`
3. Select all subscription events
4. Copy signing secret → `.env` on production server

## Files Changed

```
NEW FILES:
  stripe_integration.py      - Stripe API wrapper
  .env.example              - Environment template
  STRIPE_SETUP_GUIDE.md     - Detailed setup docs
  STRIPE_BILLING_DONE.md    - This file

MODIFIED FILES:
  webapp.py                 - Added 3 billing endpoints
  templates/landing.html    - Added upgrade buttons with JS
  templates/dashboard.html  - Added manage subscription button
  models.py                 - Already had Stripe fields
```

## Next Steps (Optional Enhancements)

### Short Term
- [ ] Admin panel to manually change user tiers
- [ ] Email notifications for payment failures
- [ ] PDF export functionality (ENTERPRISE only)
- [ ] Usage tracking (scans per month)

### Medium Term
- [ ] Annual billing option (20% discount)
- [ ] Team collaboration features
- [ ] API key generation (ENTERPRISE)
- [ ] Scheduled scans with cron jobs

### Long Term
- [ ] Referral program
- [ ] Volume discounts for teams
- [ ] White-label solution for agencies
- [ ] Usage-based pricing tier

## Support

For detailed setup instructions, see: **STRIPE_SETUP_GUIDE.md**

For Stripe-specific issues:
- Stripe Docs: https://stripe.com/docs
- Stripe Support: https://support.stripe.com
- Community: https://github.com/stripe

For BugBounty Arsenal issues:
- Check server logs: `tail -f logs/app.log`
- Check webhook logs in Stripe Dashboard
- Test webhook locally with `stripe trigger checkout.session.completed`

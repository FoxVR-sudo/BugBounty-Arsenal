# BugBounty Arsenal - Subscription Tier System

## Overview

The tier system enforces feature and usage limits based on subscription plans. This enables monetization of the scanner as a SaaS product.

## Available Tiers

### 🆓 FREE Tier
- **Price**: $0/month
- **Concurrent Scans**: 1
- **Max URLs per Scan**: 5
- **Recon Pipeline**: ❌
- **Nuclei CVE Scans**: ❌
- **Mobile Scanner**: ❌
- **Cloudflare Solver**: ❌
- **API Access**: ❌
- **Detectors**: 5 basic detectors
  - XSS Pattern Detector
  - SQL Pattern Detector
  - Security Headers Detector
  - Open Redirect Detector
  - Secret Detector
- **Export Formats**: HTML only
- **Rate Limit**: 0.5 req/sec per host
- **Timeout**: 5 minutes per scan

### 💎 PRO Tier
- **Price**: $29-49/month (recommended: $39)
- **Concurrent Scans**: 3
- **Max URLs per Scan**: 50
- **Recon Pipeline**: ✅ (Subfinder, HTTPX)
- **Nuclei CVE Scans**: ❌
- **Mobile Scanner**: ❌
- **Cloudflare Solver**: ❌
- **API Access**: ❌
- **Detectors**: 19 detectors (basic + advanced)
  - All FREE detectors
  - IDOR Detector
  - CSRF Detector
  - CORS Detector
  - LFI Detector
  - XXE Detector
  - SSTI Detector
  - Command Injection Detector
  - JWT Detector
  - NoSQL Injection Detector
  - GraphQL Detector
  - Prototype Pollution Detector
  - Race Condition Detector
  - Directory Listing Detector
  - File Upload Detector
- **Export Formats**: HTML, JSON, Markdown
- **Rate Limit**: 1.0 req/sec per host
- **Timeout**: 30 minutes per scan

### 🚀 ENTERPRISE Tier
- **Price**: $99-149/month (recommended: $119)
- **Concurrent Scans**: 10
- **Max URLs per Scan**: Unlimited
- **Recon Pipeline**: ✅ (Full)
- **Nuclei CVE Scans**: ✅
- **Mobile Scanner**: ✅ (APK/IPA analysis)
- **Cloudflare Solver**: ✅
- **API Access**: ✅ (REST API for automation)
- **Detectors**: 28+ detectors (all)
  - All PRO detectors
  - SSRF Detector (basic + advanced + OOB)
  - Auth Bypass Detector
  - API Security Detector
  - Cache Poisoning Detector
  - Header Injection Detector
  - OAuth Detector
  - Rate Limit Bypass Detector
  - Brute Force Detector
- **Export Formats**: HTML, JSON, Markdown, PDF (future)
- **Rate Limit**: 2.0 req/sec per host
- **Timeout**: 120 minutes per scan
- **Custom Detectors**: Support for user-uploaded detectors
- **Priority Support**: Dedicated Slack/Discord channel

## Implementation Details

### Architecture

```
subscription.py          # Tier definitions, limits, validation logic
webapp.py               # FastAPI endpoints with tier enforcement
templates/index.html    # UI with tier-based feature gating
```

### Key Components

#### 1. Tier Configuration (`subscription.py`)
```python
TIER_CONFIGS = {
    SubscriptionTier.FREE: TierLimits(...),
    SubscriptionTier.PRO: TierLimits(...),
    SubscriptionTier.ENTERPRISE: TierLimits(...),
}
```

#### 2. Validation Functions
- `can_start_scan()` - Check concurrent scan limits
- `validate_scan_scope()` - Enforce URL count limits
- `is_detector_allowed()` - Filter detectors by tier
- `filter_detectors_by_tier()` - Get allowed detector list

#### 3. Web UI Integration
- Tier badge in header (shows current plan)
- Feature gating for recon mode (disabled in FREE)
- Error messages on limit violations (HTTP 403)
- Detector list viewer (shows enabled detectors)
- Tier switcher buttons (for MVP testing)

### Current State (MVP)

The current implementation uses a **simulated user tier** stored in a global variable:

```python
# webapp.py
CURRENT_USER_TIER = SubscriptionTier.FREE  # Change for testing
```

**To test different tiers:**
1. Use the tier switcher buttons in UI (FREE/PRO/ENT)
2. Or manually change `CURRENT_USER_TIER` in `webapp.py` and restart server

### Next Steps for Production

To make this production-ready, you need:

1. **User Authentication**
   - JWT tokens or session-based auth
   - Login/signup pages
   - Password hashing (bcrypt)

2. **Database Integration**
   - User accounts table (id, email, password_hash, tier, created_at)
   - Subscriptions table (user_id, tier, start_date, end_date, status)
   - Scan history table (job_id, user_id, status, created_at)
   - SQLAlchemy ORM + PostgreSQL/MySQL

3. **Billing Integration**
   - Stripe/Paddle for payments
   - Webhooks for subscription events (activated, canceled, failed payment)
   - Usage tracking (scan count, API calls)

4. **Tier Middleware**
   ```python
   from fastapi import Depends
   
   async def get_current_user(token: str) -> User:
       # Decode JWT, fetch from DB
       pass
   
   @app.post("/scan")
   async def start_scan(user: User = Depends(get_current_user)):
       tier = user.subscription.tier
       # Enforce limits based on tier
   ```

5. **API Key Management** (for ENTERPRISE)
   - Generate API keys for users
   - Rate limiting per key
   - Key rotation/revocation

6. **Usage Analytics**
   - Track scans per user per month
   - Monitor concurrent scan usage
   - Billing alerts on limit approaching

## Testing the Tier System

### Test Case 1: FREE Tier Limits
1. Set tier to FREE (click FREE button in UI)
2. Try to start scan in "Recon" mode
3. **Expected**: Error message - "Recon pipeline not available in FREE tier"

### Test Case 2: Concurrent Scan Limit
1. Set tier to FREE (max 1 concurrent scan)
2. Start a scan with a large domain (e.g., `tesla.com`)
3. While first scan is running, try to start another scan
4. **Expected**: Error message - "Concurrent scan limit reached (1). Upgrade for more."

### Test Case 3: PRO Tier Features
1. Set tier to PRO
2. Start scan in "Recon" mode
3. **Expected**: Scan starts successfully, recon pipeline enabled
4. Click "View Enabled Detectors" button
5. **Expected**: Shows 19 detectors (basic + advanced)

### Test Case 4: URL Scope Limits
(Not yet enforced - requires parsing scope file to count URLs)
1. Create `targets.csv` with 10 URLs
2. Set tier to FREE (max 5 URLs)
3. Start standard scan with `targets.csv`
4. **Expected**: Should reject with "URL limit exceeded"
   - **TODO**: Implement URL counting in `start_scan()` endpoint

## Pricing Recommendations

Based on competitive analysis:

- **FREE**: $0 (freemium model to attract users)
- **PRO**: $39/month ($468/year with 20% discount = $374/year)
- **ENTERPRISE**: $119/month ($1428/year with 20% discount = $1142/year)

**Comparison with competitors:**
- Burp Suite Pro: $449/year
- Nuclei Cloud: ~$50-100/month
- Acunetix: $4,500+/year
- Our ENTERPRISE: $1,142/year ✅ (competitive pricing)

## Feature Roadmap by Tier

### Planned Features (Future)

**PRO Tier Additions:**
- Custom wordlists for fuzzing
- Scheduled scans (cron-like)
- Team collaboration (2-3 seats)
- Slack/email notifications

**ENTERPRISE Additions:**
- White-label reports (custom branding)
- Multi-tenancy (unlimited team members)
- SSO (SAML/OAuth)
- Dedicated infrastructure
- SLA guarantee (99.9% uptime)
- Custom integrations (Jira, ServiceNow)

## Monetization Strategy

1. **Freemium Model**: FREE tier for hobbyists, converts ~2-5% to paid
2. **Usage-Based Upsell**: Limit violations prompt upgrade
3. **Annual Discounts**: 20% off for yearly subscriptions
4. **Educational Pricing**: 50% off for students (verify with email)
5. **Affiliate Program**: 20% commission for referrals

## Security Considerations

1. **Tier Bypass Prevention**
   - All tier checks server-side (never trust client)
   - Validate on every endpoint (not just UI)
   - Log tier violations for fraud detection

2. **Abuse Prevention**
   - Rate limiting per IP/user
   - CAPTCHA on signup
   - Email verification required
   - Monitor for trial abuse (temporary emails)

3. **Data Isolation**
   - Each user's scan results isolated
   - No cross-tenant data leakage
   - Encryption at rest for sensitive findings

## Support and Documentation

- **FREE**: Community forum (Discord/GitHub Discussions)
- **PRO**: Email support (24-48h response)
- **ENTERPRISE**: Priority support (4h response, dedicated channel)

## License

Tier system is proprietary for SaaS deployment. Open-source CLI version remains MIT licensed.

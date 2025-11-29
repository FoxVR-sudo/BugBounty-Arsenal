# Email Verification Setup Guide

## Overview
BugBounty Arsenal now includes email verification for new user signups. Users must verify their email address before they can log in.

## Features
- ✅ Email verification on signup
- ✅ Beautiful HTML email templates
- ✅ Secure token-based verification
- ✅ Password reset capability (ready to implement)
- ✅ Audit logging for verification events

## Setup Instructions

### 1. Gmail App Password (Recommended)

1. Go to your Google Account: https://myaccount.google.com/
2. Navigate to **Security** → **2-Step Verification** (enable if not already)
3. Scroll down to **App passwords**: https://myaccount.google.com/apppasswords
4. Select app: **Mail**
5. Select device: **Other (Custom name)** → Enter "BugBounty Arsenal"
6. Click **Generate**
7. Copy the 16-character password (e.g., `abcd efgh ijkl mnop`)

### 2. Configure Environment Variables

Edit your `.env` file (copy from `.env.example` if needed):

```bash
# Email Service Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your-email@gmail.com
SENDER_PASSWORD=abcdefghijklmnop  # 16-char app password (no spaces)
FRONTEND_URL=http://localhost:8000
```

**Important:** 
- Remove spaces from the app password
- For production, use your actual domain (e.g., `https://bugbountyarsenal.com`)

### 3. Alternative Email Providers

#### Outlook/Hotmail
```bash
SMTP_SERVER=smtp-mail.outlook.com
SMTP_PORT=587
SENDER_EMAIL=your-email@outlook.com
SENDER_PASSWORD=your-password
```

#### SendGrid (Production Recommended)
```bash
SMTP_SERVER=smtp.sendgrid.net
SMTP_PORT=587
SENDER_EMAIL=noreply@yourdomain.com
SENDER_PASSWORD=your-sendgrid-api-key
```

#### AWS SES
```bash
SMTP_SERVER=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SENDER_EMAIL=noreply@yourdomain.com
SENDER_PASSWORD=your-ses-smtp-credentials
```

## How It Works

### 1. User Registration Flow
```
User fills signup form
    ↓
Account created (is_verified=False)
    ↓
Verification email sent with unique token
    ↓
User clicks verification link
    ↓
Token validated, is_verified=True
    ↓
User can now log in
```

### 2. Email Template
The verification email includes:
- Professional HTML design
- Prominent "Verify Email Address" button
- Fallback text link
- Security notice
- Branded footer

### 3. Security Features
- Tokens are cryptographically secure (32 bytes, URL-safe)
- One-time use tokens (cleared after verification)
- Tokens stored hashed in database
- Verification required before login

## Testing Email Verification

### 1. Development Testing (Console Output)
For local testing without email:

```python
# In email_service.py, modify send_verification_email:
def send_verification_email(self, recipient_email: str, verification_token: str):
    verification_link = f"{self.frontend_url}/verify-email?token={verification_token}"
    print(f"\n{'='*60}")
    print(f"📧 VERIFICATION EMAIL (DEV MODE)")
    print(f"{'='*60}")
    print(f"To: {recipient_email}")
    print(f"Link: {verification_link}")
    print(f"{'='*60}\n")
    return True  # Pretend it worked
```

### 2. Production Testing Checklist

1. **Create test account:**
   ```bash
   curl -X POST http://localhost:8000/api/signup \
     -F "email=test@example.com" \
     -F "full_name=Test User" \
     -F "password=TestPassword123"
   ```

2. **Check email inbox** for verification email

3. **Click verification link** or visit manually:
   ```
   http://localhost:8000/verify-email?token=YOUR_TOKEN_HERE
   ```

4. **Verify success page** shows green checkmark

5. **Try to log in** - should work now

6. **Try logging in without verification** - should fail with error:
   ```
   "Please verify your email address before logging in"
   ```

## Troubleshooting

### Email Not Sending

1. **Check SMTP credentials:**
   ```python
   # Run in terminal:
   python -c "from email_service import email_service; print(email_service.sender_email)"
   ```

2. **Test SMTP connection:**
   ```python
   import smtplib
   server = smtplib.SMTP('smtp.gmail.com', 587)
   server.starttls()
   server.login('your-email@gmail.com', 'app-password')
   print("✓ SMTP connection successful!")
   server.quit()
   ```

3. **Check Gmail security:**
   - Ensure 2FA is enabled
   - Verify app password is correct (16 chars, no spaces)
   - Check for "blocked sign-in attempt" emails

### Email Goes to Spam

- Add SPF record to your domain
- Add DKIM signature
- Use a verified "From" address
- Warm up your sending IP
- Consider using SendGrid/Mailgun for production

### Token Invalid

- Token is one-time use only
- Check database: `SELECT verification_token FROM users WHERE email='test@example.com'`
- Token should be NULL after verification

## Production Recommendations

### 1. Use Professional Email Service
Replace Gmail with:
- **SendGrid** (12,000 free emails/month)
- **Mailgun** (5,000 free emails/month)
- **AWS SES** ($0.10 per 1,000 emails)
- **Postmark** (100 free emails/month)

### 2. Add Email Queue
For high volume, use background tasks:
```python
from celery import Celery
celery = Celery('tasks', broker='redis://localhost:6379')

@celery.task
def send_verification_email_async(email, token):
    email_service.send_verification_email(email, token)
```

### 3. Rate Limiting
Prevent abuse:
```python
# In webapp.py
@app.post("/api/signup")
@limiter.limit("5 per hour")  # Max 5 signups per hour per IP
async def signup(...):
    ...
```

### 4. Email Logging
Track delivery:
```python
# Add to email_service.py
import logging
logger = logging.getLogger(__name__)

def send_verification_email(self, recipient_email, token):
    try:
        # ... send email ...
        logger.info(f"Verification email sent to {recipient_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {recipient_email}: {e}")
        return False
```

## Daily Scan Limits

All tiers now have daily scan limits (except ENTERPRISE):

| Tier       | Daily Scans | Monthly Cost |
|------------|-------------|--------------|
| FREE       | 3/day       | €0           |
| BASIC      | 10/day      | €4.99        |
| PRO        | 50/day      | €9.99        |
| ENTERPRISE | Unlimited   | €49.99       |

Daily counters reset at midnight UTC.

## Support

For issues or questions:
- Check logs in terminal where server is running
- Enable debug mode: `uvicorn webapp:app --reload --log-level debug`
- Check database: `sqlite3 bugbounty_arsenal.db "SELECT * FROM users;"`

## Next Steps

- [ ] Add password reset functionality (code template in `email_service.py`)
- [ ] Add email change verification
- [ ] Add email preferences (notification settings)
- [ ] Add email templates for scan completion
- [ ] Add webhook notifications (Slack/Discord)

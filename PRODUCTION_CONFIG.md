# Production Configuration

## Environment Variables

### Server (.env)
```bash
# Production Settings
DEBUG=False
SECRET_KEY=m0oYLcfZGtJLDwxUI+6ltSjQcQ9wOz5Zkq4MFXq381c7Uss5yUErpJM2IuJLQg0O

# Allowed Hosts
ALLOWED_HOSTS=bugbounty-arsenal.com,www.bugbounty-arsenal.com,127.0.0.1,localhost

# CSRF Settings
CSRF_TRUSTED_ORIGINS=https://bugbounty-arsenal.com,https://www.bugbounty-arsenal.com

# Database
DATABASE_URL=postgresql://bugbount_user:BugBounty2026!@localhost:5432/bugbount_db

# Email (SendGrid)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=apikey
EMAIL_HOST_PASSWORD=<GENERATE_NEW_KEY_FROM_SENDGRID>
DEFAULT_FROM_EMAIL=noreply@bugbounty-arsenal.com
SENDGRID_API_KEY=<GENERATE_NEW_KEY_FROM_SENDGRID>
SENDGRID_FROM_EMAIL=noreply@bugbounty-arsenal.com
SENDGRID_FROM_NAME=BugBounty Arsenal

# Stripe (Live Keys) ✅ CONFIGURED
STRIPE_SECRET_KEY=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
STRIPE_PUBLISHABLE_KEY=pk_live_51SlR8t5oSlrc0LTCfM3YCYRujbD9c2Ksbdonr9zTuZBFnIutYTosZy0EMW1wVUModMJ6pLCTnbYgjth9kWn9GdZ900jufDT8Ms
STRIPE_PUBLIC_KEY=pk_live_51SlR8t5oSlrc0LTCfM3YCYRujbD9c2Ksbdonr9zTuZBFnIutYTosZy0EMW1wVUModMJ6pLCTnbYgjth9kWn9GdZ900jufDT8Ms
STRIPE_WEBHOOK_SECRET=<GET_FROM_STRIPE_DASHBOARD>

# Frontend URL
FRONTEND_URL=https://bugbounty-arsenal.com

# Redis/Celery (Optional)
REDIS_HOST=localhost
REDIS_PORT=6379
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Security
SECURE_SSL_REDIRECT=False
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
SECURE_HSTS_SECONDS=31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS=True
SECURE_HSTS_PRELOAD=True
```

### Frontend (.env.production)
```bash
REACT_APP_API_URL=https://bugbounty-arsenal.com/api
REACT_APP_STRIPE_PUBLISHABLE_KEY=pk_live_51SlR8t5oSlrc0LTCfM3YCYRujbD9c2Ksbdonr9zTuZBFnIutYTosZy0EMW1wVUModMJ6pLCTnbYgjth9kWn9GdZ900jufDT8Ms
```

## Integration Status

### ✅ Stripe Payments
- **Status**: Fully Configured
- **Test Result**: API connection successful
- **Balance**: €0.00 EUR (available), €0.00 EUR (pending)
- **Next Steps**: 
  1. Add webhook secret from Stripe dashboard
  2. Test payment flow
  3. Configure webhook endpoint at https://bugbounty-arsenal.com/api/webhooks/stripe/

### ⚠️ SendGrid Email
- **Status**: API Key Expired/Invalid
- **Current Behavior**: Emails logged to console
- **Action Required**:
  1. Login to https://app.sendgrid.com/settings/api_keys
  2. Create new API key with "Mail Send" permission
  3. Update SENDGRID_API_KEY in server .env
  4. Restart Gunicorn: `pkill -f gunicorn && ./start_gunicorn.sh`

### ✅ Security
- DEBUG=False
- Secure SECRET_KEY (50 chars)
- HTTPS security headers enabled
- HSTS configured (1 year)
- Secure cookies enabled

### ✅ Database
- PostgreSQL 9.6.22
- Migrations applied (0001-0006)
- Superuser: foxvr81@gmail.com
- Plans populated (Free, Pro, Enterprise)
- Scan categories populated (10 categories)

### ✅ Deployment
- GitHub Actions auto-deploy working
- Gunicorn 2 workers on 127.0.0.1:8000
- LiteSpeed reverse proxy
- Static files via public_html/

## Gunicorn (Django Backend)

**Location**: `/home/bugbount/app/`  
**Python Environment**: `/home/bugbount/virtualenv/app/3.11/`  
**Port**: 8000 (localhost only)

### Start/Restart Gunicorn

```bash
ssh -p 12545 bugbount@79.98.104.6
cd /home/bugbount/app
./start_gunicorn.sh
```

Or manually:
```bash
cd /home/bugbount/app
source /home/bugbount/virtualenv/app/3.11/bin/activate
gunicorn config.wsgi:application \
    --bind 127.0.0.1:8000 \
    --workers 3 \
    --daemon \
    --access-logfile logs/gunicorn-access.log \
    --error-logfile logs/gunicorn-error.log \
    --pid gunicorn.pid
```

### Check Status

```bash
ps aux | grep gunicorn | grep -v grep
```

Should show 1 master + 3 worker processes.

### Stop Gunicorn

```bash
pkill -f "gunicorn config.wsgi"
```

### View Logs

```bash
tail -f /home/bugbount/app/logs/gunicorn-error.log
tail -f /home/bugbount/app/logs/gunicorn-access.log
```

## Web Server Configuration

### LiteSpeed + Django Proxy Setup

The production environment uses LiteSpeed Web Server with an `.htaccess` file to proxy API requests to the Django backend (Gunicorn on port 8000).

**Location**: `/home/bugbount/public_html/.htaccess`

**Configuration**:
```apache
# Enable rewrite engine
RewriteEngine On

# Proxy API requests to Django backend (Gunicorn on port 8000)
RewriteCond %{REQUEST_URI} ^/api/ [OR]
RewriteCond %{REQUEST_URI} ^/admin/
RewriteRule ^(.*)$ http://127.0.0.1:8000/$1 [P,L]

# All other requests serve from React build (SPA)
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^ index.html [L]
```

This configuration ensures:
- All `/api/*` requests are proxied to Django (Gunicorn on port 8000)
- All `/admin/*` requests are proxied to Django Admin
- Static files are served directly by LiteSpeed
- React SPA routing works correctly (all non-file requests go to index.html)

**Deployment**: The `.htaccess` file is automatically deployed when pushing to the repository.

## Testing Endpoints

```bash
# Public API
curl https://bugbounty-arsenal.com/api/plans/
curl https://bugbounty-arsenal.com/api/scan-categories/

# Admin
https://bugbounty-arsenal.com/admin/login/
# User: foxvr81@gmail.com
# Pass: Admin123!@#

# Frontend
https://bugbounty-arsenal.com/
https://bugbounty-arsenal.com/login
https://bugbounty-arsenal.com/dashboard
```

## Stripe Webhook Setup

1. Go to https://dashboard.stripe.com/webhooks
2. Add endpoint: `https://bugbounty-arsenal.com/api/webhooks/stripe/`
3. Select events:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
4. Copy webhook secret and add to .env as `STRIPE_WEBHOOK_SECRET`

## SendGrid Domain Authentication

1. Go to https://app.sendgrid.com/settings/sender_auth
2. Authenticate domain: bugbounty-arsenal.com
3. Add DNS records provided by SendGrid
4. Verify domain authentication

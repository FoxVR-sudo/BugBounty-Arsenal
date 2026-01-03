# Railway Deployment Guide

## Step 1: Push to GitHub (ако още не е)
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin YOUR_GITHUB_REPO_URL
git push -u origin main
```

## Step 2: Railway Setup
1. Отиди на https://railway.app
2. Sign up with GitHub
3. Click "New Project"
4. Select "Deploy from GitHub repo"
5. Избери твоя repository

## Step 3: Add Services
Railway трябва да deploy-не 3 services:

### Service 1: Web (Django Backend)
- Root Directory: `/`
- Build Command: `docker build -t backend .`
- Start Command: `gunicorn config.wsgi:application --bind 0.0.0.0:$PORT`

### Service 2: Frontend (React)
- Root Directory: `/frontend`
- Build Command: `npm install && npm run build`
- Start Command: `npx serve -s build -l $PORT`

### Service 3: Redis
- Click "New" → "Database" → "Add Redis"

## Step 4: Environment Variables (за Web service)

Add these in Railway Dashboard → Your Service → Variables:

```
ENVIRONMENT=production
DEBUG=False
SECRET_KEY=your-random-secret-key-here
ALLOWED_HOSTS=.railway.app,bugbaunty-arsenal.com,www.bugbaunty-arsenal.com
DATABASE_URL=sqlite:///./bugbounty_arsenal.db
FRONTEND_URL=https://bugbaunty-arsenal.com

# Stripe Live
STRIPE_SECRET_KEY=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
STRIPE_PUBLISHABLE_KEY=pk_live_51SlR8t5oSlrc0LTCfM3YCYRujbD9c2Ksbdonr9zTuZBFnIutYTosZy0EMW1wVUModMJ6pLCTnbYgjth9kWn9GdZ900jufDT8Ms
STRIPE_WEBHOOK_SECRET=whsec_gVi21Oq9Yevyy3fjpEreauCqklycvw2A

# SendGrid
SENDGRID_API_KEY=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
SENDGRID_FROM_EMAIL=foxvr81@gmail.com
SENDGRID_FROM_NAME=BugBounty Arsenal

# Redis (Railway auto-generates this when you add Redis service)
REDIS_URL=${{Redis.REDIS_URL}}
CELERY_BROKER_URL=${{Redis.REDIS_URL}}
CELERY_RESULT_BACKEND=${{Redis.REDIS_URL}}

# Security
SECURE_SSL_REDIRECT=True
CSRF_COOKIE_SECURE=True
SESSION_COOKIE_SECURE=True
```

## Step 5: Custom Domain
1. Go to Service Settings → Domains
2. Click "Add Domain"
3. Enter: `bugbaunty-arsenal.com`
4. Railway ще даде DNS records - добави ги в твоя domain registrar

## Step 6: Stripe Webhook
След deploy, вземи Railway URL (напр. `https://your-app.railway.app`) и:
1. Отиди на https://dashboard.stripe.com/webhooks
2. Add endpoint: `https://your-app.railway.app/api/webhooks/stripe/`
3. Copy новия webhook secret
4. Update `STRIPE_WEBHOOK_SECRET` в Railway variables

## Cost
- Free tier: $5 credit/месец (достатъчно за тестване)
- Pro: $5/месец за неограничено

## Done! 🚀
Railway автоматично deploy-ва при всеки git push.

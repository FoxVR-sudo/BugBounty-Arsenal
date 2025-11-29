# BugBounty Arsenal v2.1 - UI & Subscription System

## 🎯 Последни Промени (Nov 29, 2025)

### ✅ Завършени Features:

1. **Модерен Landing Page** (`/`)
   - Hero section с gradient animations
   - Features showcase (6 основни функции)
   - Pricing table с 3 tier-а
   - Modern dark theme design
   - Responsive layout

2. **Преработена Tier Система**
   - ✨ **Recon инструментите сега достъпни във FREE tier** (понеже са open source)
   - Лимитирани по scope: FREE (10 subdomains), PRO (100), ENTERPRISE (unlimited)
   - Добавени нови лимити:
     - `max_subdomains_to_scan` - ограничение на брой поддомейни
     - `enable_subdomain_takeover` - takeover detection (PRO+)
     - `enable_cloud_metadata` - AWS/Azure/GCP checks (PRO+)
     - `enable_scheduled_scans` - cron-like scheduling (PRO+)
     - `enable_team_collaboration` - multi-user (PRO+)
     - `enable_custom_wordlists` - custom fuzzing (PRO+)
     - `enable_notifications` - Slack/email/webhooks (PRO+)

3. **Auth Pages** (MVP mock)
   - Login page (`/login`) - beautiful dark theme
   - OAuth buttons (Google, GitHub) - за сега mock
   - Auto-redirect към dashboard (bypass auth за тестване)

4. **Нови Routes**
   - `GET /` - Landing page
   - `GET /dashboard` - Scanner dashboard (бившият index)
   - `GET /login` - Login page
   - `POST /scan` - Start scan (with tier validation)
   - `POST /change-tier` - MVP tier switcher

## 📊 Обновени Tier Планове

### 🆓 FREE - $0/month
- **Concurrent Scans**: 1
- **Max URLs**: 5
- **Recon Pipeline**: ✅ (ограничен на 10 subdomains)
- **Detectors**: 5 basic (XSS, SQLi, Headers, Open Redirect, Secrets)
- **Export**: HTML only
- **Timeout**: 10 minutes

**Нови лимити:**
- Max 10 discovered subdomains
- No subdomain takeover detection
- No cloud metadata checks
- No scheduled scans
- No team collaboration

### 💎 PRO - $39/month
- **Concurrent Scans**: 3
- **Max URLs**: 100
- **Recon Pipeline**: ✅ (пълен, до 100 subdomains)
- **Detectors**: 19 (basic + advanced)
- **Export**: HTML, JSON, Markdown
- **Timeout**: 60 minutes

**Нови features:**
- ✅ Subdomain takeover detection
- ✅ Cloud metadata checks (AWS/Azure/GCP)
- ✅ Cloudflare solver
- ✅ Scheduled scans
- ✅ Team collaboration (до 3 seats)
- ✅ Custom wordlists
- ✅ Slack/Email notifications

### 🚀 ENTERPRISE - $119/month
- **Concurrent Scans**: 10
- **Max URLs**: Unlimited
- **Recon Pipeline**: ✅ (unlimited subdomains)
- **Detectors**: 28+ (all)
- **Export**: HTML, JSON, Markdown, PDF
- **Timeout**: 180 minutes

**Enterprise features:**
- ✅ Nuclei CVE scanner (3000+ templates)
- ✅ Mobile app scanner (APK/IPA)
- ✅ API access (REST endpoints)
- ✅ Unlimited team members
- ✅ Custom detectors upload
- ✅ Priority support (4h response)

## 🗂️ File Structure

```
templates/
├── landing.html      # NEW - Modern landing page
├── dashboard.html    # RENAMED - Main scanner UI (бившият index.html)
└── login.html        # NEW - Auth page (mock)

subscription.py       # UPDATED - Tier configs with new limits
webapp.py            # UPDATED - New routes (/, /dashboard, /login)
TIER_SYSTEM_README.md # Original tier documentation
UI_UPDATE_NOTES.md   # This file
```

## 🚀 Как да тествaш:

1. **Стартирай сървъра:**
   ```bash
   cd /home/foxvr/Documents/BugBounty-Arsenal
   source .venv/bin/activate
   python -m uvicorn webapp:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Отвори браузър:**
   - `http://localhost:8000` - Landing page
   - `http://localhost:8000/login` - Login (натисни Sign In → auto redirect)
   - `http://localhost:8000/dashboard` - Scanner dashboard

3. **Тествай tier системата:**
   - Натисни FREE/PRO/ENT бутоните в dashboard header
   - Опитай да стартираш recon scan в различни tier-ове
   - Виж как се променят лимитите (concurrent scans, URLs, detectors)

4. **Провери pricing page:**
   - Scroll down на landing page до "Simple, Transparent Pricing"
   - Виж 3-те tier карти с features списъци

## 💡 Бизнес Логика:

**Защо Recon е достъпен във FREE tier?**
- Subfinder, HTTPX, Nuclei са open source инструменти
- Потребителите могат да ги изтеглят безплатно
- Вместо това лимитираме **scope** и **advanced features**:
  - FREE: само 10 subdomains, no takeover detection
  - PRO: 100 subdomains + takeover + cloud metadata
  - ENTERPRISE: unlimited + Nuclei CVE scans

**Стратегия за Upsell:**
1. FREE tier дава вкус на инструмента (basic scans)
2. При голям домейн (>10 subdomains) → показва "Upgrade to PRO"
3. PRO добавя автоматизация (scheduled scans, notifications)
4. ENTERPRISE за teams и production workflows (API, custom detectors)

## 📋 Next Steps (за Production):

### 1. Database & Auth (приоритет HIGH)
- [ ] SQLAlchemy + PostgreSQL
- [ ] User accounts table (id, email, password_hash, tier, created_at)
- [ ] JWT token authentication
- [ ] Password hashing (bcrypt)
- [ ] OAuth2 integration (Google, GitHub)

### 2. Billing Integration
- [ ] Stripe/Paddle payment gateway
- [ ] Subscription webhooks (activated, canceled, failed)
- [ ] Usage tracking (scan count per month)
- [ ] Automatic tier enforcement via DB

### 3. Enhanced Dashboard
- [ ] Scan history table (не само active scans)
- [ ] Export buttons (Download JSON/Markdown)
- [ ] Filters (by severity, by detector type)
- [ ] Search functionality

### 4. Team Features (PRO+)
- [ ] Invite team members via email
- [ ] Role-based access control (admin, member, viewer)
- [ ] Shared scan results
- [ ] Team activity log

### 5. API Access (ENTERPRISE)
- [ ] REST API endpoints (`/api/v1/scan`, `/api/v1/results`)
- [ ] API key generation + rotation
- [ ] Rate limiting per key
- [ ] Swagger/OpenAPI docs

### 6. Notifications (PRO+)
- [ ] Slack webhook integration
- [ ] Email notifications (via SendGrid/Mailgun)
- [ ] Discord webhook
- [ ] Custom webhook URLs

### 7. Scheduled Scans (PRO+)
- [ ] Cron-like scheduling UI
- [ ] Celery/RQ for background jobs
- [ ] Scan queue management
- [ ] Email reports on completion

## 🎨 Design Choices:

- **Dark Theme**: Modern, appealing за security researchers
- **Gradient Accents**: Purple/Blue gradient (#7c3aed → #0ea5e9)
- **Glassmorphism**: Transparent cards с backdrop blur
- **Responsive**: Grid layout adapts to mobile
- **Animations**: Subtle hover effects, no aggressive motion

## 🔧 Technical Notes:

1. **Landing page е 100% static** - може да се deploy-не на CDN
2. **Dashboard изисква auth** (за production добави middleware)
3. **Tier config е centralized** в `subscription.py` - лесна промяна
4. **MVP bypass auth** - в `login.html` има JS redirect към dashboard
5. **Auto-reload** - uvicorn --reload за development

## 📝 TODO за Morning:

- [ ] Add database models (User, Subscription, ScanHistory)
- [ ] Implement real JWT auth
- [ ] Create signup page
- [ ] Add password reset flow
- [ ] Implement scan history table in dashboard
- [ ] Add export buttons (JSON/Markdown download)
- [ ] Create admin panel (user management, tier changes)

## 🐛 Known Issues:

1. **No real auth** - всички могат да видят dashboard
2. **In-memory tier** - загубва се при restart
3. **No scan history** - само active scans се показват
4. **No URL count validation** - не проверява реално съдържанието на targets.csv
5. **No subdomain limit enforcement** - не проверява колко subdomains намира subfinder

## 💰 Revenue Projection:

**Conservative estimate:**
- 100 FREE users → 3-5 convert to PRO ($39/mo) = $117-195/mo
- 10 PRO users → 1-2 convert to ENT ($119/mo) = $119-238/mo
- **Total MRR**: ~$236-433/mo
- **Annual**: ~$2,832-5,196/year

**Optimistic (year 1):**
- 1000 FREE users → 50 PRO ($39) = $1,950/mo
- 50 PRO → 5 ENT ($119) = $595/mo
- **Total MRR**: $2,545/mo
- **Annual**: ~$30,540/year

**Costs:**
- Hosting (AWS/DigitalOcean): $50-100/mo
- Database (PostgreSQL): $15-50/mo
- Email service (SendGrid): $15-30/mo
- Stripe fees (2.9% + $0.30): ~$75/mo @ $2.5k MRR
- **Total costs**: ~$155-255/mo
- **Net profit**: ~$2,290-2,390/mo ($27k-29k/year)

---

**Status**: ✅ Landing page готов, Tier система updated, Auth pages създадени (mock)  
**Next**: Database integration + Real authentication  
**ETA**: 2-3 days за full production-ready auth system

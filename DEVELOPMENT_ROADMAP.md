# BugBounty Arsenal - Development Roadmap
**Created:** December 6, 2025  
**Status:** Active Development

---

## 🎯 PRIORITY TASKS (Current Sprint)

### 1. Dashboard Detector Menu Organization
**Status:** 🔴 TODO  
**Description:** Разделяне на детекторите на пасивни и активни в странично или горно меню

**Requirements:**
- Sidebar или top navigation menu
- Категория "Passive Detectors" (9 детектора)
- Категория "Active Detectors" (30 детектора)
- Визуално разделяне и ясна индикация

**Files to modify:**
- `templates/dashboard.html` - add sidebar/navigation
- `static/css/` - styling for menu
- Consider creating separate template: `templates/base_dashboard.html`

---

### 2. Scan Type Pages (Multiple Scan Categories)
**Status:** 🔴 TODO  
**Description:** Разделяне на scan типовете на отделни страници с уникални настройки

**Scan Types:**
1. **API Security Scan** (`/dashboard/api-scan/`)
   - Detectors: API Security, GraphQL, OAuth, JWT, Rate Limit
   - Settings: API auth (Bearer, Basic, OAuth), headers, rate limiting
   - Input: URL + CSV file option

2. **Vulnerability Scan** (`/dashboard/vulnerability-scan/`)
   - Detectors: XSS, SQLi, SSRF, XXE, SSTI, Command Injection, LFI
   - Settings: Injection depth, payload sets, timeout
   - Input: URL + CSV file option

3. **Mobile App Scan** (`/dashboard/mobile-scan/`)
   - Detectors: Mobile-specific (to be added)
   - Settings: Platform (iOS/Android), APK/IPA upload
   - Input: App package + URL for API endpoints

4. **Web Security Scan** (`/dashboard/web-scan/`) - Default
   - Detectors: All 39 detectors
   - Settings: Intensity (quick/standard/deep/brutal)
   - Input: URL + CSV file option

5. **Custom Scan** (`/dashboard/custom-scan/`)
   - Detectors: User selects which detectors to run
   - Settings: Per-detector configuration
   - Input: URL + CSV file option

**Common Requirements:**
- URL input field (single target)
- CSV file upload (multiple targets) - **mutually exclusive with URL**
- Scan intensity selector
- Detector selection (checkboxes)
- Results preview
- Download report button

**Files to create:**
- `templates/dashboard/api_scan.html`
- `templates/dashboard/vulnerability_scan.html`
- `templates/dashboard/mobile_scan.html`
- `templates/dashboard/web_scan.html`
- `templates/dashboard/custom_scan.html`
- `scans/views.py` - add view functions for each scan type
- `config/urls.py` - add URL routes

---

### 3. Remove Tier Feature Restrictions
**Status:** 🔴 TODO  
**Description:** Премахване на ограничения за функции между плановете

**Current Restrictions (to REMOVE):**
- ❌ PRO/ENTERPRISE only scope file
- ❌ Disabled features for FREE tier
- ❌ Brutal scan mode restriction

**Keep Only:**
- ✅ Daily scan limits (FREE: 3, BASIC: 10, PRO: 50, ENTERPRISE: unlimited)
- ✅ Monthly scan limits
- ✅ Storage limits (reports retention)

**Files to modify:**
- `templates/dashboard.html` - remove `{% if tier_limits.is_pro_or_enterprise %}` checks
- `scans/models.py` - verify no tier checks in model logic
- `scans/views.py` - remove tier feature checks
- `subscriptions/models.py` - keep only scan count limits

---

### 4. Admin Panel (Django Admin Enhancement)
**Status:** 🔴 TODO  
**Description:** Comprehensive admin panel за управление на цялата система

**Admin Features Required:**

#### 4.1 User Management
- List all users (email, tier, scans_today, scans_month, joined_date)
- Edit user details
- Change user tier manually
- Reset user password
- Ban/unban users
- View user scan history

#### 4.2 Subscription Management
- View all subscriptions
- Edit subscription limits (daily, monthly)
- Create custom subscription plans
- View payment history (Stripe integration)
- Apply discounts/coupons
- Manual subscription upgrades/downgrades

#### 4.3 Scan Management
- View all scans (running, completed, failed)
- Cancel running scans
- Delete old scans
- View scan statistics (total scans, vulns found, avg duration)
- Export scan data (CSV, JSON)

#### 4.4 Detector Management
- Enable/disable specific detectors globally
- Configure detector settings (timeouts, payloads, etc.)
- View detector performance stats (avg time, success rate)
- Test individual detectors

#### 4.5 System Settings
- Configure daily/monthly limits per tier
- Email settings (SMTP config)
- Stripe API keys
- Cloudflare bypass settings
- Rate limiting configuration
- Storage management (cleanup old reports)

#### 4.6 Analytics Dashboard
- Total users by tier
- Scans per day/week/month (graph)
- Most used detectors
- Vulnerability distribution (pie chart)
- Revenue statistics (if Stripe integrated)
- System health (Celery, Redis, Database)

**Files to create/modify:**
- `users/admin.py` - register User model with custom admin
- `scans/admin.py` - register Scan model with filters/actions
- `subscriptions/admin.py` - register Subscription with custom views
- `templates/admin/` - custom admin templates
- `static/admin/` - custom admin CSS/JS
- Consider: Django Admin customization or build custom admin UI

**Django Admin Customization:**
- Custom list_display, list_filter, search_fields
- Custom admin actions (bulk operations)
- Inline editing for related models
- Custom admin dashboard with charts (use django-admin-charts or Chart.js)

---

## 🔧 TECHNICAL TASKS

### Fix Pylance Import Errors (Low Priority)
**Status:** 🟡 OPTIONAL  
**Description:** 215 import errors са false positives - пакетите са в venv/Docker

**Solution Options:**
1. Add `.vscode/settings.json` with proper Python path
2. Configure `pyrightconfig.json` to use venv
3. Ignore - не пречат на функционалността

**Files:**
```json
// .vscode/settings.json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "python.analysis.extraPaths": ["${workspaceFolder}"]
}
```

---

## 📅 SPRINT TIMELINE

### 5. Scan Results Page & Report Export System
**Status:** 🔴 TODO  
**Priority:** HIGH  
**Description:** Dedicated results page с автоматично storage management и multi-format export

**Requirements:**

#### 5.1 Results Storage System
- Store scan results with expiration policy:
  - **FREE tier:** 7 days retention or 100MB limit
  - **BASIC tier:** 30 days retention or 500MB limit
  - **PRO tier:** 90 days retention or 2GB limit
  - **ENTERPRISE tier:** 365 days retention or 10GB limit
- Auto-cleanup job (Celery Periodic Task) runs daily
- Storage quota tracking per user
- Warning notifications when approaching limits

#### 5.2 Results Page (`/dashboard/results/`)
- List all scan results with filters:
  - Date range picker
  - Status filter (completed/failed)
  - Severity filter (critical/high/medium/low)
  - Search by target URL
- Scan result card shows:
  - Target URL
  - Scan date/time
  - Vulnerabilities found (count by severity)
  - Status badge
  - Actions: View, Export, Delete
- Pagination (25 results per page)
- Bulk actions (delete multiple, export multiple)

#### 5.3 Single Result Detail Page (`/dashboard/results/<scan_id>/`)
- Full scan report with:
  - Executive Summary (overview, statistics)
  - Vulnerability List (grouped by severity)
  - Detailed findings per vulnerability:
    - Title, Severity, CVSS score
    - Description
    - Affected URL/endpoint
    - Payload used
    - Response snippet
    - Remediation steps
    - References (OWASP, CWE)
  - Timeline (scan start/end, duration)
  - Detectors used (active/passive)
  - Raw response data (collapsible)

#### 5.4 Multi-Format Report Export
**Export Formats:**

1. **HTML Report** (`report_<scan_id>.html`)
   - Styled professional report
   - Includes charts (vulnerability distribution pie chart)
   - Embedded CSS (no external dependencies)
   - Print-friendly layout
   - Table of contents with anchor links

2. **PDF Report** (`report_<scan_id>.pdf`)
   - Convert HTML to PDF using WeasyPrint or ReportLab
   - Professional header/footer with logo
   - Page numbers
   - Cover page with executive summary
   - Suitable for client delivery

3. **JSON Report** (`report_<scan_id>.json`)
   - Machine-readable format
   - Full vulnerability data
   - Schema:
   ```json
   {
     "scan_id": "uuid",
     "target": "example.com",
     "started_at": "2025-12-06T12:00:00Z",
     "completed_at": "2025-12-06T12:15:00Z",
     "vulnerabilities": [
       {
         "id": "vuln_001",
         "title": "XSS in search parameter",
         "severity": "high",
         "cvss": 7.3,
         "url": "https://example.com/search?q=<payload>",
         "description": "...",
         "remediation": "...",
         "references": ["OWASP-A03", "CWE-79"]
       }
     ],
     "statistics": {
       "total_vulnerabilities": 15,
       "critical": 2,
       "high": 5,
       "medium": 6,
       "low": 2
     }
   }
   ```

4. **CSV Report** (`report_<scan_id>.csv`)
   - Spreadsheet-friendly format
   - Columns: ID, Title, Severity, CVSS, URL, Category, Status
   - Suitable for importing to Excel/Google Sheets
   - Easy filtering and sorting

**Export Features:**
- Single export: Download one format at a time
- Bulk export: Download all formats as ZIP archive
- Scheduled exports: Email report on scan completion (optional)
- API endpoint: `/api/scans/<id>/export/?format=html|pdf|json|csv`

**Files to create:**
- `scans/reports.py` - Report generation logic
- `scans/exporters.py` - Export format handlers
- `templates/reports/scan_report.html` - HTML report template
- `templates/dashboard/results.html` - Results listing page
- `templates/dashboard/result_detail.html` - Single result page
- `scans/views.py` - Add report views
- `scans/tasks.py` - Add cleanup task
- `scans/management/commands/cleanup_old_reports.py` - Manual cleanup command

**Dependencies to add:**
```
weasyprint==60.1  # HTML to PDF conversion
reportlab==4.0.7  # Alternative PDF generation
```

---

### Week 1 (Dec 6-12, 2025)
- ✅ Day 1: Plan creation (this document)
- 🔴 Day 2-3: Task #1 - Dashboard menu reorganization
- 🔴 Day 4-5: Task #5 - Results page & Report export (HIGH PRIORITY)
- 🔴 Day 6-7: Task #3 - Remove tier restrictions

### Week 2 (Dec 13-19, 2025)
- 🔴 Day 1-3: Task #2 continued - (Mobile, Custom scan pages)
- 🔴 Day 4-7: Task #4 - Admin panel (Phase 1: User + Scan management)

### Week 3 (Dec 20-26, 2025)
- 🔴 Task #4 continued - Admin panel (Phase 2: Analytics + Settings)
- 🔴 Testing and bug fixes
- 🔴 Documentation updates

---

## 🎨 UI/UX IMPROVEMENTS

### Dashboard Navigation
```
┌─────────────────────────────────────────────────────────┐
│  BugBounty Arsenal        [User] [Logout]               │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────┐  ┌──────────────────────────────────────┐ │
│  │ MENU     │  │ CONTENT AREA                         │ │
│  │          │  │                                       │ │
│  │ 🌐 Web   │  │ [Scan Form]                          │ │
│  │ 🔌 API   │  │                                       │ │
│  │ 🐛 Vuln  │  │ [Active Scans]                       │ │
│  │ 📱 Mobile│  │                                       │ │
│  │ ⚙️  Custom│  │ [Scan History]                      │ │
│  │          │  │                                       │ │
│  │ ──────── │  │                                       │ │
│  │ Passive  │  └───────────────────────────────────────┘ │
│  │ Active   │                                            │
│  └──────────┘                                            │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 DATABASE SCHEMA UPDATES (if needed)

### Scan Model Enhancement
```python
# scans/models.py
class Scan(models.Model):
    # ... existing fields ...
    scan_category = models.CharField(
        max_length=20,
        choices=[
            ('web', 'Web Security'),
            ('api', 'API Security'),
            ('vulnerability', 'Vulnerability Assessment'),
            ('mobile', 'Mobile App Security'),
            ('custom', 'Custom Scan')
        ],
        default='web'
    )
    enabled_detectors = models.JSONField(default=list)  # List of detector names
    scan_config = models.JSONField(default=dict)  # Scan-specific settings
```

---

## 🚀 DEPLOYMENT CHECKLIST (After Completion)

- [ ] Run migrations: `python manage.py makemigrations && python manage.py migrate`
- [ ] Collect static files: `python manage.py collectstatic --noinput`
- [ ] Create admin superuser: `python manage.py createsuperuser`
- [ ] Test all scan types
- [ ] Test admin panel
- [ ] Update documentation (README.md, USAGE_GUIDE.md)
- [ ] Git commit and push
- [ ] Docker rebuild: `docker compose build --no-cache`
- [ ] Deploy to production (if applicable)

---

## 📝 NOTES

- All scan types must support both URL input and CSV file upload (mutually exclusive)
- Detector count: 30 active + 9 passive = 39 total
- Subscription limits apply only to scan COUNT, not features
- Admin panel must be accessible only to superusers
- Mobile scanner may need additional dependencies (apktool, frida, etc.)

---

## ✅ COMPLETED TASKS

- ✅ Django 6.0 + DRF setup
- ✅ Docker Compose (4 containers)
- ✅ JWT + Session authentication
- ✅ 39 security detectors
- ✅ Basic dashboard UI
- ✅ Celery background tasks
- ✅ Progress tracking fields (progress, current_step)
- ✅ Fix disabled form fields issue

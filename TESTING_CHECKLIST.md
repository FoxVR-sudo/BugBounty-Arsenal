# 🧪 Testing Checklist - December 15, 2025

## ✅ Система Готова за Тестване

### 🐳 Docker Containers Status
```bash
✅ bugbounty-web      - UP (healthy)    - Port 8000
✅ bugbounty-redis    - UP (healthy)    - Port 6380
⚠️  bugbounty-celery  - UP (unhealthy)  - Background tasks
⚠️  bugbounty-celery-beat - UP (unhealthy) - Scheduled tasks
```

**Note:** Celery unhealthy не блокира основната функционалност. Scans ще работят синхронно.

---

## 🎯 Какво е Готово

### 1. **5 Главни Сканера** ✅
- 🔭 **Reconnaissance Scanner** - `/scan/reconnaissance/`
- 🌐 **Web Application Scanner** - `/scan/web/`
- 🚀 **API Security Scanner** - `/scan/api/`
- 📱 **Mobile Security Scanner** - `/scan/mobile/`
- 🛡️ **Comprehensive Scanner** - `/scan/comprehensive/`

### 2. **Progress Tracking System** ✅
- Progress bar с проценти (0-100%)
- Real-time status updates (polling на 2s)
- Current detector display
- Active processes list
- Vulnerability counter
- Auto-stop при завършване

### 3. **Frontend Updates** ✅
- Dashboard показва 5 scanner cards
- Base scanner template с progress UI
- scan-handler.js с progress polling
- api-client.js с getScanDetails()

### 4. **Backend Ready** ✅
- Scan model с progress field
- API endpoint: GET /api/scans/{id}/
- ScanDetailSerializer с всички данни
- JWT authentication работи

---

## 🧪 Тестов План

### Test 1: Dashboard
```bash
# URL
http://localhost:8000/dashboard/

# Очаквано:
✓ 5 scanner cards (не 12)
✓ Reconnaissance, Web, API, Mobile, Comprehensive
✓ Различни badges (Core, Pro, Enterprise)
✓ Click на card води към scanner page
```

### Test 2: Reconnaissance Scanner
```bash
# URL
http://localhost:8000/scan/reconnaissance/

# Features to test:
✓ 8 detector checkboxes:
  - Subdomain Takeover
  - Directory Listing
  - Secret Detection
  - Security Headers
  - CVE Database
  - Technology Detection
  - CORS Misconfiguration
  - Open Redirect

✓ Crawl depth selector
✓ Include subdomains checkbox
✓ Target URL input
✓ "Start Scan" button
```

### Test 3: Web Application Scanner
```bash
# URL
http://localhost:8000/scan/web/

# Features to test:
✓ 16 detector checkboxes (XSS, SQLi, CSRF, LFI, XXE, SSTI, etc.)
✓ Scan depth (basic/standard/comprehensive)
✓ Follow redirects checkbox
✓ Test subdomains checkbox
✓ Target URL input
```

### Test 4: API Security Scanner
```bash
# URL
http://localhost:8000/scan/api/

# Features to test:
✓ 10 detector checkboxes (JWT, GraphQL, OAuth, NoSQL, etc.)
✓ API type selector (REST/GraphQL/SOAP/gRPC)
✓ Authentication token input
✓ OpenAPI spec URL input
```

### Test 5: Mobile Scanner
```bash
# URL
http://localhost:8000/scan/mobile/

# Features to test:
✓ 8 detector checkboxes (SSL pinning, root detection, etc.)
✓ Platform selector (Android/iOS/Both)
✓ APK/IPA file upload
✓ Dynamic analysis checkbox
```

### Test 6: Comprehensive Scanner
```bash
# URL
http://localhost:8000/scan/comprehensive/

# Features to test:
✓ 40+ detector checkboxes (всички)
✓ 3-column grid layout
✓ Scan mode (fast/balanced/thorough/aggressive)
✓ Thread count (5/10/20/50)
✓ "Select All" / "Deselect All" buttons
```

### Test 7: Progress Bar (DEMO)
```bash
# URL
http://localhost:8888/test_progress.html

# Actions:
1. Click "Start Demo Scan"
2. Watch progress bar fill (0% → 100%)
3. Watch detectors rotate
4. See "Completed" message

# Expected:
✓ Smooth animation
✓ Progress percentage updates
✓ Current detector changes
✓ Active detectors grid updates
✓ Completion status at 100%
```

### Test 8: Real Scan Progress
```bash
# Steps:
1. Login: http://localhost:8000/login/
   Email: test@test.com
   Password: test123

2. Go to: http://localhost:8000/scan/web/

3. Enter target: https://demo.testfire.net

4. Select detectors (XSS, SQLi, CSRF)

5. Click "Start Scan"

# Expected:
✓ Scan results section appears
✓ Progress bar starts at 0%
✓ Progress updates every 2 seconds
✓ Current detector displays
✓ Active detectors list shows
✓ Status changes to "Completed"
✓ Final results display
```

---

## 🔍 API Testing

### Test API Endpoints

```bash
# 1. Health Check
curl http://localhost:8000/health/
# Expected: {"status": "healthy", "timestamp": "..."}

# 2. Login
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123"}'
# Expected: {"access": "...", "refresh": "..."}

# 3. Get User Scans
curl http://localhost:8000/api/scans/status/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
# Expected: [{"id": 1, "target": "...", "status": "...", ...}, ...]

# 4. Get Scan Details (with progress)
curl http://localhost:8000/api/scans/42/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
# Expected: {"progress": 65, "current_detector": "...", ...}
```

---

## 🐛 Known Issues

### 1. Celery Unhealthy
**Status:** ⚠️ Known issue  
**Impact:** Async scans може да не работят  
**Workaround:** Scans ще се изпълняват синхронно  
**Fix:** `sudo docker restart bugbounty-celery bugbounty-celery-beat`

### 2. Raw Results Field
**Status:** ⚠️ Database constraint  
**Impact:** Не може да се създават нови scans от shell  
**Workaround:** Използвай API endpoint `/api/scans/start/`  
**Fix:** Migration може би нужна

### 3. CORS (евентуално)
**Status:** ❓ Неизвестно  
**Impact:** API calls от frontend може да fallback  
**Workaround:** Frontend и backend са на същия домейн  

---

## 📝 Test Credentials

```
User 1:
Email: test@test.com
Password: test123

User 2:
Email: testuser@example.com
Password: (unknown - use reset или login with test@test.com)

Admin:
Username: admin
Password: (set via createsuperuser if needed)
```

---

## 🚀 Quick Start Commands

```bash
# Check Docker status
sudo docker ps

# Restart all containers
sudo docker-compose restart

# View logs
sudo docker logs bugbounty-web --tail 50

# Access Django shell
sudo docker exec -it bugbounty-web python manage.py shell

# Open in browser
firefox http://localhost:8000/dashboard/ &

# Start demo server (if not running)
cd /home/foxvr/Documents/BugBounty-Arsenal
python3 -m http.server 8888 &
```

---

## 📂 Important Files

### Templates
```
templates/
├── base.html                     - Main layout
├── landing.html                  - Landing page
├── login.html                    - Login page
├── dashboard.html                - Main dashboard (5 scanners)
└── scans/
    ├── base_scanner.html         - Base template with progress UI
    ├── reconnaissance.html       - Recon scanner (8 detectors)
    ├── web.html                  - Web scanner (16 detectors)
    ├── api.html                  - API scanner (10 detectors)
    ├── mobile.html               - Mobile scanner (8 detectors)
    └── comprehensive.html        - All scanners (40+ detectors)
```

### JavaScript
```
static/js/
├── api-client.js                 - BugBountyAPI class with JWT
├── scan-handler.js               - Progress polling & scan logic
├── landing-handler.js            - Landing page interactions
└── theme.js                      - Dark/light theme toggle
```

### Backend
```
web/
├── views.py                      - 5 scanner view functions
└── urls.py                       - URL routing (5 scanner routes)

scans/
├── models.py                     - Scan model with progress field
├── views.py                      - API endpoints
└── serializers.py                - ScanDetailSerializer
```

### Documentation
```
├── PROGRESS_TRACKING_GUIDE.md    - Full progress system docs
├── TESTING_CHECKLIST.md          - This file
└── test_progress.html            - Interactive demo
```

---

## 🎯 Success Criteria

### Must Work:
- ✅ Dashboard loads and shows 5 scanners
- ✅ Each scanner page loads correctly
- ✅ Detector checkboxes are visible and clickable
- ✅ Login/logout works
- ✅ API endpoints respond
- ✅ Progress bar demo works

### Should Work:
- ⏳ Real scan starts successfully
- ⏳ Progress updates in real-time
- ⏳ Results display after completion
- ⏳ Multiple concurrent scans

### Nice to Have:
- ⏳ Fast scan completion (< 1 min)
- ⏳ Vulnerability results with details
- ⏳ Export functionality
- ⏳ Error handling and notifications

---

## 🔧 Troubleshooting

### Problem: Docker не работи
```bash
# Solution
sudo systemctl start docker
sudo docker-compose up -d
```

### Problem: Port 8000 заето
```bash
# Solution
sudo lsof -i :8000
sudo kill -9 PID
sudo docker restart bugbounty-web
```

### Problem: Frontend не се обновява
```bash
# Solution
# Clear browser cache (Ctrl+Shift+R)
# Or copy files again:
sudo docker cp templates/scans/base_scanner.html bugbounty-web:/app/templates/scans/
sudo docker cp static/js/scan-handler.js bugbounty-web:/app/static/js/
```

### Problem: Progress не се обновява
```bash
# Check if scan is updating
sudo docker exec bugbounty-web python manage.py shell -c "
from scans.models import Scan
scan = Scan.objects.filter(status='running').first()
print(f'Progress: {scan.progress if scan else 0}%')
"
```

---

## ✅ Ready for Testing!

**Всичко е копирано в Docker и готово за използване.**

**Start here:**
1. 🌐 Open: http://localhost:8000/dashboard/
2. 🎬 Demo: http://localhost:8888/test_progress.html
3. 📖 Read: PROGRESS_TRACKING_GUIDE.md

**Успех с тестването! 🚀**

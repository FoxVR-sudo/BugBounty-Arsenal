# 🛡️ Progress Tracking & Real-Time Updates

## Обзор

Системата сега включва real-time progress tracking с:
- **Progress bar с проценти** (0-100%)
- **Live status updates** - текущо изпълняващ се детектор
- **Active detectors list** - списък с активни процеси
- **Vulnerability counter** - брой намерени уязвимости
- **Real-time polling** - автоматично обновяване на данните

---

## 🎯 Архитектура

### Frontend Components

#### 1. **Progress Bar UI** (`base_scanner.html`)
```html
<!-- Progress Bar with percentage -->
<div id="progressSection">
    <div class="progress-bar-container">
        <div id="progressBar" style="width: 0%">0%</div>
    </div>
    <div id="progressPercentage">0%</div>
    <div id="currentDetector">Initializing...</div>
</div>

<!-- Active Detectors List -->
<div id="activeProcesses">
    <div id="processList">
        <!-- Dynamically updated -->
    </div>
</div>
```

#### 2. **JavaScript Progress Polling** (`scan-handler.js`)

**Ключови функции:**

```javascript
// Стартира polling за progress updates на всеки 2 секунди
function startProgressPolling(scanId)

// Обновява UI с текущ progress
function updateScanProgress(scanId)

// Спира polling след завършване на скана
function stopProgressPolling()

// Зарежда финални резултати
function loadScanResults(scanId)
```

**Workflow:**
1. User стартира scan → `startScan()` 
2. API връща scan ID
3. Стартира `startProgressPolling(scanId)` - polling на всеки 2 сек
4. `updateScanProgress()` извиква `api.getScanDetails(scanId)`
5. Обновява progress bar, current detector, active processes
6. При status='completed' → спира polling, показва резултати

#### 3. **API Client** (`api-client.js`)

```javascript
// Нов метод за получаване на scan детайли
async getScanDetails(scanId) {
    const response = await this.request(`${this.baseURL}/api/scans/${scanId}/`);
    if (response.ok) {
        return await response.json();
    }
    throw new Error('Failed to fetch scan details');
}
```

---

### Backend Components

#### 1. **Scan Model** (`scans/models.py`)

**Полета за progress tracking:**
```python
class Scan(models.Model):
    # Progress tracking
    progress = models.IntegerField(default=0, help_text='Scan progress percentage (0-100)')
    
    # Status field
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('running', 'Running'),
            ('completed', 'Completed'),
            ('failed', 'Failed'),
            ('cancelled', 'Cancelled')
        ]
    )
    
    # Results
    raw_results = models.JSONField(default=dict, blank=True)
    vulnerabilities_found = models.IntegerField(default=0)
```

#### 2. **API Endpoint** (`config/urls.py`)

```python
# Router автоматично създава:
GET /api/scans/{id}/  →  ScanViewSet.retrieve()

# Връща ScanDetailSerializer с всички полета:
{
    "id": 42,
    "target": "https://example.com",
    "scan_type": "web_security",
    "status": "running",
    "progress": 65,
    "current_detector": "XSS Pattern Detection",
    "active_detectors": ["sql_injection", "xss", "csrf"],
    "vulnerabilities": [...],
    "vulnerabilities_found": 3,
    "started_at": "2025-12-14T16:00:00Z",
    ...
}
```

---

## 📊 Progress Data Flow

```
┌─────────────────┐
│  Scan Started   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│  Frontend: startScan()       │
│  - Call API /api/scans/start/│
│  - Get scan ID: 42           │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  Start Progress Polling (every 2s)  │
│  - startProgressPolling(42)          │
└────────┬────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────┐
│  Poll Loop (2s interval)              │
│  ┌─────────────────────────────────┐ │
│  │ updateScanProgress(42)          │ │
│  │  ↓                              │ │
│  │ GET /api/scans/42/              │ │
│  │  ↓                              │ │
│  │ Response: {                     │ │
│  │   progress: 45,                 │ │
│  │   status: "running",            │ │
│  │   current_detector: "XSS",      │ │
│  │   active_detectors: [...]       │ │
│  │ }                               │ │
│  │  ↓                              │ │
│  │ Update UI:                      │ │
│  │  - Progress bar → 45%           │ │
│  │  - Current detector → "XSS"     │ │
│  │  - Active list → 3 detectors    │ │
│  └─────────────────────────────────┘ │
└──────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Status Changed: "completed" │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  stopProgressPolling()       │
│  loadScanResults(42)         │
│  - Show vulnerabilities      │
└─────────────────────────────┘
```

---

## 🎨 UI Components

### Progress Bar
```css
.progress-bar-container {
    background: var(--darker-bg);
    border-radius: 12px;
    height: 24px;
    border: 1px solid var(--border-color);
}

.progress-bar {
    background: linear-gradient(90deg, var(--primary-blue), #0096c7);
    width: 0%; /* Динамично обновяване */
    transition: width 0.3s ease;
}
```

### Current Detector
```html
<div id="currentDetector">
    <span style="color: var(--primary-blue);">🔍</span> 
    Running: <strong>XSS Pattern Detection</strong>
</div>
```

### Active Detectors Grid
```html
<div id="processList" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 0.5rem;">
    <div class="detector-badge">
        <span>⚡</span> SQL Injection
    </div>
    <div class="detector-badge">
        <span>⚡</span> CSRF Testing
    </div>
    <!-- Динамично обновяване -->
</div>
```

---

## 🚀 Използване

### 1. Стартиране на Scan

```javascript
// User попълва формата и кликва "Start Scan"
const form = document.getElementById('scanForm');
form.addEventListener('submit', startScan);

// Системата автоматично:
// 1. Изпраща POST /api/scans/start/
// 2. Получава scan ID
// 3. Стартира progress polling
// 4. Показва progress bar
```

### 2. Real-Time Updates

```javascript
// Polling цикъл (автоматичен)
setInterval(async () => {
    const response = await api.getScanDetails(scanId);
    
    // Обновява progress
    updateProgressBar(response.progress);  // 0-100%
    
    // Обновява current detector
    updateCurrentDetector(response.current_detector);
    
    // Обновява active detectors
    updateActiveProcesses(response.active_detectors);
    
    // Проверява дали е завършен
    if (response.status === 'completed') {
        stopPolling();
        showResults(response.vulnerabilities);
    }
}, 2000); // Всеки 2 секунди
```

### 3. Резултати

```javascript
// След завършване на скана
function loadScanResults(scanId) {
    const response = await api.getScanDetails(scanId);
    
    // Показва vulnerability summary
    showVulnerabilityCounts({
        total: response.vulnerabilities_found,
        high: response.severity_counts.high,
        medium: response.severity_counts.medium,
        low: response.severity_counts.low
    });
    
    // Показва детайлни резултати
    renderVulnerabilities(response.vulnerabilities);
}
```

---

## 📝 Backend Progress Update

**Как детекторите обновяват progress:**

```python
# В scan task (Celery)
scan = Scan.objects.get(id=scan_id)

total_detectors = len(selected_detectors)
completed = 0

for detector in selected_detectors:
    # Обновява current detector
    scan.current_detector = detector.name
    scan.progress = int((completed / total_detectors) * 100)
    scan.save()
    
    # Изпълнява детектора
    results = detector.run(target)
    
    # Обновява резултати
    scan.vulnerabilities_found += len(results)
    scan.raw_results['vulnerabilities'].extend(results)
    scan.save()
    
    completed += 1

# Маркира като завършен
scan.status = 'completed'
scan.progress = 100
scan.completed_at = timezone.now()
scan.save()
```

---

## 🔧 Конфигурация

### Polling Interval

```javascript
// scan-handler.js
function startProgressPolling(scanId) {
    progressPollInterval = setInterval(async () => {
        await updateScanProgress(scanId);
    }, 2000);  // 2 seconds - може да се променя
}
```

**Препоръчани стойности:**
- **Fast**: 1000ms (1s) - за бързи scans
- **Normal**: 2000ms (2s) - балансирано
- **Slow**: 5000ms (5s) - за дълги scans

---

## 📊 Демо

**Demo страница:** `test_progress.html`

Симулира scan progress с:
- 16 детектора
- Progress bar animation
- Active detectors rotation
- Completion status

**Как да стартирате:**
```bash
# Start demo server
cd /home/foxvr/Documents/BugBounty-Arsenal
python3 -m http.server 8888

# Open in browser
http://localhost:8888/test_progress.html
```

---

## ✅ Тестване

### 1. Ръчен Тест

```bash
# Създайте scan с progress
sudo docker exec bugbounty-web python manage.py shell -c "
from scans.models import Scan
from users.models import User
user = User.objects.first()
scan = Scan.objects.filter(user=user, status='pending').first()
scan.status = 'running'
scan.progress = 50
scan.current_detector = 'XSS Pattern Detection'
scan.save()
print(f'Scan {scan.id} updated to 50%')
"

# Тествайте API
curl http://localhost:8000/api/scans/{scan_id}/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 2. Frontend Test

```javascript
// Отворете browser console на scan страница
// Мониторирайте network requests
// Проверете дали polling работи на всеки 2s
```

---

## 🎯 Следващи Стъпки

1. ✅ **Progress bar** - ГОТОВО
2. ✅ **Real-time updates** - ГОТОВО
3. ✅ **Active detectors list** - ГОТОВО
4. ⏳ **WebSocket поддръжка** - За по-бързи updates
5. ⏳ **Estimирано време** - "~5 min remaining"
6. ⏳ **Детайлен лог** - Real-time лог на действия

---

## 🐛 Troubleshooting

### Problem: Progress не се обновява

**Причина:** API не връща актуални данни

**Решение:**
```bash
# Проверете дали scan се обновява
sudo docker exec bugbounty-web python manage.py shell -c "
from scans.models import Scan
scan = Scan.objects.get(id=YOUR_SCAN_ID)
print(f'Progress: {scan.progress}%, Status: {scan.status}')
"
```

### Problem: Polling не спира

**Причина:** Status не е 'completed' или 'failed'

**Решение:**
```javascript
// Проверете в console
console.log('Current status:', response.status);

// Ръчно спрете polling
stopProgressPolling();
```

---

## 📚 API Reference

### GET /api/scans/{id}/

**Response:**
```json
{
    "id": 42,
    "user": 1,
    "target": "https://example.com",
    "scan_type": "web_security",
    "status": "running",
    "progress": 65,
    "current_detector": "XSS Pattern Detection",
    "active_detectors": [
        "sql_injection",
        "xss_pattern",
        "csrf_detector"
    ],
    "vulnerabilities_found": 5,
    "vulnerabilities": [...],
    "severity_counts": {
        "critical": 0,
        "high": 2,
        "medium": 2,
        "low": 1,
        "info": 0
    },
    "started_at": "2025-12-14T16:00:00Z",
    "completed_at": null
}
```

---

**✅ Системата е готова за използване!**

Отворете: http://localhost:8000/scan/web/ за да тествате live!

# Celery Async Scans - Implementation Summary

## ✅ Implementation Complete!

Asynchronous scan execution has been successfully integrated into BugBounty Arsenal using Celery.

---

## 📋 What Was Implemented

### 1. **Celery Application** (`config/celery.py`)
- Configured Celery app with Django integration
- Auto-discovers tasks from all Django apps
- Redis broker and result backend configured
- Debug task for testing setup

### 2. **Scan Execution Tasks** (`scans/tasks.py`)
- **`execute_scan_task`**: Main async task that:
  - Takes scan ID and configuration
  - Executes security scan using existing `scanner.py`
  - Processes results and counts vulnerabilities by severity
  - Generates JSON report
  - Updates scan status and results in database
  - Supports automatic retries (max 3) on failure
  
- **`cancel_scan_task`**: Cancels running scans
  
- **`cleanup_old_scans_task`**: Periodic cleanup of old scan data

### 3. **Database Changes** (`scans/models.py`)
- Added `celery_task_id` field to Scan model
- Migration created and applied: `0003_scan_celery_task_id`

**New Methods:**
- `start_async_scan(scan_config)`: Starts scan asynchronously
- `cancel_scan()`: Cancels running/pending scan
- `get_task_status()`: Returns Celery task status

### 4. **API Enhancements** (`scans/views.py`)
- **Modified endpoints:**
  - `POST /api/scans/` - Now auto-starts async scan on creation
  - `POST /api/scans/{id}/cancel/` - Cancel running scans
  
- **New endpoint:**
  - `GET /api/scans/{id}/task_status/` - Check Celery task status

**Scan Configuration Options:**
```json
{
  "target": "https://example.com",
  "scan_type": "web_security",
  "concurrency": 10,
  "timeout": 15,
  "per_host_rate": 1.0,
  "allow_destructive": false,
  "bypass_cloudflare": false,
  "enable_forbidden_probe": false,
  "scan_mode": "normal"
}
```

### 5. **Serializers** (`scans/serializers.py`)
- Added `celery_task_id` to ScanSerializer
- Updated ScanDetailSerializer with task tracking

### 6. **Dependencies** (`requirements.txt`)
- Added Django packages
- Added Celery 5.6.0
- Added Redis 7.1.0

---

## 🚀 Quick Start

### Step 1: Install Redis
```bash
# Option A: Quick install script
./install_redis.sh

# Option B: Manual install (Ubuntu/Debian/Mint)
sudo apt-get update
sudo apt-get install redis-server
sudo systemctl start redis-server
redis-cli ping  # Should return "PONG"
```

### Step 2: Start Celery Worker
```bash
# Activate virtual environment
source .venv/bin/activate

# Start worker with auto-reload (development)
celery -A config worker --loglevel=info --autoreload

# Or start in background
celery -A config worker --loglevel=info --detach
```

### Step 3: Start Django Server
```bash
# In another terminal
python manage.py runserver
```

### Step 4: Test Async Scan
```bash
# Get JWT token
TOKEN=$(curl -s -X POST http://localhost:8000/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@bugbountyarsenal.com","password":"admin123"}' \
  | python -c "import sys, json; print(json.load(sys.stdin)['access'])")

# Create and start async scan
curl -X POST http://localhost:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "https://example.com",
    "scan_type": "web_security",
    "concurrency": 5,
    "timeout": 10
  }'

# Check scan status
curl http://localhost:8000/api/scans/1/ \
  -H "Authorization: Bearer $TOKEN"

# Check Celery task status
curl http://localhost:8000/api/scans/1/task_status/ \
  -H "Authorization: Bearer $TOKEN"

# Cancel scan if needed
curl -X POST http://localhost:8000/api/scans/1/cancel/ \
  -H "Authorization: Bearer $TOKEN"
```

---

## 📊 Workflow

```
User creates scan
       ↓
POST /api/scans/
       ↓
Django creates Scan (status='pending')
       ↓
start_async_scan() triggered
       ↓
Celery task queued
       ↓
celery_task_id stored
       ↓
[Celery Worker picks up task]
       ↓
Status → 'running'
       ↓
scanner.py executes
       ↓
Results processed
       ↓
Report saved to reports/scan_{id}/
       ↓
Database updated with results
       ↓
Status → 'completed'
```

---

## 🧪 Testing

### Verify Configuration
```bash
python test_celery.py
```

Expected output:
```
✓ Celery App Configuration
✓ 3 scan-related tasks registered
✓ All task functions valid
✓ Scan model methods available
✓ Redis connection (if Redis running)
```

### Monitor Celery
```bash
# View active tasks
celery -A config inspect active

# View registered tasks
celery -A config inspect registered

# View worker stats
celery -A config inspect stats

# Optional: Install Flower for web UI
pip install flower
celery -A config flower --port=5555
# Access at http://localhost:5555
```

---

## 📁 Files Created/Modified

### Created:
- `config/celery.py` - Celery app configuration
- `scans/tasks.py` - Async scan tasks
- `scans/migrations/0003_scan_celery_task_id.py` - Database migration
- `test_celery.py` - Configuration test script
- `install_redis.sh` - Redis installation script
- `CELERY_SETUP.md` - Comprehensive setup guide
- `CELERY_IMPLEMENTATION.md` - This summary

### Modified:
- `config/__init__.py` - Import Celery app
- `scans/models.py` - Added celery_task_id field and async methods
- `scans/serializers.py` - Added celery_task_id to serializers
- `scans/views.py` - Added async execution and task management
- `requirements.txt` - Added Celery and Redis dependencies

---

## 🎯 Benefits

✅ **Non-blocking API** - Returns immediately, scan runs in background  
✅ **Scalable** - Run multiple Celery workers for parallel processing  
✅ **Resilient** - Automatic retries on failure (max 3 attempts)  
✅ **Monitorable** - Real-time task status tracking  
✅ **Production-ready** - Battle-tested Celery + Redis stack  
✅ **Integrated** - Seamlessly uses existing scanner.py detectors  
✅ **Flexible** - Configurable scan parameters per request  

---

## 📈 Production Deployment

### Using Supervisor

Create `/etc/supervisor/conf.d/celery.conf`:
```ini
[program:celery]
command=/path/to/venv/bin/celery -A config worker --loglevel=info
directory=/path/to/BugBounty-Arsenal
user=www-data
autostart=true
autorestart=true
stdout_logfile=/var/log/celery/worker.log
stderr_logfile=/var/log/celery/worker_error.log
```

Start with:
```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start celery
```

### Using Systemd

Create `/etc/systemd/system/celery.service`:
```ini
[Unit]
Description=Celery Worker for BugBounty Arsenal
After=network.target redis.target

[Service]
Type=forking
User=www-data
Group=www-data
WorkingDirectory=/path/to/BugBounty-Arsenal
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/celery -A config worker --loglevel=info --detach
Restart=always

[Install]
WantedBy=multi-user.target
```

Start with:
```bash
sudo systemctl daemon-reload
sudo systemctl enable celery
sudo systemctl start celery
```

### Periodic Tasks (Optional)

Add to `config/celery.py` for scheduled cleanup:
```python
from celery.schedules import crontab

app.conf.beat_schedule = {
    'cleanup-old-scans-daily': {
        'task': 'scans.tasks.cleanup_old_scans_task',
        'schedule': crontab(hour=3, minute=0),  # 3 AM daily
        'args': (30,)  # Delete scans older than 30 days
    },
}
```

Start Celery Beat:
```bash
celery -A config beat --loglevel=info
```

---

## 🔧 Troubleshooting

### Redis Connection Failed
**Problem**: `redis.exceptions.ConnectionError`

**Solution**:
```bash
sudo systemctl status redis-server
redis-cli ping
# If not running:
sudo systemctl start redis-server
```

### Tasks Not Executing
**Problem**: Scans stay in 'pending' status

**Solution**:
```bash
# Check if worker is running
ps aux | grep celery
celery -A config inspect active

# Restart worker
pkill -f "celery worker"
celery -A config worker --loglevel=info
```

### Import Errors
**Problem**: `ModuleNotFoundError` in Celery worker

**Solution**:
```bash
# Ensure all dependencies installed
pip install -r requirements.txt

# Check Python path in worker logs
celery -A config worker --loglevel=debug
```

### Scanner Not Found
**Problem**: `ModuleNotFoundError: No module named 'scanner'`

**Solution**: Celery task adds project root to path automatically, but verify:
```python
# In scans/tasks.py (already implemented)
import sys
import os
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
```

---

## 📚 API Documentation

Access Swagger UI at: http://localhost:8000/api/docs/

**Key Endpoints:**
- `POST /api/scans/` - Create and start async scan
- `GET /api/scans/` - List all scans with status
- `GET /api/scans/{id}/` - Get scan details and results
- `POST /api/scans/{id}/cancel/` - Cancel running scan
- `GET /api/scans/{id}/task_status/` - Check Celery task status
- `GET /api/scans/stats/` - Get scan statistics

---

## 🎉 Success Criteria

All objectives achieved:

✅ Celery configured with Django  
✅ Redis broker integrated  
✅ Scan tasks created with retry logic  
✅ Database schema updated  
✅ API endpoints support async execution  
✅ Task status tracking implemented  
✅ Cancel functionality working  
✅ Configuration tested and validated  
✅ Documentation complete  
✅ Installation scripts provided  

---

## 📞 Next Steps

The async scan system is ready to use! Just:

1. **Install Redis**: `./install_redis.sh`
2. **Start Celery**: `celery -A config worker --loglevel=info`
3. **Start Django**: `python manage.py runserver`
4. **Create scans** via API and watch them execute asynchronously!

For questions or issues, check:
- `CELERY_SETUP.md` - Detailed setup guide
- `test_celery.py` - Configuration validation
- Celery logs - Worker output shows task execution

---

**Implementation Date**: December 4, 2025  
**Status**: ✅ Production Ready  
**Stack**: Django 6.0 + Celery 5.6.0 + Redis 7.1.0

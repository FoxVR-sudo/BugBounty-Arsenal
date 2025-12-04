# Celery Async Scans - Quick Reference

## 🚀 Start Services

```bash
# 1. Start Redis (one-time setup)
./install_redis.sh  # or: sudo systemctl start redis-server

# 2. Start Celery Worker (terminal 1)
source .venv/bin/activate
celery -A config worker --loglevel=info

# 3. Start Django Server (terminal 2)
python manage.py runserver
```

## 📝 Create Async Scan

### Via API
```bash
curl -X POST http://localhost:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "target": "https://example.com",
    "scan_type": "web_security",
    "concurrency": 10
  }'
```

### Via Python
```python
from scans.models import Scan
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.first()

scan = Scan.objects.create(
    user=user,
    target='https://example.com',
    scan_type='web_security'
)

# Start async execution
scan.start_async_scan({
    'concurrency': 10,
    'timeout': 15,
    'scan_mode': 'normal'
})
```

## 🔍 Check Status

### Check Scan Status
```bash
curl http://localhost:8000/api/scans/1/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Check Celery Task Status
```bash
curl http://localhost:8000/api/scans/1/task_status/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Monitor Celery
```bash
# Active tasks
celery -A config inspect active

# All registered tasks
celery -A config inspect registered

# Worker stats
celery -A config inspect stats
```

## ⏹️ Cancel Scan

### Via API
```bash
curl -X POST http://localhost:8000/api/scans/1/cancel/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Via Python
```python
scan = Scan.objects.get(id=1)
scan.cancel_scan()
```

## 🧪 Test Setup

```bash
# Run configuration test
python test_celery.py

# Test Redis connection
redis-cli ping  # Should return "PONG"

# Check Celery tasks registered
celery -A config inspect registered | grep scans
```

## 📊 Scan Configuration Options

```json
{
  "target": "https://target.com",
  "scan_type": "web_security",
  
  // Optional parameters:
  "concurrency": 10,          // Parallel requests
  "timeout": 15,              // Request timeout (seconds)
  "per_host_rate": 1.0,       // Requests per second per host
  "allow_destructive": false, // Allow dangerous tests
  "bypass_cloudflare": false, // Cloudflare bypass attempts
  "enable_forbidden_probe": false, // 403 bypass attempts
  "scan_mode": "normal"       // normal | aggressive | stealth
}
```

## 📁 File Locations

- **Configuration**: `config/celery.py`
- **Tasks**: `scans/tasks.py`
- **Models**: `scans/models.py`
- **Views**: `scans/views.py`
- **Reports**: `reports/scan_{id}/report.json`

## 🐛 Troubleshooting

### Redis not running
```bash
sudo systemctl status redis-server
sudo systemctl start redis-server
redis-cli ping
```

### Worker not picking up tasks
```bash
# Restart worker
pkill -f "celery worker"
celery -A config worker --loglevel=debug
```

### Import errors
```bash
pip install -r requirements.txt
python test_celery.py
```

### Check logs
```bash
# Celery worker logs (in terminal where worker runs)
# Django logs
python manage.py runserver

# Redis logs
sudo journalctl -u redis-server -f
```

## 🎯 Key Features

✅ Non-blocking API responses  
✅ Parallel scan processing  
✅ Automatic retry on failure  
✅ Real-time status tracking  
✅ Cancel capability  
✅ Detailed reports  
✅ Severity classification  

## 📚 Documentation

- **Setup Guide**: `CELERY_SETUP.md`
- **Implementation**: `CELERY_IMPLEMENTATION.md`
- **API Docs**: http://localhost:8000/api/docs/

## 🔐 Authentication

```bash
# Get JWT token
curl -X POST http://localhost:8000/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@bugbountyarsenal.com","password":"admin123"}'

# Use token in requests
-H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 📊 Scan Statuses

- `pending` - Queued for execution
- `running` - Currently scanning
- `completed` - Finished successfully
- `failed` - Error occurred
- `stopped` - Manually cancelled

## 💡 Tips

- Use `concurrency=5` for rate-limited targets
- Set `timeout=30` for slow targets
- Enable `bypass_cloudflare` for protected sites
- Check `task_status` endpoint for detailed progress
- Reports saved in `reports/scan_{id}/`
- Use `scan_mode="stealth"` for defensive targets

---

**Quick Start**: `./install_redis.sh` → `celery -A config worker` → `python manage.py runserver` → Create scan!

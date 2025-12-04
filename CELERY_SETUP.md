# Celery Setup Guide

## Installation Complete! ✓

Celery has been successfully configured for asynchronous scan execution.

## Components Created:

### 1. Celery Configuration (`config/celery.py`)
- Celery app configured with Django settings
- Auto-discovers tasks from all Django apps
- Result backend configured for Redis

### 2. Scan Tasks (`scans/tasks.py`)
- `execute_scan_task`: Main task for running security scans asynchronously
- `cancel_scan_task`: Task for canceling running scans
- `cleanup_old_scans_task`: Periodic task for cleaning up old scan data

### 3. Scan Model Updates (`scans/models.py`)
- Added `celery_task_id` field to track async tasks
- `start_async_scan()`: Start scan execution in background
- `cancel_scan()`: Cancel running scans
- `get_task_status()`: Check task progress

### 4. API Endpoints (`scans/views.py`)
- POST `/api/scans/` - Create and auto-start async scan
- POST `/api/scans/{id}/cancel/` - Cancel running scan
- GET `/api/scans/{id}/task_status/` - Check task status

## Starting Celery Worker

### Option 1: Install Redis (Recommended for Production)

```bash
# Install Redis
sudo apt-get update
sudo apt-get install redis-server

# Start Redis
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Verify Redis is running
redis-cli ping  # Should return "PONG"
```

### Option 2: Use Docker Redis (Quick Setup)

```bash
# Start Redis in Docker
docker run -d -p 6379:6379 --name bugbounty-redis redis:alpine

# Verify
docker ps | grep redis
```

### Start Celery Worker

```bash
# Activate virtual environment
source .venv/bin/activate

# Start Celery worker
celery -A config worker --loglevel=info

# For development with auto-reload on code changes:
celery -A config worker --loglevel=info --autoreload
```

### Start Celery in Background

```bash
# Start as background process
celery -A config worker --loglevel=info --detach

# Or use supervisord/systemd for production
```

## Testing the Setup

### 1. Start Django Server

```bash
python manage.py runserver
```

### 2. Create a Test Scan

```bash
# Get JWT token
curl -X POST http://localhost:8000/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@bugbountyarsenal.com", "password": "admin123"}'

# Create async scan
curl -X POST http://localhost:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "target": "https://example.com",
    "scan_type": "web_security"
  }'

# Check scan status
curl http://localhost:8000/api/scans/1/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Check task status
curl http://localhost:8000/api/scans/1/task_status/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Cancel scan if needed
curl -X POST http://localhost:8000/api/scans/1/cancel/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## How It Works

1. **User creates scan** via POST `/api/scans/`
2. **Django saves scan** with status='pending'
3. **Celery task starts** automatically via `start_async_scan()`
4. **Task ID stored** in `celery_task_id` field
5. **Scan executes** in background using existing scanner.py
6. **Results saved** to database when complete
7. **Status updated** to 'completed' or 'failed'

## Scan Configuration Options

When creating a scan, you can pass additional options:

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

## Monitoring

### Check Celery Worker Status

```bash
# View active tasks
celery -A config inspect active

# View registered tasks
celery -A config inspect registered

# View worker stats
celery -A config inspect stats
```

### Monitor with Flower (Optional)

```bash
# Install Flower
pip install flower

# Start Flower web UI
celery -A config flower --port=5555

# Access at http://localhost:5555
```

## Production Deployment

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

### Using Systemd

Create `/etc/systemd/system/celery.service`:

```ini
[Unit]
Description=Celery Service
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

## Periodic Tasks (Optional)

To run cleanup tasks periodically, use Celery Beat:

```bash
# Start Celery Beat scheduler
celery -A config beat --loglevel=info
```

Add to `config/celery.py`:

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

## Troubleshooting

### Redis Connection Error

```
Error: Redis connection failed
```

**Solution**: Make sure Redis is running:
```bash
sudo systemctl status redis-server
redis-cli ping
```

### Task Not Executing

**Solution**: Check if Celery worker is running:
```bash
ps aux | grep celery
celery -A config inspect active
```

### Import Errors

**Solution**: Ensure project root is in Python path and all dependencies are installed:
```bash
pip install -r requirements.txt
```

## Next Steps

1. **Install Redis** (if not already done)
2. **Start Celery worker**
3. **Start Django server**
4. **Create test scan** via API
5. **Monitor execution** in Celery worker logs
6. **Check results** in Django admin or API

## Benefits

✅ **Non-blocking API** - Scans run in background
✅ **Scalable** - Multiple workers can process scans in parallel
✅ **Resilient** - Automatic retries on failure
✅ **Monitorable** - Track task status in real-time
✅ **Production-ready** - Uses battle-tested Celery + Redis stack

---

**Status**: Ready to use! Just install Redis and start the Celery worker.

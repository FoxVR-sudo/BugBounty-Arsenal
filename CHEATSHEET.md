# 🚀 BugBounty Arsenal - Developer Cheat Sheet

Quick reference for common development tasks.

---

## 🏃 Quick Start Commands

### Start Development Environment
```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f web

# Stop services
docker compose down
```

### Run Django Commands
```bash
# Inside Docker
docker compose exec web python manage.py <command>

# Or enter shell
docker compose exec web bash
```

---

## 🧪 Testing

### Run Tests
```bash
# All tests
./run_tests.sh

# Specific test file
pytest tests/test_xss_detector.py -v

# With coverage
pytest --cov=. --cov-report=html

# Run in Docker
docker compose exec web pytest -v
```

### Test Markers
```bash
pytest -m detector    # Only detector tests
pytest -m api         # Only API tests
pytest -m unit        # Only unit tests
pytest -m integration # Only integration tests
```

---

## 📦 Database

### Migrations
```bash
# Create migration
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Show migrations
python manage.py showmigrations

# Rollback
python manage.py migrate app_name 0001
```

### Data Management
```bash
# Create superuser
python manage.py createsuperuser

# Populate test data
python manage.py populate_scan_categories

# Shell
python manage.py shell
python manage.py shell_plus  # If django-extensions installed
```

---

## 🔍 Debugging

### View Logs
```bash
# Docker logs
docker compose logs -f web
docker compose logs -f celery
docker compose logs -f redis

# Application logs
tail -f logs/bugbounty_arsenal.log
tail -f logs/errors.log
tail -f logs/scans.log
```

### Django Debug Toolbar
```python
# In settings.py (development only)
INSTALLED_APPS += ['debug_toolbar']
MIDDLEWARE += ['debug_toolbar.middleware.DebugToolbarMiddleware']
INTERNAL_IPS = ['127.0.0.1']
```

---

## 🛠️ Detectors

### Create New Detector
```python
# detectors/my_detector.py
async def detect(url: str, config: dict = None):
    findings = []
    
    # Your detection logic here
    
    return findings

__all__ = ['detect']
```

### Register Detector
```python
# Create DetectorConfig in database
from scans.models import DetectorConfig

DetectorConfig.objects.create(
    name='my_detector',
    display_name='My Detector',
    description='Detects XYZ vulnerability',
    enabled=True,
    is_dangerous=False,
    timeout=30
)
```

### Test Detector
```python
# tests/test_my_detector.py
import pytest
from detectors.my_detector import detect

@pytest.mark.detector
@pytest.mark.asyncio
async def test_my_detector():
    url = "https://example.com"
    findings = await detect(url, {})
    assert isinstance(findings, list)
```

---

## 🌐 API Endpoints

### Scans
```bash
# List scans
GET /api/scans/

# Create scan
POST /api/scans/
{
  "target_url": "https://example.com",
  "category": "recon",
  "accept_disclaimer": true
}

# Get scan details
GET /api/scans/{id}/

# Delete scan
DELETE /api/scans/{id}/
```

### Authentication
```bash
# Register
POST /api/auth/register/

# Login
POST /api/auth/token/

# Refresh token
POST /api/auth/token/refresh/

# Current user
GET /api/auth/user/
```

### Subscriptions
```bash
# List plans
GET /api/subscriptions/plans/

# My subscription
GET /api/subscriptions/my-subscription/

# Upgrade
POST /api/subscriptions/upgrade/
```

---

## 🔐 Security

### Generate Secret Key
```python
from django.core.management.utils import get_random_secret_key
print(get_random_secret_key())
```

### Create User Programmatically
```python
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.create_user(
    username='testuser',
    email='test@example.com',
    password='password123'
)
```

---

## 📊 Monitoring

### Check Service Health
```bash
# Web service
curl http://localhost:8001/api/health/

# Redis
docker compose exec redis redis-cli ping

# PostgreSQL
docker compose exec db psql -U postgres -c "SELECT 1"

# Celery
docker compose exec celery celery -A config inspect ping
```

### Performance Testing
```bash
# Install locust
pip install locust

# Create locustfile.py
# Run load test
locust -f locustfile.py
```

---

## 🎨 Frontend

### Start Frontend Dev Server
```bash
cd frontend
npm install
npm start  # Runs on port 3000
```

### Build for Production
```bash
cd frontend
npm run build
```

### Lint Code
```bash
npm run lint
npm run lint:fix
```

---

## 🐳 Docker

### Useful Docker Commands
```bash
# Rebuild containers
docker compose build

# Rebuild specific service
docker compose build web

# Remove all containers and volumes
docker compose down -v

# View container resource usage
docker stats

# Execute command in container
docker compose exec web <command>

# View container logs
docker compose logs -f <service_name>
```

### Clean Up Docker
```bash
# Remove unused containers
docker system prune

# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune
```

---

## 📝 Code Quality

### Linting
```bash
# flake8
flake8 . --count --select=E9,F63,F7,F82 --show-source

# Black (formatter)
black .
black --check .  # Check only

# isort (import sorting)
isort .
isort --check-only .
```

### Type Checking
```bash
# mypy
mypy .
```

---

## 🔄 Git Workflow

### Before Committing
```bash
# 1. Format code
black .
isort .

# 2. Run linter
flake8 .

# 3. Run tests
pytest

# 4. Check coverage
pytest --cov=. --cov-report=term-missing
```

### Commit Messages
```
feat: Add new SSRF detector
fix: Fix XSS false positive detection
docs: Update testing documentation
test: Add tests for SQL detector
refactor: Improve error handling
chore: Update dependencies
```

---

## 🚢 Deployment

### Environment Variables
```bash
# Required
SECRET_KEY=<django-secret-key>
DEBUG=False
ALLOWED_HOSTS=example.com,www.example.com

# Database
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# Redis
REDIS_URL=redis://host:6379/0

# Optional
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_PHONE_NUMBER=
OPENCORPORATES_API_KEY=
STRIPE_SECRET_KEY=
```

### Collect Static Files
```bash
python manage.py collectstatic --noinput
```

### Production Checklist
- [ ] DEBUG = False
- [ ] Strong SECRET_KEY
- [ ] Configure ALLOWED_HOSTS
- [ ] Set up PostgreSQL
- [ ] Configure Redis
- [ ] Set up Celery workers
- [ ] Configure CORS
- [ ] Set up SSL/TLS
- [ ] Configure logging
- [ ] Set up monitoring
- [ ] Configure backups
- [ ] Set rate limits

---

## 🔧 Celery

### Celery Commands
```bash
# Start worker
celery -A config worker -l info

# Start beat scheduler
celery -A config beat -l info

# Flower monitoring
celery -A config flower

# Purge all tasks
celery -A config purge

# Inspect active tasks
celery -A config inspect active

# List registered tasks
celery -A config inspect registered
```

### Run Task Manually
```python
from scans.tasks import run_scan_task

# Async
result = run_scan_task.delay(scan_id=123)

# Sync (for testing)
result = run_scan_task.apply(args=[123])
```

---

## 📡 WebSocket

### Test WebSocket Connection
```javascript
// In browser console
const ws = new WebSocket('ws://localhost:8001/ws/scan/123/');

ws.onopen = () => console.log('Connected');
ws.onmessage = (e) => console.log('Message:', JSON.parse(e.data));
ws.onerror = (e) => console.error('Error:', e);
ws.onclose = () => console.log('Disconnected');

// Send message
ws.send(JSON.stringify({type: 'ping'}));
```

### Send Update from Backend
```python
from scans.websocket_utils import send_scan_progress

send_scan_progress(
    scan_id=123,
    progress=50,
    current_step='Running XSS detector...'
)
```

---

## 🐛 Common Issues

### Issue: Port already in use
```bash
# Find process using port
sudo lsof -i :8001

# Kill process
sudo kill -9 <PID>
```

### Issue: Database locked
```bash
# Restart PostgreSQL
docker compose restart db
```

### Issue: Celery tasks stuck
```bash
# Purge all tasks
docker compose exec celery celery -A config purge

# Restart celery
docker compose restart celery
```

### Issue: Module not found
```bash
# Reinstall dependencies
docker compose exec web pip install -r requirements.txt

# Or rebuild container
docker compose build web
```

---

## 📚 Useful Links

- **Django Docs:** https://docs.djangoproject.com/
- **DRF Docs:** https://www.django-rest-framework.org/
- **Celery Docs:** https://docs.celeryproject.org/
- **Pytest Docs:** https://docs.pytest.org/
- **Docker Docs:** https://docs.docker.com/

---

## 💡 Pro Tips

1. **Use Django Shell Plus** for interactive debugging
2. **Enable DEBUG=True** only in development
3. **Use Docker volumes** for persistent data
4. **Run tests before committing**
5. **Keep dependencies updated**
6. **Use environment variables** for sensitive data
7. **Monitor logs** regularly
8. **Backup database** before migrations

---

**🎯 Keep this file handy for quick reference!**

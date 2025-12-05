# Docker Deployment Guide

## Quick Start

### 1. Build and Start All Services

```bash
docker-compose up -d --build
```

This will start:
- **Django web server** on `http://localhost:8000`
- **Redis** message broker on `localhost:6379`
- **Celery worker** for async scan execution
- **Celery beat** for scheduled tasks

### 2. Check Service Status

```bash
docker-compose ps
```

### 3. View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f web
docker-compose logs -f celery
docker-compose logs -f redis
```

### 4. Stop Services

```bash
docker-compose down
```

### 5. Restart Services

```bash
docker-compose restart
```

---

## Initial Setup

### Create Superuser

```bash
docker-compose exec web python manage.py createsuperuser
```

### Run Migrations

```bash
docker-compose exec web python manage.py migrate
```

### Initialize Plans (if needed)

```bash
docker-compose exec web python init_plans.py
```

---

## Service Details

### Web Service (Django)
- **Port**: 8000
- **Container**: `bugbounty-web`
- **Command**: `gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 4`
- **Health Check**: `http://localhost:8000/health/`

### Celery Worker
- **Container**: `bugbounty-celery`
- **Command**: `celery -A config worker --loglevel=info --concurrency=4`
- **Purpose**: Executes async scan tasks

### Celery Beat
- **Container**: `bugbounty-celery-beat`
- **Command**: `celery -A config beat --loglevel=info`
- **Purpose**: Scheduled periodic tasks

### Redis
- **Port**: 6379
- **Container**: `bugbounty-redis`
- **Purpose**: Message broker and result backend for Celery

---

## Environment Variables

Create a `.env` file in the project root:

```env
# Django
SECRET_KEY=your-secret-key-here
DJANGO_SETTINGS_MODULE=config.settings
ENVIRONMENT=production

# Database
DATABASE_URL=sqlite:///./bugbounty_arsenal.db

# Celery
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0

# Stripe (optional)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

---

## Development Commands

### Access Django Shell

```bash
docker-compose exec web python manage.py shell
```

### Run Django Management Commands

```bash
docker-compose exec web python manage.py <command>
```

### Execute Commands in Container

```bash
docker-compose exec web bash
docker-compose exec celery bash
```

### Rebuild Specific Service

```bash
docker-compose up -d --build web
docker-compose up -d --build celery
```

---

## Testing Scan Functionality

### Start a Test Scan

```bash
# Get JWT token first
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin"}' \
  | jq -r '.access')

# Start scan
curl -X POST http://localhost:8000/api/scans/start/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","scan_type":"web_security"}'
```

### Check Scan Status

```bash
curl -X GET http://localhost:8000/api/scans/status/ \
  -H "Authorization: Bearer $TOKEN"
```

### Monitor Celery Tasks

```bash
docker-compose logs -f celery
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose logs web

# Check container status
docker-compose ps

# Restart service
docker-compose restart web
```

### Database Issues

```bash
# Run migrations
docker-compose exec web python manage.py migrate

# Check database
docker-compose exec web python manage.py dbshell
```

### Celery Not Processing Tasks

```bash
# Check Redis connection
docker-compose exec redis redis-cli ping

# Check Celery worker logs
docker-compose logs -f celery

# Restart Celery
docker-compose restart celery
```

### Clear Redis Cache

```bash
docker-compose exec redis redis-cli FLUSHALL
```

### Reset Everything

```bash
# Stop and remove containers, networks, volumes
docker-compose down -v

# Rebuild and start
docker-compose up -d --build
```

---

## Production Considerations

### Security
1. Change `SECRET_KEY` in `.env`
2. Set `DEBUG=False` in production
3. Configure `ALLOWED_HOSTS` properly
4. Use PostgreSQL instead of SQLite
5. Enable HTTPS with reverse proxy (nginx/traefik)

### Performance
1. Increase Celery concurrency: `--concurrency=8`
2. Add more Celery workers
3. Scale services: `docker-compose up -d --scale celery=3`
4. Use Redis persistence for critical data

### Monitoring
1. Set up container health checks
2. Monitor Celery task queue length
3. Track Redis memory usage
4. Set up log aggregation (ELK, Loki)

### Backup
```bash
# Backup database
docker-compose exec web python manage.py dumpdata > backup.json

# Backup volumes
docker run --rm -v bugbounty-arsenal_redis_data:/data -v $(pwd):/backup alpine tar czf /backup/redis_backup.tar.gz /data
```

---

## Useful Docker Commands

```bash
# View resource usage
docker stats

# Clean up unused images
docker image prune -a

# View volumes
docker volume ls

# Inspect service
docker-compose exec web env

# Check network
docker network inspect bugbounty-arsenal_bugbounty-network
```

---

## Accessing Services

- **Web Application**: http://localhost:8000
- **Admin Panel**: http://localhost:8000/admin-panel/
- **API Documentation**: http://localhost:8000/api/docs/
- **Health Check**: http://localhost:8000/health/

---

## Next Steps

1. ✅ Services running via Docker
2. Configure environment variables in `.env`
3. Create superuser account
4. Test scan functionality
5. Set up reverse proxy (nginx) for production
6. Configure SSL certificates
7. Set up automated backups

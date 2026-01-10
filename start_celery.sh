#!/bin/bash
# Start Celery worker for BugBounty Arsenal
# Deploy this to: /home/bugbount/app/start_celery.sh

cd /home/bugbount/app
source /home/bugbount/virtualenv/app/3.11/bin/activate

# Kill existing Celery workers
pkill -f "celery -A config worker"

# Wait for processes to stop
sleep 2

# Start Celery worker with optimized settings
celery -A config worker \
    --loglevel=info \
    --concurrency=4 \
    --max-tasks-per-child=100 \
    --time-limit=3600 \
    --soft-time-limit=3500 \
    --logfile=logs/celery.log \
    --pidfile=celery.pid \
    --detach

echo "Celery worker started at $(date)"

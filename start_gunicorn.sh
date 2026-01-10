#!/bin/bash
# Start Gunicorn for BugBounty Arsenal
# Deploy this to: /home/bugbount/app/start_gunicorn.sh

cd /home/bugbount/app
source /home/bugbount/virtualenv/app/3.11/bin/activate

# Kill existing Gunicorn processes
pkill -f "gunicorn config.wsgi"

# Wait for processes to stop
sleep 2

# Start Gunicorn with 3 workers
gunicorn config.wsgi:application \
    --bind 127.0.0.1:8000 \
    --workers 3 \
    --daemon \
    --access-logfile logs/gunicorn-access.log \
    --error-logfile logs/gunicorn-error.log \
    --pid gunicorn.pid

echo "Gunicorn started at $(date)"

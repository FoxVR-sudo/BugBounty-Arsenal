#!/bin/bash
# Monitor and auto-restart Celery if stopped
# Add to crontab: * * * * * /home/bugbount/app/monitor_celery.sh >> /home/bugbount/app/logs/monitor.log 2>&1

LOG_FILE="/home/bugbount/app/logs/monitor.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Check if Celery worker is running
if ! pgrep -f "celery -A config worker" > /dev/null; then
    echo "[$TIMESTAMP] ⚠️  Celery worker is not running! Restarting..." >> "$LOG_FILE"
    /home/bugbount/app/start_celery.sh >> "$LOG_FILE" 2>&1
    echo "[$TIMESTAMP] ✅ Celery worker restarted" >> "$LOG_FILE"
else
    PROCESS_COUNT=$(pgrep -f "celery -A config worker" | wc -l)
    echo "[$TIMESTAMP] ✓ Celery worker running ($PROCESS_COUNT processes)" >> "$LOG_FILE"
fi

#!/bin/bash
# Monitor and auto-restart Gunicorn if stopped
# Add to crontab: */5 * * * * /home/bugbount/app/monitor_gunicorn.sh >> /home/bugbount/app/logs/monitor.log 2>&1

LOG_FILE="/home/bugbount/app/logs/monitor.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Check if Gunicorn is running
if ! pgrep -f "gunicorn config.wsgi" > /dev/null; then
    echo "[$TIMESTAMP] ⚠️  Gunicorn is not running! Restarting..." >> "$LOG_FILE"
    /home/bugbount/app/start_gunicorn.sh >> "$LOG_FILE" 2>&1
    echo "[$TIMESTAMP] ✅ Gunicorn restarted" >> "$LOG_FILE"
else
    PROCESS_COUNT=$(pgrep -f "gunicorn config.wsgi" | wc -l)
    echo "[$TIMESTAMP] ✓ Gunicorn running ($PROCESS_COUNT processes)" >> "$LOG_FILE"
fi

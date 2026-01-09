#!/bin/bash
#
# cPanel Django Deployment Script
# Използвай този скрипт за ръчен deploy или от GitHub Actions
#

set -e  # Спри при грешка

APP_DIR="/home/bugbount/app"
VENV_DIR="/home/bugbount/virtualenv/app-py39"
LOG_FILE="$APP_DIR/deploy.log"

echo "========================================" | tee -a $LOG_FILE
echo "Deployment started at $(date)" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE

cd $APP_DIR

# 1. Backup database (опционално)
echo "📦 Creating database backup..." | tee -a $LOG_FILE
timestamp=$(date +%Y%m%d_%H%M%S)
# pg_dump може да не е налично на shared hosting, коментирай ако не работи
# PGPASSWORD="BugBounty2026!" pg_dump -h localhost -U bugbount_user bugbount_db > backups/db_$timestamp.sql 2>&1 | tee -a $LOG_FILE || echo "⚠️  Database backup skipped"

# 2. Pull latest code
echo "📥 Pulling latest code from Git..." | tee -a $LOG_FILE
git fetch origin 2>&1 | tee -a $LOG_FILE
git reset --hard origin/master 2>&1 | tee -a $LOG_FILE

# 3. Activate virtualenv
echo "🐍 Activating Python environment..." | tee -a $LOG_FILE
source $VENV_DIR/bin/activate

# 4. Install/update dependencies
echo "📦 Installing Python dependencies..." | tee -a $LOG_FILE
pip install -r requirements.txt --quiet 2>&1 | tee -a $LOG_FILE

# 5. Collect static files
echo "📁 Collecting static files..." | tee -a $LOG_FILE
python manage.py collectstatic --noinput --clear 2>&1 | tee -a $LOG_FILE

# 6. Run migrations
echo "🗄️  Running database migrations..." | tee -a $LOG_FILE
python manage.py migrate --noinput 2>&1 | tee -a $LOG_FILE

# 7. Check for errors
echo "🔍 Running Django checks..." | tee -a $LOG_FILE
python manage.py check 2>&1 | tee -a $LOG_FILE

# 8. Restart gunicorn
echo "🔄 Restarting Gunicorn..." | tee -a $LOG_FILE
pkill -f "gunicorn config.wsgi" || echo "No gunicorn process found"
sleep 2
$APP_DIR/start_gunicorn.sh 2>&1 | tee -a $LOG_FILE

# 9. Verify gunicorn is running
sleep 2
if pgrep -f "gunicorn config.wsgi" > /dev/null; then
    echo "✅ Gunicorn is running" | tee -a $LOG_FILE
    ps aux | grep gunicorn | grep -v grep | tee -a $LOG_FILE
else
    echo "❌ ERROR: Gunicorn failed to start!" | tee -a $LOG_FILE
    echo "Check logs: tail -50 $APP_DIR/logs/gunicorn-error.log" | tee -a $LOG_FILE
    exit 1
fi

echo "========================================" | tee -a $LOG_FILE
echo "✅ Deployment completed successfully!" | tee -a $LOG_FILE
echo "Finished at $(date)" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE

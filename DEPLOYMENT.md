# cPanel Deployment Guide

## 🚀 Автоматичен Deploy с GitHub Actions

### 1. Настройка на GitHub Secrets

Отиди в GitHub Repository → Settings → Secrets and variables → Actions

Добави следните secrets:

```
CPANEL_HOST=79.98.104.6
CPANEL_USER=bugbount
CPANEL_PASSWORD=((Lc5KVhW01kt3
CPANEL_SSH_PORT=12545
```

### 2. Активиране на Git на сървъра

Влез в cPanel SSH и инициализирай Git repo:

```bash
cd /home/bugbount/app

# Инициализирай Git repo
git init
git remote add origin https://github.com/YOUR_USERNAME/BugBounty-Arsenal.git

# Настрой Git credentials (за автоматичен pull)
git config user.name "YourName"
git config user.email "your@email.com"

# Направи deploy скрипта изпълним
chmod +x deploy.sh
chmod +x start_gunicorn.sh

# Създай директория за backups
mkdir -p backups
```

### 3. Създай start_gunicorn.sh

```bash
cat > /home/bugbount/app/start_gunicorn.sh << 'EOF'
#!/bin/bash
cd /home/bugbount/app
source /home/bugbount/virtualenv/app-py39/bin/activate

gunicorn config.wsgi:application \
    --bind 127.0.0.1:8000 \
    --workers 2 \
    --timeout 120 \
    --access-logfile /home/bugbount/app/logs/gunicorn-access.log \
    --error-logfile /home/bugbount/app/logs/gunicorn-error.log \
    --daemon
EOF

chmod +x /home/bugbount/app/start_gunicorn.sh
```

### 4. Тест на deployment

```bash
cd /home/bugbount/app
./deploy.sh
```

### 5. Как работи автоматичният deploy

Всеки път когато push-неш към `master` branch:

```bash
git add .
git commit -m "Update application"
git push origin master
```

GitHub Actions автоматично ще:
1. ✅ Свали новия код на сървъра
2. ✅ Инсталира dependencies
3. ✅ Пусне миграции
4. ✅ Collect static files
5. ✅ Рестартира gunicorn

### 6. Проверка на deploy logs

```bash
# На сървъра
tail -f /home/bugbount/app/deploy.log

# Gunicorn logs
tail -f /home/bugbount/app/logs/gunicorn-error.log
```

## 🔧 Ръчен Deploy

Ако искаш да deploy-неш ръчно:

```bash
ssh bugbount@79.98.104.6 -p12545
cd /home/bugbount/app
./deploy.sh
```

## 📋 Checklist преди първи deploy

- [ ] GitHub Secrets добавени
- [ ] Git инициализиран на сървъра
- [ ] start_gunicorn.sh създаден и executable
- [ ] deploy.sh е executable
- [ ] .env файл съществува на сървъра
- [ ] PostgreSQL база данни създадена
- [ ] Frontend build качен в public_html

## 🚨 Troubleshooting

### Deploy failва с "Permission denied"

```bash
chmod +x /home/bugbount/app/deploy.sh
chmod +x /home/bugbount/app/start_gunicorn.sh
```

### Git pull failва с "Authentication failed"

Използвай Personal Access Token:

```bash
git remote set-url origin https://YOUR_TOKEN@github.com/YOUR_USERNAME/BugBounty-Arsenal.git
```

### Gunicorn не стартира

```bash
# Провери грешките
tail -50 /home/bugbount/app/logs/gunicorn-error.log

# Тествай Django
python manage.py check

# Тествай ръчно gunicorn
gunicorn config.wsgi:application --bind 127.0.0.1:8000
```

## 📝 Notes

- Deployment logs се записват в `/home/bugbount/app/deploy.log`
- Database backups се създават преди всеки deploy (ако е активирано)
- Gunicorn използва 2 workers (можеш да увеличиш според RAM)

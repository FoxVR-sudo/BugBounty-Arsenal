#!/bin/bash
# Configure and start production deployment

set -e
cd /opt/bugbounty-arsenal

echo "=== Configuring Nginx ==="
ln -sf /etc/nginx/sites-available/bugbounty-arsenal /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

echo "=== Loading production environment ==="
source .env.production

echo "=== Building and starting containers ==="
docker compose up -d --build

echo "=== Waiting for services to start ==="
sleep 10

echo "=== Running migrations ==="
docker compose exec -T web python manage.py migrate --noinput

echo "=== Collecting static files ==="
docker compose exec -T web python manage.py collectstatic --noinput

echo "=== Creating superuser (if needed) ==="
docker compose exec -T web python manage.py shell -c "
from users.models import CustomUser
if not CustomUser.objects.filter(email='admin@bugbaunty-arsenal.com').exists():
    CustomUser.objects.create_superuser(
        email='admin@bugbaunty-arsenal.com',
        password='ChangeMe123!',
        full_name='Admin'
    )
    print('Superuser created: admin@bugbaunty-arsenal.com / ChangeMe123!')
else:
    print('Superuser already exists')
"

echo "=== Checking container status ==="
docker compose ps

echo "=== Production deployment complete! ==="
echo "Application running on http://164.138.221.48"
echo "Next: Configure DNS and setup SSL with certbot"

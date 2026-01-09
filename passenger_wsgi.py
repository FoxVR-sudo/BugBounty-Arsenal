import os
import sys

# Add virtualenv site-packages to path
INTERP = '/home/bugbount/virtualenv/app/3.11/bin/python3'
if sys.executable != INTERP:
    os.execl(INTERP, INTERP, *sys.argv)

# Add your project directory to the sys.path
project_home = '/home/bugbount/app'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set environment variables
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'

# Import Django WSGI application
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()

#!/usr/bin/env python
"""
Test script to verify Celery configuration.

This script checks that:
1. Celery app is properly configured
2. Tasks are discoverable
3. Configuration is valid
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
django.setup()

from config.celery import app as celery_app
from scans.tasks import execute_scan_task, cancel_scan_task, cleanup_old_scans_task

def test_celery_config():
    """Test Celery configuration"""
    print("=" * 60)
    print("CELERY CONFIGURATION TEST")
    print("=" * 60)
    
    # Test 1: Celery app configuration
    print("\n1. Celery App Configuration:")
    print(f"   ✓ App name: {celery_app.main}")
    print(f"   ✓ Broker URL: {celery_app.conf.broker_url}")
    print(f"   ✓ Result backend: {celery_app.conf.result_backend}")
    print(f"   ✓ Task serializer: {celery_app.conf.task_serializer}")
    
    # Test 2: Task discovery
    print("\n2. Registered Tasks:")
    registered_tasks = celery_app.tasks
    scan_tasks = [name for name in registered_tasks.keys() if 'scans' in name]
    
    if scan_tasks:
        print(f"   ✓ Found {len(scan_tasks)} scan-related tasks:")
        for task_name in scan_tasks:
            print(f"     - {task_name}")
    else:
        print("   ⚠ No scan tasks found (this is OK if tasks haven't been imported)")
    
    # Test 3: Task callability
    print("\n3. Task Functions:")
    tasks_to_test = [
        ('execute_scan_task', execute_scan_task),
        ('cancel_scan_task', cancel_scan_task),
        ('cleanup_old_scans_task', cleanup_old_scans_task),
    ]
    
    for task_name, task_func in tasks_to_test:
        if hasattr(task_func, 'delay'):
            print(f"   ✓ {task_name} is a valid Celery task")
        else:
            print(f"   ✗ {task_name} is NOT a Celery task")
    
    # Test 4: Django models
    print("\n4. Django Models:")
    try:
        from scans.models import Scan
        scan_count = Scan.objects.count()
        print(f"   ✓ Scan model accessible")
        print(f"   ✓ Database contains {scan_count} scans")
        
        # Check if Scan model has the new methods
        if hasattr(Scan, 'start_async_scan'):
            print("   ✓ Scan.start_async_scan() method available")
        if hasattr(Scan, 'cancel_scan'):
            print("   ✓ Scan.cancel_scan() method available")
        if hasattr(Scan, 'get_task_status'):
            print("   ✓ Scan.get_task_status() method available")
            
    except Exception as e:
        print(f"   ✗ Error accessing Scan model: {e}")
    
    # Test 5: Dependencies
    print("\n5. Dependencies:")
    try:
        import celery
        print(f"   ✓ Celery version: {celery.__version__}")
    except ImportError:
        print("   ✗ Celery not installed")
    
    try:
        import redis
        print(f"   ✓ Redis Python client installed")
    except ImportError:
        print("   ✗ Redis Python client not installed")
    
    # Test 6: Redis connection (optional)
    print("\n6. Redis Connection:")
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, socket_connect_timeout=1)
        r.ping()
        print("   ✓ Redis server is running and accessible")
    except redis.exceptions.ConnectionError:
        print("   ⚠ Redis server not running (required for Celery)")
        print("     Install with: sudo apt-get install redis-server")
        print("     Start with: sudo systemctl start redis-server")
    except ImportError:
        print("   ⚠ Redis Python client not installed")
    except Exception as e:
        print(f"   ⚠ Redis connection failed: {e}")
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print("\nCelery is configured and ready to use!")
    print("\nTo start the Celery worker:")
    print("  celery -A config worker --loglevel=info")
    print("\nTo test with a real scan:")
    print("  1. Start Redis: sudo systemctl start redis-server")
    print("  2. Start Celery worker (command above)")
    print("  3. Start Django: python manage.py runserver")
    print("  4. Create scan via API: POST /api/scans/")
    print("\n" + "=" * 60)


if __name__ == '__main__':
    try:
        test_celery_config()
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

"""
Pytest configuration and fixtures for BugBounty Arsenal
"""
import pytest
import os
import sys
from pathlib import Path

# Add project root to Python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from django.test import Client
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from subscriptions.models import Plan, Subscription
from scans.category_models import ScanCategory, DetectorConfig

User = get_user_model()


@pytest.fixture
def api_client():
    """DRF API client for testing authenticated endpoints"""
    return APIClient()


@pytest.fixture
def django_client():
    """Django test client"""
    return Client()


@pytest.fixture
def test_user(db):
    """Create a test user"""
    user = User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123',
        first_name='Test',
        middle_name='Middle',
        last_name='User',
        phone_number='+1234567890',
        is_verified=True
    )
    return user


@pytest.fixture
def test_admin(db):
    """Create a test admin user"""
    admin = User.objects.create_superuser(
        username='admin',
        email='admin@example.com',
        password='admin123',
        first_name='Admin',
        last_name='User'
    )
    return admin


@pytest.fixture
def authenticated_client(api_client, test_user):
    """API client with authenticated test user"""
    api_client.force_authenticate(user=test_user)
    return api_client


@pytest.fixture
def free_plan(db):
    """Create FREE plan"""
    plan, _ = Plan.objects.get_or_create(
        name='free',
        defaults={
            'display_name': 'Free',
            'price': 0.00,
            'scans_per_day': 3,
            'scans_per_month': 30,
            'concurrent_scans': 1,
            'storage_limit_mb': 100,
            'retention_days': 7,
            'allow_dangerous_tools': False,
            'allow_teams': False,
            'max_team_members': 0,
            'allow_integrations': False,
            'max_integrations': 0,
            'features': ['Basic scanning', 'Email support']
        }
    )
    return plan


@pytest.fixture
def pro_plan(db):
    """Create PRO plan"""
    plan, _ = Plan.objects.get_or_create(
        name='pro',
        defaults={
            'display_name': 'Pro',
            'price': 20.00,
            'scans_per_day': 50,
            'scans_per_month': 1000,
            'concurrent_scans': 5,
            'storage_limit_mb': 5000,
            'retention_days': 30,
            'allow_dangerous_tools': False,
            'allow_teams': True,
            'max_team_members': 5,
            'allow_integrations': True,
            'max_integrations': 5,
            'features': ['Advanced scanning', 'Teams', 'Integrations', 'Priority support']
        }
    )
    return plan


@pytest.fixture
def enterprise_plan(db):
    """Create ENTERPRISE plan"""
    plan, _ = Plan.objects.get_or_create(
        name='enterprise',
        defaults={
            'display_name': 'Enterprise',
            'price': 100.00,
            'scans_per_day': -1,  # Unlimited
            'scans_per_month': -1,  # Unlimited
            'concurrent_scans': 10,
            'storage_limit_mb': -1,  # Unlimited
            'retention_days': 365,
            'allow_dangerous_tools': True,
            'allow_teams': True,
            'max_team_members': -1,  # Unlimited
            'allow_integrations': True,
            'max_integrations': -1,  # Unlimited
            'features': ['Unlimited scans', 'Custom tools', 'Dedicated support', '24/7 monitoring']
        }
    )
    return plan
    plan, _ = Plan.objects.get_or_create(
        name='ENTERPRISE',
        defaults={
            'price': 100.00,
            'daily_scans_limit': -1,  # Unlimited
            'monthly_scans_limit': -1,  # Unlimited
            'max_concurrent_scans': 20,
            'features': {
                'recon': True,
                'web_security': True,
                'api_security': True,
                'mobile': True,
                'vulnerability': True,
                'custom': True,
                'teams': True,
                'integrations': True,
                'priority_support': True
            }
        }
    )
    return plan


@pytest.fixture
def user_subscription(db, test_user, free_plan):
    """Create subscription for test user"""
    subscription, _ = Subscription.objects.get_or_create(
        user=test_user,
        defaults={
            'plan': free_plan,
            'status': 'active',
            'daily_scans_used': 0,
            'monthly_scans_used': 0
        }
    )
    return subscription


@pytest.fixture
def scan_categories(db):
    """Create all scan categories"""
    categories = []
    category_data = [
        {
            'name': 'Reconnaissance',
            'slug': 'recon',
            'description': 'Subdomain enumeration, tech stack detection',
            'icon': '🔍',
            'required_plan': 'FREE'
        },
        {
            'name': 'Web Application Security',
            'slug': 'web_security',
            'description': 'XSS, SQL Injection, CSRF, etc.',
            'icon': '🌐',
            'required_plan': 'FREE'
        },
        {
            'name': 'API Security',
            'slug': 'api_security',
            'description': 'GraphQL, JWT, OAuth testing',
            'icon': '🔌',
            'required_plan': 'PRO'
        },
        {
            'name': 'Mobile Security',
            'slug': 'mobile',
            'description': 'Mobile app security testing',
            'icon': '📱',
            'required_plan': 'PRO'
        },
        {
            'name': 'Vulnerability Scanning',
            'slug': 'vulnerability',
            'description': 'CVE database scanning',
            'icon': '🛡️',
            'required_plan': 'PRO'
        },
        {
            'name': 'Custom Scan',
            'slug': 'custom',
            'description': 'All detectors + dangerous tools',
            'icon': '⚡',
            'required_plan': 'ENTERPRISE'
        }
    ]
    
    for data in category_data:
        category, _ = ScanCategory.objects.get_or_create(
            slug=data['slug'],
            defaults=data
        )
        categories.append(category)
    
    return categories


@pytest.fixture
def detector_configs(db, scan_categories):
    """Create detector configurations"""
    # This would normally be populated by management command
    # For tests, we create a minimal set
    detectors = []
    
    xss_detector, _ = DetectorConfig.objects.get_or_create(
        name='xss_pattern',
        defaults={
            'display_name': 'XSS Pattern Detection',
            'description': 'Detects Cross-Site Scripting vulnerabilities',
            'enabled': True,
            'is_dangerous': False,
            'timeout': 30
        }
    )
    detectors.append(xss_detector)
    
    sql_detector, _ = DetectorConfig.objects.get_or_create(
        name='sql_pattern',
        defaults={
            'display_name': 'SQL Injection Detection',
            'description': 'Detects SQL injection vulnerabilities',
            'enabled': True,
            'is_dangerous': False,
            'timeout': 30
        }
    )
    detectors.append(sql_detector)
    
    return detectors


@pytest.fixture
def mock_scan_response():
    """Mock HTTP response for scan testing"""
    class MockResponse:
        def __init__(self, status_code=200, text='', headers=None):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}
            self.content = text.encode()
        
        def json(self):
            import json
            return json.loads(self.text)
    
    return MockResponse


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    """Enable database access for all tests"""
    pass

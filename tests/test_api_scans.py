"""
API Integration tests for scan endpoints
"""
import pytest
from django.urls import reverse
from rest_framework import status
from scans.models import Scan


class TestScanAPI:
    """Test /api/scans/ endpoints"""
    
    @pytest.mark.api
    def test_create_scan_authenticated(self, authenticated_client, user_subscription, scan_categories):
        """Test creating a scan with authenticated user"""
        url = reverse('scan-list')
        data = {
            'target_url': 'https://example.com',
            'category': 'recon',
            'accept_disclaimer': True
        }
        
        response = authenticated_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_201_CREATED
        assert 'id' in response.data
        assert response.data['target_url'] == 'https://example.com'
        assert response.data['status'] == 'pending'
    
    @pytest.mark.api
    def test_create_scan_unauthenticated(self, api_client):
        """Test that unauthenticated users cannot create scans"""
        url = reverse('scan-list')
        data = {
            'target_url': 'https://example.com',
            'category': 'recon'
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.api
    def test_create_scan_exceeds_daily_limit(self, authenticated_client, user_subscription, scan_categories):
        """Test that users cannot exceed daily scan limits"""
        # Set daily scans to limit
        user_subscription.daily_scans_used = user_subscription.plan.daily_scans_limit
        user_subscription.save()
        
        url = reverse('scan-list')
        data = {
            'target_url': 'https://example.com',
            'category': 'recon',
            'accept_disclaimer': True
        }
        
        response = authenticated_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_402_PAYMENT_REQUIRED
        assert 'limit' in response.data.get('error', '').lower()
    
    @pytest.mark.api
    def test_create_scan_invalid_url(self, authenticated_client, user_subscription):
        """Test validation of invalid URLs"""
        url = reverse('scan-list')
        data = {
            'target_url': 'not-a-valid-url',
            'category': 'recon',
            'accept_disclaimer': True
        }
        
        response = authenticated_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    @pytest.mark.api
    def test_create_scan_requires_disclaimer(self, authenticated_client, user_subscription, scan_categories):
        """Test that disclaimer acceptance is required"""
        url = reverse('scan-list')
        data = {
            'target_url': 'https://example.com',
            'category': 'recon',
            'accept_disclaimer': False
        }
        
        response = authenticated_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    @pytest.mark.api
    def test_list_user_scans(self, authenticated_client, test_user, scan_categories):
        """Test listing user's scans"""
        # Create test scans
        web_category = scan_categories[1]  # Web Security
        Scan.objects.create(
            user=test_user,
            target_url='https://example1.com',
            category=web_category,
            status='completed'
        )
        Scan.objects.create(
            user=test_user,
            target_url='https://example2.com',
            category=web_category,
            status='pending'
        )
        
        url = reverse('scan-list')
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 2
    
    @pytest.mark.api
    def test_get_scan_details(self, authenticated_client, test_user, scan_categories):
        """Test retrieving scan details"""
        web_category = scan_categories[1]
        scan = Scan.objects.create(
            user=test_user,
            target_url='https://example.com',
            category=web_category,
            status='completed',
            results={'vulnerabilities': []}
        )
        
        url = reverse('scan-detail', kwargs={'pk': scan.id})
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == scan.id
        assert response.data['target_url'] == 'https://example.com'
    
    @pytest.mark.api
    def test_cannot_access_other_users_scans(self, authenticated_client, test_admin, scan_categories):
        """Test that users cannot access other users' scans"""
        web_category = scan_categories[1]
        # Create scan for different user
        other_scan = Scan.objects.create(
            user=test_admin,
            target_url='https://private.com',
            category=web_category,
            status='completed'
        )
        
        url = reverse('scan-detail', kwargs={'pk': other_scan.id})
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
    
    @pytest.mark.api
    def test_delete_scan(self, authenticated_client, test_user, scan_categories):
        """Test deleting a scan"""
        web_category = scan_categories[1]
        scan = Scan.objects.create(
            user=test_user,
            target_url='https://example.com',
            category=web_category,
            status='completed'
        )
        
        url = reverse('scan-detail', kwargs={'pk': scan.id})
        response = authenticated_client.delete(url)
        
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Scan.objects.filter(id=scan.id).exists()


class TestScanCategoryAPI:
    """Test /api/categories/ endpoints"""
    
    @pytest.mark.api
    def test_list_categories(self, authenticated_client, scan_categories):
        """Test listing all scan categories"""
        url = reverse('scancategory-list')
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 6  # 6 categories
    
    @pytest.mark.api
    def test_category_detector_count(self, authenticated_client, scan_categories, detector_configs):
        """Test that category shows detector count"""
        url = reverse('scancategory-list')
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        # Each category should have detector_count field
        for category in response.data['results']:
            assert 'detector_count' in category
    
    @pytest.mark.api
    def test_category_plan_restriction(self, authenticated_client, scan_categories):
        """Test that categories show required plan"""
        url = reverse('scancategory-list')
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        
        # Find API Security category (requires PRO)
        api_category = next(c for c in response.data['results'] if c['slug'] == 'api_security')
        assert api_category['required_plan'] == 'PRO'
        
        # Find Custom category (requires ENTERPRISE)
        custom_category = next(c for c in response.data['results'] if c['slug'] == 'custom')
        assert custom_category['required_plan'] == 'ENTERPRISE'

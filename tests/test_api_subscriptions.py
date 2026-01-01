"""
Tests for subscription system
"""
import pytest
from django.urls import reverse
from rest_framework import status
from subscriptions.models import Subscription


class TestSubscriptionAPI:
    """Test subscription endpoints"""
    
    @pytest.mark.api
    def test_list_plans(self, api_client, free_plan, pro_plan, enterprise_plan):
        """Test listing all available plans"""
        url = reverse('plan-list')
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 3
        
        # Verify plan details
        plan_names = [p['name'] for p in response.data['results']]
        assert 'FREE' in plan_names
        assert 'PRO' in plan_names
        assert 'ENTERPRISE' in plan_names
    
    @pytest.mark.api
    def test_get_current_subscription(self, authenticated_client, user_subscription):
        """Test getting user's current subscription"""
        url = reverse('my-subscription')
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['plan']['name'] == 'FREE'
        assert response.data['status'] == 'active'
    
    @pytest.mark.api
    def test_upgrade_subscription(self, authenticated_client, user_subscription, pro_plan):
        """Test upgrading subscription to PRO"""
        url = reverse('upgrade-subscription')
        data = {
            'plan_id': pro_plan.id
        }
        
        response = authenticated_client.post(url, data, format='json')
        
        # Should succeed or require payment
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_402_PAYMENT_REQUIRED]
    
    @pytest.mark.api
    def test_subscription_usage_tracking(self, authenticated_client, user_subscription):
        """Test that subscription tracks usage correctly"""
        initial_daily = user_subscription.daily_scans_used
        initial_monthly = user_subscription.monthly_scans_used
        
        url = reverse('my-subscription')
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'daily_scans_used' in response.data
        assert 'monthly_scans_used' in response.data
        assert 'daily_scans_remaining' in response.data
        assert 'monthly_scans_remaining' in response.data
    
    @pytest.mark.api
    def test_cannot_downgrade_below_usage(self, authenticated_client, test_user, free_plan, pro_plan):
        """Test that users cannot downgrade if they've exceeded lower tier limits"""
        # Create PRO subscription with high usage
        subscription = Subscription.objects.create(
            user=test_user,
            plan=pro_plan,
            status='active',
            daily_scans_used=10,  # More than FREE allows (3)
            monthly_scans_used=50
        )
        
        url = reverse('downgrade-subscription')
        data = {
            'plan_id': free_plan.id
        }
        
        response = authenticated_client.post(url, data, format='json')
        
        # Should prevent downgrade
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    @pytest.mark.api
    def test_enterprise_unlimited_scans(self, authenticated_client, test_user, enterprise_plan):
        """Test that ENTERPRISE plan has unlimited scans"""
        subscription = Subscription.objects.create(
            user=test_user,
            plan=enterprise_plan,
            status='active',
            daily_scans_used=1000,  # Way over normal limits
            monthly_scans_used=10000
        )
        
        url = reverse('my-subscription')
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        # Enterprise should show unlimited
        assert response.data['plan']['daily_scans_limit'] == -1
        assert response.data['plan']['monthly_scans_limit'] == -1


class TestSubscriptionLimits:
    """Test subscription limit enforcement"""
    
    @pytest.mark.api
    def test_free_plan_limits(self, free_plan):
        """Verify FREE plan limits"""
        assert free_plan.daily_scans_limit == 3
        assert free_plan.monthly_scans_limit == 30
        assert free_plan.max_concurrent_scans == 1
        assert free_plan.features['recon'] is True
        assert free_plan.features['api_security'] is False
    
    @pytest.mark.api
    def test_pro_plan_limits(self, pro_plan):
        """Verify PRO plan limits"""
        assert pro_plan.daily_scans_limit == 50
        assert pro_plan.monthly_scans_limit == 1000
        assert pro_plan.max_concurrent_scans == 5
        assert pro_plan.features['api_security'] is True
        assert pro_plan.features['teams'] is True
    
    @pytest.mark.api
    def test_enterprise_plan_limits(self, enterprise_plan):
        """Verify ENTERPRISE plan limits"""
        assert enterprise_plan.daily_scans_limit == -1  # Unlimited
        assert enterprise_plan.monthly_scans_limit == -1  # Unlimited
        assert enterprise_plan.max_concurrent_scans == 20
        assert enterprise_plan.features['custom'] is True
    
    @pytest.mark.api
    def test_auto_subscription_creation(self, authenticated_client, test_user, free_plan):
        """Test that FREE subscription is auto-created on first scan"""
        # Delete any existing subscription
        Subscription.objects.filter(user=test_user).delete()
        
        # Create scan (should auto-create FREE subscription)
        from scans.models import ScanCategory
        category = ScanCategory.objects.filter(slug='recon').first()
        
        if category:
            url = reverse('scan-list')
            data = {
                'target_url': 'https://example.com',
                'category': 'recon',
                'accept_disclaimer': True
            }
            
            response = authenticated_client.post(url, data, format='json')
            
            # Should auto-create subscription
            assert Subscription.objects.filter(user=test_user).exists()
            subscription = Subscription.objects.get(user=test_user)
            assert subscription.plan.name == 'FREE'

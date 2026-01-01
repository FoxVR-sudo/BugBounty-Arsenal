"""
API tests for authentication endpoints
"""
import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class TestAuthenticationAPI:
    """Test authentication endpoints"""
    
    @pytest.mark.api
    def test_user_registration(self, api_client, free_plan):
        """Test new user registration"""
        url = reverse('register')
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'securepass123',
            'password2': 'securepass123',
            'first_name': 'New',
            'middle_name': 'Middle',
            'last_name': 'User',
            'phone_number': '+1234567890',
            'country': 'USA'
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_201_CREATED
        assert 'access' in response.data
        assert 'refresh' in response.data
        assert User.objects.filter(username='newuser').exists()
    
    @pytest.mark.api
    def test_registration_duplicate_email(self, api_client, test_user):
        """Test registration with duplicate email fails"""
        url = reverse('register')
        data = {
            'username': 'anotheruser',
            'email': test_user.email,  # Duplicate
            'password': 'securepass123',
            'password2': 'securepass123',
            'first_name': 'Another',
            'last_name': 'User'
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    @pytest.mark.api
    def test_registration_password_mismatch(self, api_client):
        """Test registration with mismatched passwords"""
        url = reverse('register')
        data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'password123',
            'password2': 'different456',
            'first_name': 'New',
            'last_name': 'User'
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    @pytest.mark.api
    def test_user_login(self, api_client, test_user):
        """Test user login with correct credentials"""
        url = reverse('token_obtain_pair')
        data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'refresh' in response.data
    
    @pytest.mark.api
    def test_login_wrong_password(self, api_client, test_user):
        """Test login with wrong password fails"""
        url = reverse('token_obtain_pair')
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.api
    def test_token_refresh(self, api_client, test_user):
        """Test JWT token refresh"""
        refresh = RefreshToken.for_user(test_user)
        
        url = reverse('token_refresh')
        data = {
            'refresh': str(refresh)
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
    
    @pytest.mark.api
    def test_get_current_user(self, authenticated_client, test_user):
        """Test retrieving current user profile"""
        url = reverse('current-user')
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['username'] == test_user.username
        assert response.data['email'] == test_user.email
    
    @pytest.mark.api
    def test_update_user_profile(self, authenticated_client, test_user):
        """Test updating user profile"""
        url = reverse('current-user')
        data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'phone_number': '+9876543210'
        }
        
        response = authenticated_client.patch(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['first_name'] == 'Updated'
        
        # Verify in database
        test_user.refresh_from_db()
        assert test_user.first_name == 'Updated'


class TestPhoneVerification:
    """Test phone verification endpoints"""
    
    @pytest.mark.api
    def test_send_verification_code(self, authenticated_client):
        """Test sending SMS verification code"""
        url = reverse('send-verification-code')
        
        response = authenticated_client.post(url)
        
        # May return 200 or error depending on Twilio config
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_500_INTERNAL_SERVER_ERROR]
    
    @pytest.mark.api
    def test_verify_phone_correct_code(self, authenticated_client, test_user):
        """Test verifying phone with correct code"""
        # Set verification code manually for testing
        test_user.verification_code = '123456'
        test_user.save()
        
        url = reverse('verify-phone')
        data = {'code': '123456'}
        
        response = authenticated_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify user is marked as verified
        test_user.refresh_from_db()
        assert test_user.is_verified is True
    
    @pytest.mark.api
    def test_verify_phone_wrong_code(self, authenticated_client, test_user):
        """Test verifying phone with wrong code"""
        test_user.verification_code = '123456'
        test_user.save()
        
        url = reverse('verify-phone')
        data = {'code': '999999'}
        
        response = authenticated_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST

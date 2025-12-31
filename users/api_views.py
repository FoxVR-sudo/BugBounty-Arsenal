"""
API views for phone and company verification
"""
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .services import PhoneVerificationService, CompanyVerificationService


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_user(request):
    """
    Get current authenticated user info
    
    GET /api/auth/me/
    """
    user = request.user
    
    # Get client IP
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(',')[0]
    else:
        client_ip = request.META.get('REMOTE_ADDR')
    
    # Get subscription plan
    current_plan = 'Free'
    try:
        from subscriptions.models import Subscription
        subscription = Subscription.objects.filter(user=user, status='active').first()
        if subscription:
            current_plan = subscription.plan.display_name
    except:
        pass
    
    return Response({
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'middle_name': user.middle_name,
        'last_name': user.last_name,
        'full_name': user.full_name,
        'phone': user.phone,
        'phone_verified': user.phone_verified,
        'company_name': user.company_name,
        'company_registration_number': user.company_registration_number,
        'company_address': user.company_address,
        'company_country': user.company_country,
        'company_verified': user.company_verified,
        'address': user.address,
        'is_superuser': user.is_superuser,
        'is_staff': user.is_staff,
        'is_admin': user.is_admin,
        'date_joined': user.date_joined,
        'client_ip': client_ip,
        'current_plan': current_plan,
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_phone_verification(request):
    """
    Send SMS verification code to phone number
    
    POST /api/users/verify-phone/send/
    {
        "phone": "+359888123456"  # Optional - uses user.phone if not provided
    }
    """
    # Get phone from request body or user profile
    phone = request.data.get('phone') or request.user.phone
    
    if not phone:
        return Response(
            {'error': 'Phone number is required. Please update your profile.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Format phone number
    service = PhoneVerificationService()
    
    # Validate format
    valid, message = service.validate_phone_format(phone)
    if not valid:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Send verification code
    success, code, message = service.send_verification_code(request.user, phone)
    
    if success:
        response_data = {
            'success': True,
            'message': message,
        }
        # In development, include code in response for easy testing
        if settings.DEBUG and code:
            response_data['code'] = code
        return Response(response_data)
    else:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_phone_code(request):
    """
    Verify SMS code
    
    POST /api/users/verify-phone/confirm/
    {
        "code": "123456"
    }
    """
    code = request.data.get('code')
    
    if not code:
        return Response(
            {'error': 'Verification code is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    service = PhoneVerificationService()
    success, message = service.verify_code(request.user, code)
    
    if success:
        return Response({
            'success': True,
            'message': message,
            'phone_verified': True,
        })
    else:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def resend_phone_verification(request):
    """
    Resend verification code
    
    POST /api/users/verify-phone/resend/
    """
    service = PhoneVerificationService()
    success, code, message = service.resend_code(request.user)
    
    if success:
        return Response({
            'success': True,
            'message': message,
        })
    else:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_company(request):
    """
    Verify company registration
    
    POST /api/users/verify-company/
    {
        "company_name": "Example Ltd",
        "registration_number": "123456789",
        "country_code": "bg"
    }
    """
    company_name = request.data.get('company_name')
    registration_number = request.data.get('registration_number')
    country_code = request.data.get('country_code')
    
    # Validate required fields
    if not all([company_name, registration_number, country_code]):
        return Response(
            {'error': 'company_name, registration_number, and country_code are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Validate country code
    service = CompanyVerificationService()
    supported_countries = service.get_supported_countries()
    
    if country_code.lower() not in supported_countries:
        return Response(
            {
                'error': f'Country code {country_code} not supported',
                'supported_countries': supported_countries
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Validate registration number format
    valid, message = service.validate_registration_number(registration_number, country_code)
    if not valid:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Check subscription plan (Enterprise only)
    if not hasattr(request.user, 'subscription'):
        return Response(
            {'error': 'No active subscription found'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    if request.user.subscription.plan.name != 'enterprise':
        return Response(
            {'error': 'Company verification is only available for Enterprise plan'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Verify company
    success, message, data = service.verify_company(
        request.user,
        company_name,
        registration_number,
        country_code
    )
    
    if success:
        return Response({
            'success': True,
            'message': message,
            'company_verified': True,
            'company_data': data,
        })
    else:
        return Response({
            'success': False,
            'message': message,
            'company_verified': False,
            'manual_review_required': True,
        }, status=status.HTTP_202_ACCEPTED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def search_company(request):
    """
    Search for company (for autocomplete/lookup)
    
    GET /api/users/search-company/?q=example&country=bg
    """
    query = request.GET.get('q')
    country = request.GET.get('country')
    
    if not query:
        return Response(
            {'error': 'Query parameter "q" is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    service = CompanyVerificationService()
    result = service.search_company(query, country)
    
    return Response(result)


@api_view(['GET'])
def get_supported_countries(request):
    """
    Get list of supported countries for company verification
    
    GET /api/users/supported-countries/
    """
    service = CompanyVerificationService()
    countries = service.get_supported_countries()
    
    return Response({
        'countries': [
            {'code': code, 'name': name}
            for code, name in countries.items()
        ]
    })

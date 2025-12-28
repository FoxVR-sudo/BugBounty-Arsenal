"""
API views for phone and company verification
"""
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .services import PhoneVerificationService, CompanyVerificationService


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_phone_verification(request):
    """
    Send SMS verification code to phone number
    
    POST /api/users/verify-phone/send/
    {
        "phone": "+359888123456"
    }
    """
    phone = request.data.get('phone')
    
    if not phone:
        return Response(
            {'error': 'Phone number is required'},
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
        return Response({
            'success': True,
            'message': message,
            # Don't send code in production, only in development
            # 'code': code if settings.DEBUG else None,
        })
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

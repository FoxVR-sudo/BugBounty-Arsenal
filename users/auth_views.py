"""
Authentication views for login and signup with JWT tokens.
"""
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.throttling import AnonRateThrottle
from django.contrib.auth import authenticate, login as django_login
from drf_spectacular.utils import extend_schema, OpenApiExample
from .serializers import UserCreateSerializer, UserSerializer
import logging

logger = logging.getLogger(__name__)


# Custom throttle for login attempts
class LoginRateThrottle(AnonRateThrottle):
    scope = 'login'  # Uses 'login' rate from settings (5/hour)


@extend_schema(
    summary="User Login",
    description="Authenticate user and return JWT access and refresh tokens",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'email': {'type': 'string', 'format': 'email'},
                'password': {'type': 'string', 'format': 'password'}
            },
            'required': ['email', 'password']
        }
    },
    responses={
        200: {
            'type': 'object',
            'properties': {
                'access': {'type': 'string', 'description': 'JWT access token'},
                'refresh': {'type': 'string', 'description': 'JWT refresh token'},
                'user': {'type': 'object', 'description': 'User information'}
            }
        },
        401: {
            'type': 'object',
            'properties': {
                'error': {'type': 'string'}
            }
        }
    },
    examples=[
        OpenApiExample(
            'Login Example',
            value={
                'email': 'user@example.com',
                'password': 'SecurePass123!'
            }
        )
    ]
)
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def login_view(request):
    """
    User login endpoint with rate limiting (5 attempts per hour).
    
    Accepts email and password, returns JWT tokens and user data.
    """
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email or not password:
        return Response(
            {'error': 'Email and password are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Authenticate user
    user = authenticate(request, username=email, password=password)
    
    if user is None:
        logger.warning(f"Failed login attempt for email: {email} from IP: {request.META.get('REMOTE_ADDR')}")
        return Response(
            {'error': 'Invalid email or password'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    if not user.is_active:
        return Response(
            {'error': 'Account is deactivated'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Create Django session for template views
    django_login(request, user)
    
    # Generate JWT tokens
    refresh = RefreshToken.for_user(user)
    
    # Serialize user data
    user_serializer = UserSerializer(user)
    
    return Response({
        'access': str(refresh.access_token),
        'refresh': str(refresh),
        'user': user_serializer.data
    }, status=status.HTTP_200_OK)


@extend_schema(
    summary="User Registration",
    description="Register a new user account and return JWT tokens",
    tags=["Authentication"],
    request=UserCreateSerializer,
    responses={
        201: {
            'type': 'object',
            'properties': {
                'access': {'type': 'string', 'description': 'JWT access token'},
                'refresh': {'type': 'string', 'description': 'JWT refresh token'},
                'user': {'type': 'object', 'description': 'User information'}
            }
        },
        400: {
            'type': 'object',
            'properties': {
                'errors': {'type': 'object'}
            }
        }
    },
    examples=[
        OpenApiExample(
            'Registration Example',
            value={
                'email': 'newuser@example.com',
                'password': 'SecurePass123!',
                'password_confirm': 'SecurePass123!',
                'first_name': 'John',
                'last_name': 'Doe'
            }
        )
    ]
)
@api_view(['POST'])
@permission_classes([AllowAny])
def signup_view(request):
    """
    User registration endpoint with optional plan selection.
    
    Creates a new user account and returns JWT tokens.
    If a paid plan (Pro/Enterprise) is selected, also returns checkout URL.
    """
    from subscriptions.models import Plan
    from subscriptions.stripe_service import StripeService
    from django.conf import settings
    
    logger.info(f"Signup request data: {request.data}")
    
    serializer = UserCreateSerializer(data=request.data)
    
    if not serializer.is_valid():
        logger.error(f"Signup validation failed: {serializer.errors}")
        return Response(
            {'errors': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Create user
    user = serializer.save()
    
    # Create Django session for template views
    django_login(request, user)
    
    # Generate JWT tokens
    refresh = RefreshToken.for_user(user)
    
    # Serialize user data
    user_serializer = UserSerializer(user)
    
    response_data = {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
        'user': user_serializer.data
    }
    
    # Auto-create Free plan subscription for all new users
    try:
        from subscriptions.models import Plan, Subscription
        free_plan = Plan.objects.get(name__iexact='free')
        Subscription.objects.create(
            user=user,
            plan=free_plan,
            status='active'
        )
        logger.info(f"Created Free subscription for user {user.email}")
    except Plan.DoesNotExist:
        logger.warning("Free plan not found in database")
    except Exception as e:
        logger.error(f"Failed to create subscription: {str(e)}")
    
    return Response(response_data, status=status.HTTP_201_CREATED)


@extend_schema(
    summary="Enterprise Registration",
    description="Register a new enterprise customer account with company details",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'email': {'type': 'string'},
                'password': {'type': 'string'},
                'password_confirm': {'type': 'string'},
                'first_name': {'type': 'string'},
                'last_name': {'type': 'string'},
                'phone': {'type': 'string'},
                'company_name': {'type': 'string'},
                'vat_number': {'type': 'string'},
                'registration_number': {'type': 'string'},
                'billing_address': {'type': 'string'},
                'billing_city': {'type': 'string'},
                'billing_country': {'type': 'string'},
                'payment_terms': {'type': 'string'},
            }
        }
    },
    responses={201: {'type': 'object'}}
)
@api_view(['POST'])
@permission_classes([AllowAny])
def signup_enterprise_view(request):
    """Enterprise customer registration with company details."""
    from subscriptions.models import Plan, EnterpriseCustomer
    from subscriptions.stripe_service import StripeService
    from django.conf import settings
    
    serializer = UserCreateSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
    # Create user
    user = serializer.save()
    django_login(request, user)
    
    # Generate JWT tokens
    refresh = RefreshToken.for_user(user)
    user_serializer = UserSerializer(user)
    
    response_data = {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
        'user': user_serializer.data
    }
    
    # Get Enterprise plan
    try:
        enterprise_plan = Plan.objects.get(name__iexact='enterprise')
    except Plan.DoesNotExist:
        return Response({'error': 'Enterprise plan not found'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # Create EnterpriseCustomer record
    EnterpriseCustomer.objects.create(
        user=user,
        company_name=request.data.get('company_name'),
        vat_number=request.data.get('vat_number', ''),
        registration_number=request.data.get('registration_number', ''),
        billing_address=request.data.get('billing_address'),
        billing_city=request.data.get('billing_city'),
        billing_country=request.data.get('billing_country', 'Bulgaria'),
        billing_zip=request.data.get('billing_zip', ''),
        billing_email=request.data.get('billing_email', user.email),
        billing_phone=request.data.get('billing_phone', request.data.get('phone', '')),
        accounting_contact_name=request.data.get('accounting_contact_name', ''),
        accounting_contact_email=request.data.get('accounting_contact_email', ''),
        payment_terms=request.data.get('payment_terms', 'net_30'),
        use_stripe=True
    )
    
    # Create Stripe checkout for Enterprise plan
    frontend_url = settings.FRONTEND_URL
    try:
        checkout_session = StripeService.create_checkout_session(
            user=user,
            plan=enterprise_plan,
            success_url=f"{frontend_url}/payment-success",
            cancel_url=f"{frontend_url}/register-enterprise?payment=cancelled"
        )
        response_data['checkout_url'] = checkout_session.url
        response_data['requires_payment'] = True
    except Exception:
        response_data['checkout_url'] = f"{frontend_url}/pricing"
        response_data['requires_payment'] = True
        response_data['test_mode'] = True
    
    return Response(response_data, status=status.HTTP_201_CREATED)


@extend_schema(
    summary="Refresh JWT Token",
    description="Obtain a new access token using a refresh token",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'refresh': {'type': 'string', 'description': 'JWT refresh token'}
            },
            'required': ['refresh']
        }
    },
    responses={
        200: {
            'type': 'object',
            'properties': {
                'access': {'type': 'string', 'description': 'New JWT access token'}
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def token_refresh_view(request):
    """
    Refresh JWT access token.
    
    Accepts a refresh token and returns a new access token.
    """
    refresh_token = request.data.get('refresh')
    
    if not refresh_token:
        return Response(
            {'error': 'Refresh token is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        refresh = RefreshToken(refresh_token)
        return Response({
            'access': str(refresh.access_token)
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response(
            {'error': 'Invalid or expired refresh token'},
            status=status.HTTP_401_UNAUTHORIZED
        )

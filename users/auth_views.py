"""
Authentication views for login and signup with JWT tokens.
"""
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from drf_spectacular.utils import extend_schema, OpenApiExample
from .serializers import UserCreateSerializer, UserSerializer


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
def login_view(request):
    """
    User login endpoint.
    
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
        return Response(
            {'error': 'Invalid email or password'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    if not user.is_active:
        return Response(
            {'error': 'Account is deactivated'},
            status=status.HTTP_403_FORBIDDEN
        )
    
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
    User registration endpoint.
    
    Creates a new user account and returns JWT tokens.
    """
    serializer = UserCreateSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(
            {'errors': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Create user
    user = serializer.save()
    
    # Generate JWT tokens
    refresh = RefreshToken.for_user(user)
    
    # Serialize user data
    user_serializer = UserSerializer(user)
    
    return Response({
        'access': str(refresh.access_token),
        'refresh': str(refresh),
        'user': user_serializer.data
    }, status=status.HTTP_201_CREATED)


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

"""
Email Verification and Password Reset Views
"""
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from utils.sendgrid_service import sendgrid_service
from drf_spectacular.utils import extend_schema, OpenApiExample
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


@extend_schema(
    summary="Request email verification",
    description="Send email verification link to user's email address",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'email': {'type': 'string', 'format': 'email'}
            },
            'required': ['email']
        }
    },
    responses={
        200: {
            'description': 'Verification email sent',
            'content': {
                'application/json': {
                    'example': {
                        'message': 'Verification email sent. Please check your inbox.'
                    }
                }
            }
        }
    },
    examples=[
        OpenApiExample(
            'Email Verification Request',
            value={'email': 'user@example.com'}
        )
    ]
)
@api_view(['POST'])
@permission_classes([AllowAny])
def request_email_verification(request):
    """
    Send email verification link to user
    """
    email = request.data.get('email')
    
    if not email:
        return Response(
            {'error': 'Email is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        user = User.objects.get(email=email)
        
        if user.is_verified:
            return Response(
                {'message': 'Email is already verified'},
                status=status.HTTP_200_OK
            )
        
        # Generate verification token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        
        # Create verification URL
        verification_url = f"{settings.FRONTEND_URL}/verify-email/{uid}/{token}/"
        
        # Send email
        success = sendgrid_service.send_verification_email(
            user_email=user.email,
            user_name=user.get_full_name() or user.email.split('@')[0],
            verification_url=verification_url
        )
        
        if success:
            return Response(
                {'message': 'Verification email sent. Please check your inbox.'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'Failed to send email. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    except User.DoesNotExist:
        # Don't reveal if email exists or not (security)
        return Response(
            {'message': 'If this email exists, a verification link has been sent.'},
            status=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f'Email verification error: {str(e)}')
        return Response(
            {'error': 'An error occurred. Please try again later.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Verify email address",
    description="Verify user's email address using token from email",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'uid': {'type': 'string'},
                'token': {'type': 'string'}
            },
            'required': ['uid', 'token']
        }
    },
    responses={
        200: {
            'description': 'Email verified successfully',
            'content': {
                'application/json': {
                    'example': {
                        'message': 'Email verified successfully!'
                    }
                }
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def verify_email(request):
    """
    Verify email using uid and token from verification link
    """
    uid = request.data.get('uid')
    token = request.data.get('token')
    
    if not uid or not token:
        return Response(
            {'error': 'Invalid verification link'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Decode user ID
        user_id = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=user_id)
        
        # Verify token
        if default_token_generator.check_token(user, token):
            user.is_verified = True
            user.save()
            
            # Send welcome email
            sendgrid_service.send_welcome_email(
                user_email=user.email,
                user_name=user.get_full_name() or user.email.split('@')[0]
            )
            
            return Response(
                {'message': 'Email verified successfully! You can now log in.'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'Invalid or expired verification link'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response(
            {'error': 'Invalid verification link'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        logger.error(f'Email verification error: {str(e)}')
        return Response(
            {'error': 'An error occurred. Please try again later.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Request password reset",
    description="Send password reset link to user's email",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'email': {'type': 'string', 'format': 'email'}
            },
            'required': ['email']
        }
    },
    examples=[
        OpenApiExample(
            'Password Reset Request',
            value={'email': 'user@example.com'}
        )
    ]
)
@api_view(['POST'])
@permission_classes([AllowAny])
def request_password_reset(request):
    """
    Send password reset link to user's email
    """
    email = request.data.get('email')
    
    if not email:
        return Response(
            {'error': 'Email is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        user = User.objects.get(email=email)
        
        # Generate reset token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        
        # Create reset URL
        reset_url = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"
        
        # Send email
        success = sendgrid_service.send_password_reset_email(
            user_email=user.email,
            user_name=user.get_full_name() or user.email.split('@')[0],
            reset_url=reset_url
        )
        
        if success:
            return Response(
                {'message': 'Password reset link sent. Please check your email.'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'Failed to send email. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    except User.DoesNotExist:
        # Don't reveal if email exists (security)
        return Response(
            {'message': 'If this email exists, a reset link has been sent.'},
            status=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f'Password reset error: {str(e)}')
        return Response(
            {'error': 'An error occurred. Please try again later.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Reset password",
    description="Reset user's password using token from email",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'uid': {'type': 'string'},
                'token': {'type': 'string'},
                'new_password': {'type': 'string', 'minLength': 8}
            },
            'required': ['uid', 'token', 'new_password']
        }
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request):
    """
    Reset password using uid, token, and new password
    """
    uid = request.data.get('uid')
    token = request.data.get('token')
    new_password = request.data.get('new_password')
    
    if not all([uid, token, new_password]):
        return Response(
            {'error': 'Missing required fields'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if len(new_password) < 8:
        return Response(
            {'error': 'Password must be at least 8 characters'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Decode user ID
        user_id = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=user_id)
        
        # Verify token
        if default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            
            return Response(
                {'message': 'Password reset successfully! You can now log in.'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'Invalid or expired reset link'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response(
            {'error': 'Invalid reset link'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        logger.error(f'Password reset error: {str(e)}')
        return Response(
            {'error': 'An error occurred. Please try again later.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

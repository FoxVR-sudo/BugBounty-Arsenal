"""
API views for subscription and plan management
"""
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .models import Plan, Subscription
from .stripe_service import StripeService
import logging

logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_plans(request):
    """
    Get all active plans for pricing page
    
    GET /api/plans/
    """
    plans = Plan.objects.filter(is_active=True).order_by('order', 'price')
    
    data = []
    for plan in plans:
        data.append({
            'id': plan.id,
            'name': plan.name,
            'display_name': plan.display_name,
            'description': plan.description,
            'price': float(plan.price),
            'features': plan.features or [],
            'daily_scan_limit': plan.scans_per_day,
            'monthly_scan_limit': plan.scans_per_month,
            'concurrent_scans': plan.concurrent_scans,
            'storage_limit_mb': plan.storage_limit_mb,
            'retention_days': plan.retention_days,
            'allow_dangerous_tools': plan.allow_dangerous_tools,
            'allow_teams': plan.allow_teams,
            'max_team_members': plan.max_team_members,
            'allow_integrations': plan.allow_integrations,
            'max_integrations': plan.max_integrations,
            'is_popular': plan.is_popular,
        })
    
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_subscription(request):
    """
    Get current user's subscription details with full billing info
    
    GET /api/subscriptions/current/
    """
    try:
        subscription = Subscription.objects.get(user=request.user, status='active')
        
        # Get plan features
        plan_features = subscription.plan.features or []
        
        data = {
            'id': subscription.id,
            'plan_name': subscription.plan.display_name,
            'plan_id': subscription.plan.id,
            'daily_scan_limit': subscription.plan.scans_per_day,
            'monthly_scan_limit': subscription.plan.scans_per_month,
            'concurrent_scans': subscription.plan.concurrent_scans,
            'storage_limit_mb': subscription.plan.storage_limit_mb,
            'retention_days': subscription.plan.retention_days,
            'status': subscription.status,
            'scans_used_today': subscription.scans_used_today,
            'scans_used_this_month': subscription.scans_used_this_month,
            'current_period_start': subscription.current_period_start,
            'current_period_end': subscription.current_period_end,
            'cancel_at_period_end': subscription.cancel_at_period_end,
            'stripe_subscription_id': subscription.stripe_subscription_id,
            'stripe_customer_id': subscription.stripe_customer_id,
            'plan': {
                'name': subscription.plan.name,
                'display_name': subscription.plan.display_name,
                'description': subscription.plan.description,
                'price': float(subscription.plan.price),
                'features': plan_features,
                'is_popular': subscription.plan.is_popular,
            },
            # Check if user is enterprise customer
            'is_enterprise': hasattr(request.user, 'enterprise_customer'),
        }
        
        return Response(data)
        
    except Subscription.DoesNotExist:
        # Return free plan defaults
        try:
            free_plan = Plan.objects.get(name='free')
            return Response({
                'plan_name': 'Free',
                'plan_id': free_plan.id,
                'daily_scan_limit': free_plan.scans_per_day,
                'monthly_scan_limit': free_plan.scans_per_month,
                'status': 'active',
                'scans_used_today': 0,
                'scans_used_this_month': 0,
                'plan': {
                    'name': 'free',
                    'display_name': 'Free',
                    'price': 0,
                    'features': free_plan.features or [],
                },
                'is_enterprise': False,
            })
        except Plan.DoesNotExist:
            return Response({'error': 'No plan found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_subscription(request):
    """
    Cancel user's subscription
    
    POST /api/subscriptions/cancel/
    Body: { "immediate": false }  // true = cancel now, false = cancel at period end
    """
    try:
        subscription = Subscription.objects.get(user=request.user, status='active')
    except Subscription.DoesNotExist:
        return Response({'error': 'No active subscription found'}, status=status.HTTP_404_NOT_FOUND)
    
    # Check if already cancelled
    if subscription.cancel_at_period_end:
        return Response({'error': 'Subscription already scheduled for cancellation'}, status=status.HTTP_400_BAD_REQUEST)
    
    immediate = request.data.get('immediate', False)
    
    # If free plan or no Stripe subscription, just mark as cancelled
    if not subscription.stripe_subscription_id or subscription.plan.price == 0:
        subscription.status = 'cancelled'
        subscription.save()
        return Response({
            'message': 'Subscription cancelled',
            'cancel_at_period_end': False,
        })
    
    # Cancel Stripe subscription
    try:
        StripeService.cancel_subscription(
            subscription.stripe_subscription_id,
            at_period_end=not immediate
        )
        
        if immediate:
            subscription.status = 'cancelled'
            subscription.cancel_at_period_end = False
        else:
            subscription.cancel_at_period_end = True
        
        subscription.save()
        
        return Response({
            'message': 'Subscription cancelled successfully',
            'cancel_at_period_end': subscription.cancel_at_period_end,
            'current_period_end': subscription.current_period_end,
        })
    except Exception as e:
        logger.error(f'Failed to cancel subscription: {str(e)}')
        return Response({'error': 'Failed to cancel subscription'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_plan(request):
    """
    Upgrade or downgrade subscription plan
    
    POST /api/subscriptions/change-plan/
    Body: { "new_plan_id": 2 }
    """
    new_plan_id = request.data.get('new_plan_id')
    
    if not new_plan_id:
        return Response({'error': 'new_plan_id is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        new_plan = Plan.objects.get(id=new_plan_id, is_active=True)
    except Plan.DoesNotExist:
        return Response({'error': 'Plan not found'}, status=status.HTTP_404_NOT_FOUND)
    
    try:
        subscription = Subscription.objects.get(user=request.user, status='active')
    except Subscription.DoesNotExist:
        # No subscription - create checkout for new plan
        if new_plan.price > 0:
            try:
                frontend_url = settings.FRONTEND_URL
                checkout_session = StripeService.create_checkout_session(
                    user=request.user,
                    plan=new_plan,
                    success_url=f"{frontend_url}/subscription?upgraded=true",
                    cancel_url=f"{frontend_url}/subscription"
                )
                return Response({
                    'checkout_url': checkout_session.url,
                    'requires_payment': True,
                })
            except Exception as e:
                logger.error(f'Failed to create checkout: {str(e)}')
                return Response({'error': 'Failed to create checkout session'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            # Free plan - create subscription
            subscription = Subscription.objects.create(
                user=request.user,
                plan=new_plan,
                status='active'
            )
            return Response({
                'message': 'Plan changed successfully',
                'new_plan': new_plan.display_name,
            })
    
    # User has subscription - check if same plan
    if subscription.plan.id == new_plan_id:
        return Response({'error': 'Already on this plan'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Downgrade to free plan
    if new_plan.price == 0:
        if subscription.stripe_subscription_id:
            try:
                StripeService.cancel_subscription(subscription.stripe_subscription_id, at_period_end=True)
            except Exception as e:
                logger.error(f'Failed to cancel for downgrade: {str(e)}')
        
        subscription.plan = new_plan
        subscription.cancel_at_period_end = True
        subscription.save()
        
        return Response({
            'message': f'Plan will change to {new_plan.display_name} at period end',
            'current_period_end': subscription.current_period_end,
        })
    
    # Upgrade/change paid plan
    if subscription.stripe_subscription_id:
        try:
            StripeService.update_subscription(subscription.stripe_subscription_id, new_plan)
            subscription.plan = new_plan
            subscription.cancel_at_period_end = False
            subscription.save()
            
            return Response({
                'message': f'Plan changed to {new_plan.display_name}',
                'new_plan': new_plan.display_name,
                'proration': 'You will be charged/credited the prorated amount',
            })
        except Exception as e:
            logger.error(f'Failed to update subscription: {str(e)}')
            return Response({'error': 'Failed to update subscription'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        # No Stripe subscription, create new checkout
        try:
            frontend_url = settings.FRONTEND_URL
            checkout_session = StripeService.create_checkout_session(
                user=request.user,
                plan=new_plan,
                success_url=f"{frontend_url}/subscription?upgraded=true",
                cancel_url=f"{frontend_url}/subscription"
            )
            return Response({
                'checkout_url': checkout_session.url,
                'requires_payment': True,
            })
        except Exception as e:
            logger.error(f'Failed to create checkout: {str(e)}')
            return Response({'error': 'Failed to create checkout session'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reactivate_subscription(request):
    """
    Reactivate a cancelled subscription (cancel the cancellation)
    
    POST /api/subscriptions/reactivate/
    """
    try:
        subscription = Subscription.objects.get(user=request.user)
    except Subscription.DoesNotExist:
        return Response({'error': 'No subscription found'}, status=status.HTTP_404_NOT_FOUND)
    
    if not subscription.cancel_at_period_end:
        return Response({'error': 'Subscription is not scheduled for cancellation'}, status=status.HTTP_400_BAD_REQUEST)
    
    if subscription.stripe_subscription_id:
        try:
            # Update Stripe subscription to not cancel
            import stripe
            stripe.api_key = settings.STRIPE_SECRET_KEY
            stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                cancel_at_period_end=False
            )
            
            subscription.cancel_at_period_end = False
            subscription.save()
            
            return Response({
                'message': 'Subscription reactivated successfully',
            })
        except Exception as e:
            logger.error(f'Failed to reactivate subscription: {str(e)}')
            return Response({'error': 'Failed to reactivate subscription'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        subscription.cancel_at_period_end = False
        subscription.status = 'active'
        subscription.save()
        
        return Response({
            'message': 'Subscription reactivated successfully',
        })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def sync_subscription(request):
    """
    Sync subscription with Stripe after successful checkout
    
    POST /api/subscriptions/sync/
    Body: { "session_id": "cs_test_..." }
    """
    import stripe
    
    session_id = request.data.get('session_id')
    if not session_id:
        return Response({'error': 'session_id required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Retrieve checkout session from Stripe
        session = stripe.checkout.Session.retrieve(session_id)
        
        if session.payment_status != 'paid':
            return Response({'error': 'Payment not completed'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Handle checkout completion (update subscription)
        StripeService.handle_checkout_completed(session)
        
        return Response({
            'message': 'Subscription synced successfully',
            'status': 'success'
        })
        
    except stripe.error.StripeError as e:
        logger.error(f'Stripe error during sync: {str(e)}')
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f'Failed to sync subscription: {str(e)}')
        return Response({'error': 'Failed to sync subscription'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
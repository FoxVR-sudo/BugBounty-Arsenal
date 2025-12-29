"""
API views for subscription and plan management
"""
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Plan, Subscription


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
    Get current user's subscription details
    
    GET /api/subscriptions/current/
    """
    try:
        subscription = Subscription.objects.get(user=request.user, status='active')
        
        # Calculate can_scan status
        can_scan, message = subscription.can_create_scan()
        
        data = {
            'id': subscription.id,
            'plan_name': subscription.plan.display_name,
            'plan_id': subscription.plan.id,
            'daily_scan_limit': subscription.plan.scans_per_day,
            'monthly_scan_limit': subscription.plan.scans_per_month,
            'status': subscription.status,
            'scans_used_today': subscription.scans_used_today,
            'scans_used_this_month': subscription.scans_used_this_month,
            'can_scan': [can_scan, message],
            'current_period_start': subscription.current_period_start,
            'current_period_end': subscription.current_period_end,
            'cancel_at_period_end': subscription.cancel_at_period_end,
            'plan': {
                'name': subscription.plan.name,
                'display_name': subscription.plan.display_name,
                'price': float(subscription.plan.price),
            }
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
                'can_scan': [True, 'OK'],
                'plan': {
                    'name': 'free',
                    'display_name': 'Free',
                    'price': 0,
                }
            })
        except Plan.DoesNotExist:
            return Response({'error': 'No plan found'}, status=status.HTTP_404_NOT_FOUND)

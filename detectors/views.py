from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from detectors.detector_categories import (
    DETECTOR_CATEGORIES,
    PLAN_ACCESS,
    get_categories_for_plan,
    get_allowed_detectors_for_plan,
    is_detector_allowed_for_plan,
)


class DetectorCategoryViewSet(viewsets.ViewSet):
    """
    API endpoint for detector categories and plan-based access control.
    Shows which detectors are available for the user's current plan.
    """
    permission_classes = [AllowAny]  # Public for browsing, but shows plan restrictions
    
    def list(self, request):
        """
        Get all detector categories with plan-based access info.
        If authenticated, shows which are allowed for user's plan.
        If not authenticated, shows as if on Free plan.
        """
        # Determine user's plan
        plan_name = 'free'
        if request.user.is_authenticated:
            try:
                from subscriptions.models import Subscription
                subscription = Subscription.objects.get(user=request.user)
                plan_name = subscription.plan.name
            except Subscription.DoesNotExist:
                pass
        
        # Get categories with access info
        categories = get_categories_for_plan(plan_name)
        
        return Response({
            'current_plan': plan_name,
            'categories': categories,
            'total_categories': len(categories),
            'unlocked_categories': len([c for c in categories if c['is_allowed']]),
        })
    
    @action(detail=False, methods=['get'])
    def allowed(self, request):
        """
        Get only the allowed detectors for user's plan (useful for scan creation).
        """
        plan_name = 'free'
        if request.user.is_authenticated:
            try:
                from subscriptions.models import Subscription
                subscription = Subscription.objects.get(user=request.user)
                plan_name = subscription.plan.name
            except Subscription.DoesNotExist:
                pass
        
        allowed_detectors = get_allowed_detectors_for_plan(plan_name)
        allowed_categories = PLAN_ACCESS.get(plan_name, [])
        
        return Response({
            'plan': plan_name,
            'allowed_categories': allowed_categories,
            'allowed_detectors': allowed_detectors,
            'detector_count': len(allowed_detectors),
        })
    
    @action(detail=False, methods=['post'])
    def validate(self, request):
        """
        Validate if a list of detectors is allowed for user's plan.
        Request body: {"detectors": ["detector1", "detector2", ...]}
        """
        detectors = request.data.get('detectors', [])
        
        plan_name = 'free'
        if request.user.is_authenticated:
            try:
                from subscriptions.models import Subscription
                subscription = Subscription.objects.get(user=request.user)
                plan_name = subscription.plan.name
            except Subscription.DoesNotExist:
                pass
        
        # Check each detector
        results = []
        all_allowed = True
        
        for detector in detectors:
            is_allowed = is_detector_allowed_for_plan(detector, plan_name)
            if not is_allowed:
                all_allowed = False
            
            results.append({
                'detector': detector,
                'is_allowed': is_allowed,
            })
        
        return Response({
            'plan': plan_name,
            'all_allowed': all_allowed,
            'results': results,
        })

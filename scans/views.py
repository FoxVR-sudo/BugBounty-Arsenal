from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from drf_spectacular.utils import extend_schema, OpenApiParameter
from .models import Scan, AuditLog, ApiKey
from .serializers import (
    ScanSerializer,
    ScanDetailSerializer,
    AuditLogSerializer,
    ApiKeySerializer
)


class ScanViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Scan CRUD operations
    """
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['scan_type', 'status']
    search_fields = ['target']
    ordering_fields = ['started_at', 'completed_at', 'vulnerabilities_found']
    ordering = ['-started_at']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return ScanDetailSerializer
        return ScanSerializer

    def get_queryset(self):
        # Users can only see their own scans
        # Admins can see all scans
        if self.request.user.is_admin or self.request.user.is_staff:
            return Scan.objects.all()
        return Scan.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """Create scan and start async execution"""
        # Save the scan instance
        scan = serializer.save(user=self.request.user)
        
        # Get scan configuration from request data
        scan_config = {
            'concurrency': self.request.data.get('concurrency', 10),
            'timeout': self.request.data.get('timeout', 15),
            'per_host_rate': self.request.data.get('per_host_rate', 1.0),
            'allow_destructive': self.request.data.get('allow_destructive', False),
            'bypass_cloudflare': self.request.data.get('bypass_cloudflare', False),
            'enable_forbidden_probe': self.request.data.get('enable_forbidden_probe', False),
            'scan_mode': self.request.data.get('scan_mode', 'normal'),
        }
        
        # Start async scan
        scan.start_async_scan(scan_config)

    @extend_schema(
        description="Cancel a running or pending scan",
        responses={200: {'description': 'Scan cancelled successfully'}}
    )
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def cancel(self, request, pk=None):
        """Cancel a running or pending scan"""
        scan = self.get_object()
        
        if scan.status not in ['running', 'pending']:
            return Response(
                {'error': f'Cannot cancel scan with status: {scan.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Cancel the scan
        if scan.cancel_scan():
            return Response(
                {'message': 'Scan cancelled successfully'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'Failed to cancel scan'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @extend_schema(
        description="Get the current status of a scan's Celery task",
        responses={200: {'description': 'Task status information'}}
    )
    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated])
    def task_status(self, request, pk=None):
        """Get the current status of the scan's Celery task"""
        scan = self.get_object()
        task_status = scan.get_task_status()
        
        if task_status is None:
            return Response(
                {'error': 'No task associated with this scan'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        return Response(task_status, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def stats(self, request):
        """Get scan statistics for current user"""
        queryset = self.get_queryset()
        return Response({
            'total_scans': queryset.count(),
            'completed': queryset.filter(status='completed').count(),
            'running': queryset.filter(status='running').count(),
            'failed': queryset.filter(status='failed').count(),
            'pending': queryset.filter(status='pending').count(),
        })


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for AuditLog (read-only)
    """
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['event_type', 'user']
    search_fields = ['description', 'event_type']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        # Users can only see their own audit logs
        # Admins can see all audit logs
        if self.request.user.is_admin or self.request.user.is_staff:
            return AuditLog.objects.all()
        return AuditLog.objects.filter(user=self.request.user)


class ApiKeyViewSet(viewsets.ModelViewSet):
    """
    ViewSet for ApiKey CRUD operations
    """
    serializer_class = ApiKeySerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['is_active']
    ordering_fields = ['created_at', 'last_used_at']
    ordering = ['-created_at']

    def get_queryset(self):
        # Users can only see their own API keys
        # Admins can see all API keys
        if self.request.user.is_admin or self.request.user.is_staff:
            return ApiKey.objects.all()
        return ApiKey.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        # Set the user from request
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def revoke(self, request, pk=None):
        """Revoke (deactivate) an API key"""
        api_key = self.get_object()
        api_key.is_active = False
        api_key.save()
        return Response({'message': 'API key revoked successfully'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def regenerate(self, request, pk=None):
        """Regenerate an API key"""
        api_key = self.get_object()
        api_key.regenerate_key()
        serializer = self.get_serializer(api_key)
        return Response(serializer.data)

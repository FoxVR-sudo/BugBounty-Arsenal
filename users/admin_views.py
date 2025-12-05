"""
Admin API views for user and system management.
Requires admin/staff permissions.
"""
import logging
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework import status

from scans.models import Scan
from subscriptions.models import Subscription, Plan

User = get_user_model()
logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_stats(request):
    """
    Get comprehensive dashboard statistics.
    
    Returns:
        - User statistics (total, active, new this month)
        - Scan statistics (total, by status)
        - Subscription statistics
        - Revenue metrics (if available)
    """
    now = timezone.now()
    month_ago = now - timedelta(days=30)
    
    # User statistics
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    new_users_this_month = User.objects.filter(date_joined__gte=month_ago).count()
    
    # Scan statistics
    total_scans = Scan.objects.count()
    scans_by_status = Scan.objects.values('status').annotate(count=Count('id'))
    scans_this_month = Scan.objects.filter(created_at__gte=month_ago).count()
    
    # Subscription statistics
    active_subscriptions = Subscription.objects.filter(status='active').count()
    subscriptions_by_plan = Subscription.objects.filter(
        status='active'
    ).values('plan__name').annotate(count=Count('id'))
    
    # Recent activity
    recent_scans = Scan.objects.order_by('-created_at')[:5].values(
        'id', 'target', 'status', 'created_at', 'user__email'
    )
    
    return Response({
        'users': {
            'total': total_users,
            'active': active_users,
            'new_this_month': new_users_this_month,
            'inactive': total_users - active_users,
        },
        'scans': {
            'total': total_scans,
            'this_month': scans_this_month,
            'by_status': {item['status']: item['count'] for item in scans_by_status},
        },
        'subscriptions': {
            'active': active_subscriptions,
            'by_plan': {item['plan__name']: item['count'] for item in subscriptions_by_plan},
        },
        'recent_activity': {
            'recent_scans': list(recent_scans),
        },
        'timestamp': now.isoformat(),
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_users_list(request):
    """
    List all users with filtering and search capabilities.
    
    Query parameters:
        - search: Search by email
        - is_active: Filter by active status (true/false)
        - has_subscription: Filter users with active subscriptions
    """
    queryset = User.objects.all()
    
    # Search filter
    search = request.query_params.get('search', '')
    if search:
        queryset = queryset.filter(Q(email__icontains=search))
    
    # Active filter
    is_active = request.query_params.get('is_active', None)
    if is_active is not None:
        queryset = queryset.filter(is_active=is_active.lower() == 'true')
    
    # Subscription filter
    has_subscription = request.query_params.get('has_subscription', None)
    if has_subscription is not None:
        if has_subscription.lower() == 'true':
            queryset = queryset.filter(subscription__status='active').distinct()
        else:
            queryset = queryset.exclude(subscription__status='active').distinct()
    
    # Annotate with scan count
    queryset = queryset.annotate(scan_count=Count('scans'))
    
    users_data = queryset.values(
        'id', 'email', 'is_active', 'is_staff', 
        'date_joined', 'last_login', 'scan_count'
    ).order_by('-date_joined')
    
    return Response({
        'count': queryset.count(),
        'results': list(users_data),
    })


@api_view(['POST'])
@permission_classes([IsAdminUser])
def admin_user_activate(request, user_id):
    """
    Activate a user account.
    """
    try:
        user = User.objects.get(id=user_id)
        user.is_active = True
        user.save()
        logger.info(f"Admin {request.user.email} activated user {user.email}")
        return Response({
            'message': f'User {user.email} activated successfully',
            'user_id': user.id,
            'is_active': user.is_active,
        })
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([IsAdminUser])
def admin_user_deactivate(request, user_id):
    """
    Deactivate a user account.
    Prevents login but preserves data.
    """
    try:
        user = User.objects.get(id=user_id)
        
        # Prevent self-deactivation
        if user.id == request.user.id:
            return Response(
                {'error': 'Cannot deactivate your own account'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.is_active = False
        user.save()
        logger.info(f"Admin {request.user.email} deactivated user {user.email}")
        
        return Response({
            'message': f'User {user.email} deactivated successfully',
            'user_id': user.id,
            'is_active': user.is_active,
        })
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_scans_list(request):
    """
    List all scans across all users.
    
    Query parameters:
        - status: Filter by scan status
        - user_id: Filter by user
        - date_from: Filter scans created after this date (ISO format)
        - date_to: Filter scans created before this date (ISO format)
    """
    queryset = Scan.objects.select_related('user').all()
    
    # Status filter
    scan_status = request.query_params.get('status', '')
    if scan_status:
        queryset = queryset.filter(status=scan_status)
    
    # User filter
    user_id = request.query_params.get('user_id', '')
    if user_id:
        queryset = queryset.filter(user_id=user_id)
    
    # Date range filters
    date_from = request.query_params.get('date_from', '')
    if date_from:
        queryset = queryset.filter(created_at__gte=date_from)
    
    date_to = request.query_params.get('date_to', '')
    if date_to:
        queryset = queryset.filter(created_at__lte=date_to)
    
    scans_data = queryset.values(
        'id', 'target', 'status', 'created_at', 'updated_at',
        'user__email', 'user__id', 'scan_type'
    ).order_by('-created_at')[:100]  # Limit to 100 for performance
    
    return Response({
        'count': queryset.count(),
        'results': list(scans_data),
    })


@api_view(['POST'])
@permission_classes([IsAdminUser])
def admin_database_backup(request):
    """
    Create a database backup (mock implementation for SQLite).
    In production, this should trigger actual backup logic.
    """
    import os
    import shutil
    from pathlib import Path
    
    try:
        # Mock backup for SQLite
        db_path = Path('bugbounty_arsenal.db')
        if db_path.exists():
            backup_dir = Path('backups')
            backup_dir.mkdir(exist_ok=True)
            
            timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
            backup_path = backup_dir / f'db_backup_{timestamp}.db'
            
            shutil.copy2(db_path, backup_path)
            
            logger.info(f"Database backup created by {request.user.email}: {backup_path}")
            
            return Response({
                'message': 'Database backup created successfully',
                'backup_file': str(backup_path),
                'timestamp': timestamp,
            })
        else:
            return Response(
                {'error': 'Database file not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    except Exception as e:
        logger.error(f"Database backup failed: {str(e)}")
        return Response(
            {'error': f'Backup failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAdminUser])
def admin_database_restore(request):
    """
    Restore database from backup (mock implementation).
    Requires backup_file parameter.
    """
    backup_file = request.data.get('backup_file', '')
    
    if not backup_file:
        return Response(
            {'error': 'backup_file parameter is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    from pathlib import Path
    backup_path = Path(backup_file)
    
    if not backup_path.exists():
        return Response(
            {'error': 'Backup file not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # In production, this would perform actual restoration
    logger.warning(f"Database restore requested by {request.user.email}: {backup_file}")
    
    return Response({
        'message': 'Database restore would be performed in production',
        'backup_file': backup_file,
        'note': 'This is a mock response. Real restore requires downtime.',
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_system_health(request):
    """
    Check system health and component status.
    """
    import psutil
    from django.db import connection
    
    # Database check
    db_status = 'healthy'
    try:
        connection.ensure_connection()
    except Exception as e:
        db_status = f'unhealthy: {str(e)}'
    
    # Celery check
    celery_status = 'unknown'
    try:
        from config.celery import app as celery_app
        inspect = celery_app.control.inspect()
        stats = inspect.stats()
        if stats:
            celery_status = f'healthy ({len(stats)} workers)'
        else:
            celery_status = 'no workers available'
    except Exception as e:
        celery_status = f'error: {str(e)}'
    
    # System metrics
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return Response({
        'status': 'healthy',
        'components': {
            'database': db_status,
            'celery': celery_status,
        },
        'system': {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_available_gb': round(memory.available / (1024**3), 2),
            'disk_percent': disk.percent,
            'disk_free_gb': round(disk.free / (1024**3), 2),
        },
        'timestamp': timezone.now().isoformat(),
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_celery_status(request):
    """
    Get detailed Celery worker and task status.
    """
    try:
        from config.celery import app as celery_app
        inspect = celery_app.control.inspect()
        
        # Get worker stats
        stats = inspect.stats()
        active_tasks = inspect.active()
        scheduled_tasks = inspect.scheduled()
        reserved_tasks = inspect.reserved()
        
        return Response({
            'workers': stats or {},
            'active_tasks': active_tasks or {},
            'scheduled_tasks': scheduled_tasks or {},
            'reserved_tasks': reserved_tasks or {},
            'timestamp': timezone.now().isoformat(),
        })
    except Exception as e:
        logger.error(f"Failed to get Celery status: {str(e)}")
        return Response(
            {'error': f'Celery inspection failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAdminUser])
def admin_clear_cache(request):
    """
    Clear application cache.
    """
    try:
        from django.core.cache import cache
        cache.clear()
        logger.info(f"Cache cleared by admin {request.user.email}")
        
        return Response({
            'message': 'Cache cleared successfully',
            'timestamp': timezone.now().isoformat(),
        })
    except Exception as e:
        logger.error(f"Failed to clear cache: {str(e)}")
        return Response(
            {'error': f'Cache clear failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

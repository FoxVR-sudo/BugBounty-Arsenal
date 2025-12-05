"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from users.views import UserViewSet
from users.auth_views import login_view, signup_view, token_refresh_view
from users.admin_views import (
    admin_stats, admin_users_list, admin_user_activate, admin_user_deactivate,
    admin_scans_list, admin_database_backup, admin_database_restore,
    admin_system_health, admin_celery_status, admin_clear_cache
)
from scans.views import (
    ScanViewSet, AuditLogViewSet, ApiKeyViewSet,
    scan_status_view, scan_start_view, scan_stop_view, validate_scope_view
)
from subscriptions.views import PlanViewSet, SubscriptionViewSet
from subscriptions.billing_views import (
    create_checkout_session, billing_portal, buy_extra_scans, change_tier
)

# DRF Router
router = routers.DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'scans', ScanViewSet, basename='scan')
router.register(r'audit-logs', AuditLogViewSet, basename='auditlog')
router.register(r'api-keys', ApiKeyViewSet, basename='apikey')
router.register(r'plans', PlanViewSet, basename='plan')
router.register(r'subscriptions', SubscriptionViewSet, basename='subscription')

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Web interface (templates)
    path('', include('web.urls')),
    
    # Authentication endpoints (must be before api/ include)
    path('api/auth/login/', login_view, name='auth-login'),
    path('api/auth/signup/', signup_view, name='auth-signup'),
    path('api/auth/refresh/', token_refresh_view, name='auth-refresh'),
    
    # Scan endpoints (custom actions - must be before router)
    path('api/scans/status/', scan_status_view, name='scan-status'),
    path('api/scans/start/', scan_start_view, name='scan-start'),
    path('api/scans/stop/<str:scan_id>/', scan_stop_view, name='scan-stop'),
    path('api/scans/validate-scope/', validate_scope_view, name='validate-scope'),
    
    # Billing endpoints
    path('api/billing/checkout/', create_checkout_session, name='billing-checkout'),
    path('api/billing/portal/', billing_portal, name='billing-portal'),
    path('api/billing/buy-scans/', buy_extra_scans, name='buy-extra-scans'),
    path('api/subscriptions/change-tier/', change_tier, name='change-tier'),
    
    # Admin endpoints (requires admin/staff permissions)
    path('api/admin/stats/', admin_stats, name='admin-stats'),
    path('api/admin/users/', admin_users_list, name='admin-users-list'),
    path('api/admin/users/<str:user_id>/activate/', admin_user_activate, name='admin-user-activate'),
    path('api/admin/users/<str:user_id>/deactivate/', admin_user_deactivate, name='admin-user-deactivate'),
    path('api/admin/scans/', admin_scans_list, name='admin-scans-list'),
    path('api/admin/database/backup/', admin_database_backup, name='admin-database-backup'),
    path('api/admin/database/restore/', admin_database_restore, name='admin-database-restore'),
    path('api/admin/system-health/', admin_system_health, name='admin-system-health'),
    path('api/admin/celery-status/', admin_celery_status, name='admin-celery-status'),
    path('api/admin/clear-cache/', admin_clear_cache, name='admin-clear-cache'),
    
    # API endpoints (router - more general patterns)
    path('api/', include((router.urls, 'api'), namespace='api')),
    
    # JWT Authentication
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    
    # Browsable API login/logout
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]

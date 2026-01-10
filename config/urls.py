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
from django.views.generic import RedirectView
from django.http import JsonResponse
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
from users.auth_views import login_view, signup_view, signup_enterprise_view, token_refresh_view
from users.email_views import (
    request_email_verification, verify_email,
    request_password_reset, reset_password
)
from users.landing_views import (
    landing_page, dashboard_page, login_page, signup_page, pricing_page,
    docs_page, api_reference_page, about_page, blog_page, careers_page,
    contact_page, privacy_page, terms_page, security_page, compliance_page
)
from users.api_views import (
    send_phone_verification, verify_phone_code, resend_phone_verification,
    verify_company, search_company, get_supported_countries, get_current_user
)
from users.admin_views import (
    admin_stats, admin_users_list, admin_user_activate, admin_user_deactivate,
    admin_scans_list, admin_database_backup, admin_database_restore,
    admin_system_health, admin_celery_status, admin_clear_cache
)
from scans.views import (
    ScanViewSet, AuditLogViewSet, ApiKeyViewSet,
    scan_status_view, scan_start_view, scan_stop_view, validate_scope_view
)
from scans.export_views import export_pdf_view, export_json_view, export_csv_view
from scans.category_views import (
    ScanCategoryViewSet, start_category_scan, get_detector_statistics
)
from detectors.views import DetectorCategoryViewSet
from subscriptions.views import PlanViewSet, SubscriptionViewSet
from subscriptions.billing_views import (
    create_checkout_session, billing_portal, buy_extra_scans, change_tier
)
from subscriptions.api_views import (
    get_plans, get_current_subscription, cancel_subscription, 
    change_plan, reactivate_subscription, sync_subscription, upgrade_to_enterprise
)

# DRF Router
router = routers.DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'scans', ScanViewSet, basename='scan')
router.register(r'scan-categories', ScanCategoryViewSet, basename='scan-category')
router.register(r'detector-categories', DetectorCategoryViewSet, basename='detector-category')
router.register(r'audit-logs', AuditLogViewSet, basename='auditlog')
router.register(r'api-keys', ApiKeyViewSet, basename='apikey')
# router.register(r'plans', PlanViewSet, basename='plan')  # Using custom endpoint instead
router.register(r'subscriptions', SubscriptionViewSet, basename='subscription')

urlpatterns = [
    # Landing page
    path('', landing_page, name='landing'),
    
    # Auth pages (HTML forms)
    path('login/', login_page, name='login-page'),
    path('signup/', signup_page, name='signup-page'),
    path('pricing/', pricing_page, name='pricing-page'),
    
    # Dashboard (requires authentication)
    path('dashboard/', dashboard_page, name='dashboard'),
    
    # Footer pages
    path('docs/', docs_page, name='docs'),
    path('api/', api_reference_page, name='api-reference'),
    path('about/', about_page, name='about'),
    path('blog/', blog_page, name='blog'),
    path('careers/', careers_page, name='careers'),
    path('contact/', contact_page, name='contact'),
    path('privacy/', privacy_page, name='privacy'),
    path('terms/', terms_page, name='terms'),
    path('security/', security_page, name='security'),
    path('compliance/', compliance_page, name='compliance'),
    
    path('admin/', admin.site.urls),
    
    # Favicon redirect
    path('favicon.ico', RedirectView.as_view(url='/static/favicon.svg', permanent=True)),
    
    # Authentication endpoints (must be before api/ include)
    path('api/auth/login/', login_view, name='auth-login'),
    path('api/auth/signup/', signup_view, name='auth-signup'),
    path('api/auth/signup-enterprise/', signup_enterprise_view, name='auth-signup-enterprise'),
    path('api/auth/refresh/', token_refresh_view, name='auth-refresh'),
    path('api/auth/me/', get_current_user, name='current-user'),
    
    # Email verification & password reset
    path('api/auth/request-verification/', request_email_verification, name='request-verification'),
    path('api/auth/verify-email/', verify_email, name='verify-email'),
    path('api/auth/request-reset/', request_password_reset, name='request-password-reset'),
    path('api/auth/reset-password/', reset_password, name='reset-password'),
    
    # NEW v3.0: Phone & Company Verification endpoints
    path('api/users/verify-phone/send/', send_phone_verification, name='send-phone-verification'),
    path('api/users/verify-phone/confirm/', verify_phone_code, name='verify-phone-code'),
    path('api/users/verify-phone/resend/', resend_phone_verification, name='resend-phone-verification'),
    path('api/users/verify-company/', verify_company, name='verify-company'),
    path('api/users/search-company/', search_company, name='search-company'),
    path('api/users/supported-countries/', get_supported_countries, name='supported-countries'),
    
    # Scan endpoints (custom actions - must be before router)
    path('api/scans/status/', scan_status_view, name='scan-status'),
    path('api/scans/start/', scan_start_view, name='scan-start'),
    path('api/scans/stop/<str:scan_id>/', scan_stop_view, name='scan-stop'),
    path('api/scans/validate-scope/', validate_scope_view, name='validate-scope'),
    path('api/scans/<int:scan_id>/pdf/', export_pdf_view, name='scan-export-pdf'),
    path('api/scans/<int:scan_id>/json/', export_json_view, name='scan-export-json'),
    path('api/scans/<int:scan_id>/csv/', export_csv_view, name='scan-export-csv'),
    
    # NEW v3.0: Category-based scan endpoints
    path('api/scans/start-category-scan/', start_category_scan, name='start-category-scan'),
    path('api/detectors/statistics/', get_detector_statistics, name='detector-statistics'),
    
    # NEW v3.1: Plan and subscription endpoints
    path('api/plans/', get_plans, name='plans-list'),
    path('api/subscriptions/current/', get_current_subscription, name='subscription-current'),
    path('api/subscriptions/cancel/', cancel_subscription, name='subscription-cancel'),
    path('api/subscriptions/change-plan/', change_plan, name='subscription-change-plan'),
    path('api/subscriptions/reactivate/', reactivate_subscription, name='subscription-reactivate'),
    path('api/subscriptions/sync/', sync_subscription, name='subscription-sync'),
    path('api/subscriptions/upgrade-to-enterprise/', upgrade_to_enterprise, name='subscription-upgrade-enterprise'),
    
    # NEW v3.0: Placeholder endpoints for Pro features (to prevent 404 errors)
    path('api/teams/', lambda request: JsonResponse({'results': [], 'message': 'Teams feature available in Pro plan'}), name='teams-list'),
    path('api/integrations/', lambda request: JsonResponse({'results': [], 'message': 'Integrations feature available in Pro plan'}), name='integrations-list'),
    
    # Billing endpoints
    path('api/billing/checkout/', create_checkout_session, name='billing-checkout'),
    path('api/billing/portal/', billing_portal, name='billing-portal'),
    path('api/billing/buy-scans/', buy_extra_scans, name='buy-extra-scans'),
    path('api/subscriptions/change-tier/', change_tier, name='change-tier'),
    
    # Stripe webhook
    path('api/webhooks/stripe/', include('subscriptions.urls')),
    
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

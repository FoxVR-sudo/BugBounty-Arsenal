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
from scans.views import ScanViewSet, AuditLogViewSet, ApiKeyViewSet
from subscriptions.views import PlanViewSet, SubscriptionViewSet

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
    
    # API endpoints
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

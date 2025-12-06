"""
URL patterns for web interface views
"""

from django.urls import path
from . import views

urlpatterns = [
    # Landing page
    path('', views.landing, name='landing'),
    
    # Authentication
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    
    # Dashboard
    path('dashboard/', views.dashboard, name='dashboard'),
    path('dashboard/results/', views.results_page, name='results-page'),
    path('dashboard/api-scan/', views.api_scan_page, name='api-scan'),
    path('dashboard/vulnerability-scan/', views.vulnerability_scan_page, name='vulnerability-scan'),
    path('dashboard/mobile-scan/', views.mobile_scan_page, name='mobile-scan'),
    path('dashboard/passive-scan/', views.passive_scan_page, name='passive-scan'),
    path('dashboard/custom-scan/', views.custom_scan_page, name='custom-scan'),
    
    # Admin panel
    path('admin-panel/', views.admin_panel, name='admin-panel'),
    
    # Health check
    path('health/', views.health_check, name='health-check'),
]

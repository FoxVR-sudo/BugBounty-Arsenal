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
    path('pricing/', views.pricing_page, name='pricing'),
    
    # Scanner pages - 5 comprehensive scanners
    path('scan/reconnaissance/', views.reconnaissance_scan, name='reconnaissance-scan'),
    path('scan/web/', views.web_scan, name='web-scan'),
    path('scan/api/', views.api_scan, name='api-scan'),
    path('scan/mobile/', views.mobile_scan, name='mobile-scan'),
    path('scan/comprehensive/', views.comprehensive_scan, name='comprehensive-scan'),
    
    # Old dashboard pages (keep for backward compatibility)
    path('dashboard/results/', views.results_page, name='results-page'),
    path('dashboard/web-scan/', views.web_scan_page, name='web-scan'),
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

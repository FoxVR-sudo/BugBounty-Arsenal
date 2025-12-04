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
    
    # Dashboard
    path('dashboard/', views.dashboard, name='dashboard'),
    
    # Admin panel
    path('admin-panel/', views.admin_panel, name='admin-panel'),
    
    # Health check
    path('health/', views.health_check, name='health-check'),
]

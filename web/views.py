"""
Web interface views for BugBounty Arsenal
Renders HTML templates for landing page, authentication, dashboard, and admin panel
"""

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import datetime

from scans.models import Scan, AuditLog
from subscriptions.models import Plan, Subscription
from users.models import User


def landing(request):
    """
    Landing page with pricing and features
    """
    context = {
        'plans': Plan.objects.all().order_by('price'),
    }
    return render(request, 'landing.html', context)


def login_view(request):
    """
    Login page (authentication handled by DRF API)
    """
    # If already authenticated, redirect to dashboard
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    return render(request, 'login.html')


def signup_view(request):
    """
    Signup page (registration handled by DRF API)
    """
    # If already authenticated, redirect to dashboard
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    return render(request, 'signup.html')


@login_required
def dashboard(request):
    """
    User dashboard with scan management
    """
    user = request.user
    
    # Get user's subscription/tier
    try:
        subscription = user.subscription
        tier = subscription.plan.name.lower()  # 'free', 'pro', 'enterprise'
        tier_info = {
            'name': subscription.plan.name,
            'concurrent_scans': 1 if tier == 'free' else (3 if tier == 'pro' else 10),
            'max_urls': 10 if tier == 'free' else (100 if tier == 'pro' else 1000),
            'detectors': '15 detectors' if tier == 'free' else ('30+ detectors' if tier == 'pro' else 'All detectors'),
        }
    except:
        tier = 'free'
        tier_info = {
            'name': 'FREE',
            'concurrent_scans': 1,
            'max_urls': 10,
            'detectors': '15 detectors',
        }
    
    # Get user's scans
    scans = Scan.objects.filter(user=user).order_by('-created_at')
    active_scans = scans.filter(status__in=['queued', 'running'])
    completed_scans = scans.filter(status='completed')
    
    # Scan statistics (for daily limits)
    today = timezone.now().date()
    daily_scans = scans.filter(created_at__date=today).count()
    daily_limit = 5 if tier == 'free' else (20 if tier == 'pro' else 999999)
    
    # Calculate percentage for progress bar
    daily_percentage = (daily_scans / daily_limit * 100) if daily_limit > 0 else 0
    
    scan_stats = {
        'daily_used': daily_scans,
        'daily_limit': daily_limit,
        'daily_percentage': daily_percentage,
        'extra_scans_available': 0,  # TODO: Implement extra scans feature
    }
    
    # Tier limits
    is_pro_or_enterprise = tier in ['pro', 'enterprise']
    
    # TODO: Get actual allowed detectors from registry and format them
    allowed_detectors_formatted = []  # Format: ["SQL Injection", "XSS", "CSRF", ...]
    
    tier_limits = {
        'max_concurrent_scans': tier_info['concurrent_scans'],
        'enable_recon_pipeline': is_pro_or_enterprise,
        'allowed_detectors': allowed_detectors_formatted,
        'is_pro_or_enterprise': is_pro_or_enterprise,
    }
    
    # Get recent reports (from completed scans with report_path)
    reports = []
    for scan in completed_scans.filter(report_path__isnull=False)[:10]:
        reports.append({
            'name': f"{scan.target} - {scan.created_at.strftime('%Y-%m-%d %H:%M')}",
            'rel_path': scan.report_path,
            'created': scan.completed_at or scan.created_at,
        })
    
    context = {
        'user': user,
        'tier': tier,
        'tier_info': tier_info,
        'tier_limits': tier_limits,
        'scan_stats': scan_stats,
        'active_scans': active_scans,
        'scans': scans[:20],  # Last 20 scans
        'reports': reports,
        'now': datetime.now().timestamp(),
        'is_superuser': user.is_superuser,
    }
    
    return render(request, 'dashboard.html', context)


def is_superuser(user):
    """Check if user is superuser"""
    return user.is_superuser


@login_required
@user_passes_test(is_superuser)
def admin_panel(request):
    """
    Admin panel for managing users, subscriptions, and viewing database
    Only accessible by superusers
    """
    # Get summary statistics
    total_users = User.objects.count()
    active_subscriptions = Subscription.objects.filter(status='active').count()
    total_scans = Scan.objects.count()
    
    # Calculate monthly revenue (PRO plan subscriptions)
    try:
        pro_plan = Plan.objects.get(name='PRO')
        monthly_revenue = active_subscriptions * float(pro_plan.price)
    except:
        monthly_revenue = 0
    
    stats = {
        'total_users': total_users,
        'active_subscriptions': active_subscriptions,
        'total_scans': total_scans,
        'monthly_revenue': f"{monthly_revenue:.2f}",
    }
    
    context = {
        'stats': stats,
        'admin_email': request.user.email,
    }
    
    return render(request, 'admin.html', context)


@require_http_methods(["GET"])
def health_check(request):
    """
    Health check endpoint for monitoring
    """
    from django.http import JsonResponse
    return JsonResponse({
        'status': 'healthy',
        'timestamp': timezone.now().isoformat(),
    })


@login_required
@require_http_methods(["GET"])
def results_page(request):
    """
    Scan results page with filtering and export options
    """
    user = request.user
    
    # Get user's subscription/tier for storage limits
    try:
        subscription = user.subscription
        tier = subscription.plan.name.lower()
        
        # Storage limits by tier (in bytes)
        storage_limits = {
            'free': 100 * 1024 * 1024,      # 100 MB
            'basic': 500 * 1024 * 1024,     # 500 MB
            'pro': 2 * 1024 * 1024 * 1024,  # 2 GB
            'enterprise': 10 * 1024 * 1024 * 1024,  # 10 GB
        }
        
        storage_limit = storage_limits.get(tier, storage_limits['free'])
    except:
        tier = 'free'
        storage_limit = 100 * 1024 * 1024
    
    # Calculate total storage used
    user_scans = Scan.objects.filter(user=user)
    total_storage_used = sum(scan.report_size_bytes for scan in user_scans)
    
    storage_info = {
        'used': total_storage_used,
        'limit': storage_limit,
        'used_mb': total_storage_used / (1024 * 1024),
        'limit_mb': storage_limit / (1024 * 1024),
        'percentage': (total_storage_used / storage_limit * 100) if storage_limit > 0 else 0,
    }
    
    context = {
        'storage_info': storage_info,
        'tier': tier.upper(),
    }
    
    return render(request, 'results.html', context)

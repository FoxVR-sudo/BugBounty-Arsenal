"""
Web interface views for BugBounty Arsenal
Renders HTML templates for landing page, authentication, dashboard, and admin panel
"""

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import logout as auth_logout
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import datetime

from scans.models import Scan, AuditLog
from subscriptions.models import Plan, Subscription
from users.models import User


def landing(request):
    """
    Landing page with pricing and features - shows all 4 plans from database
    """
    # Get all active plans ordered by price
    plans = Plan.objects.filter(is_active=True).order_by('price')
    
    context = {
        'plans': plans,
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


def logout_view(request):
    """
    Logout view - clears session and redirects to login
    """
    auth_logout(request)
    return redirect('login')


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
    
    # Get current date/time for filtering
    today = timezone.now().date()
    current_month = timezone.now().month
    current_year = timezone.now().year
    
    # Get user's scans
    all_scans_queryset = Scan.objects.filter(user=user).order_by('-created_at')
    
    # Get all monthly scans (for results table)
    monthly_scans = all_scans_queryset.filter(
        created_at__month=current_month,
        created_at__year=current_year
    )
    
    # Format scans for template with severity counts
    all_scans = []
    for scan in monthly_scans:
        # Parse vulnerabilities from severity_counts JSON field
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        # Try to get severity counts from the severity_counts field
        if hasattr(scan, 'severity_counts') and scan.severity_counts:
            try:
                counts = scan.severity_counts
                if isinstance(counts, dict):
                    critical_count = counts.get('critical', 0)
                    high_count = counts.get('high', 0)
                    medium_count = counts.get('medium', 0)
                    low_count = counts.get('low', 0)
            except:
                pass
        
        # Calculate duration
        duration = "N/A"
        if scan.completed_at and scan.created_at:
            delta = scan.completed_at - scan.created_at
            minutes = int(delta.total_seconds() / 60)
            seconds = int(delta.total_seconds() % 60)
            if minutes > 0:
                duration = f"{minutes}m {seconds}s"
            else:
                duration = f"{seconds}s"
        
        all_scans.append({
            'id': scan.id,
            'target': scan.target,
            'scan_type': scan.scan_type or 'web',
            'status': scan.status,
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count,
            'started_at': scan.created_at,
            'completed_at': scan.completed_at,
            'duration': duration,
        })
    
    # Scan statistics
    scans_today = all_scans_queryset.filter(created_at__date=today).count()
    scans_month = monthly_scans.count()
    
    # Daily/monthly limits
    daily_limit = 5 if tier == 'free' else (20 if tier == 'pro' else 999999)
    monthly_limit = 100 if tier == 'free' else (500 if tier == 'pro' else 999999)
    
    remaining_today = max(0, daily_limit - scans_today)
    remaining_month = max(0, monthly_limit - scans_month)
    
    # Storage calculation
    total_storage_bytes = sum(scan.report_size_bytes for scan in all_scans_queryset if scan.report_size_bytes)
    storage_used_mb = round(total_storage_bytes / (1024 * 1024), 2)
    
    storage_limits_mb = {
        'free': 100,
        'basic': 500,
        'pro': 2048,
        'enterprise': 10240,
    }
    storage_limit_mb = storage_limits_mb.get(tier, 100)
    storage_remaining_mb = max(0, storage_limit_mb - storage_used_mb)
    
    # Active scans for legacy template compatibility
    active_scans = all_scans_queryset.filter(status__in=['queued', 'running'])
    completed_scans = all_scans_queryset.filter(status='completed')
    
    # Calculate percentage for progress bar
    daily_percentage = (scans_today / daily_limit * 100) if daily_limit > 0 else 0
    
    scan_stats = {
        'daily_used': scans_today,
        'daily_limit': daily_limit,
        'daily_percentage': daily_percentage,
        'extra_scans_available': 0,
    }
    
    # Tier limits
    is_pro_or_enterprise = tier in ['pro', 'enterprise']
    allowed_detectors_formatted = []
    
    tier_limits = {
        'max_concurrent_scans': tier_info['concurrent_scans'],
        'enable_recon_pipeline': is_pro_or_enterprise,
        'allowed_detectors': allowed_detectors_formatted,
        'is_pro_or_enterprise': is_pro_or_enterprise,
    }
    
    # Get recent reports
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
        'scans': all_scans_queryset[:20],  # Last 20 scans (legacy)
        'reports': reports,
        'now': datetime.now().timestamp(),
        'is_superuser': user.is_superuser,
        # NEW: Data for dashboard_new.html template
        'all_scans': all_scans,  # All monthly scans with severity counts
        'total_scans': scans_month,  # Total scans this month
        'scans_today': scans_today,
        'daily_limit': daily_limit,
        'remaining_today': remaining_today,
        'scans_month': scans_month,
        'monthly_limit': monthly_limit,
        'remaining_month': remaining_month,
        'storage_used_mb': storage_used_mb,
        'storage_remaining_mb': storage_remaining_mb,
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


@login_required
@require_http_methods(["GET"])
def web_scan_page(request):
    """
    Web Security Scan page with all detectors
    """
    return render(request, 'web_scan.html')


@login_required
@require_http_methods(["GET"])
def api_scan_page(request):
    """
    API Security Scan page with API-specific settings
    """
    return render(request, 'api_scan.html')


@login_required
@require_http_methods(["GET"])
def vulnerability_scan_page(request):
    """
    Vulnerability Assessment page with CVE scanning
    """
    return render(request, 'vulnerability_scan.html')


@login_required
@require_http_methods(["GET"])
def mobile_scan_page(request):
    """
    Mobile App Security page with APK/IPA upload
    """
    return render(request, 'mobile_scan.html')


@login_required
@require_http_methods(["GET"])
def custom_scan_page(request):
    """
    Custom Scan page with manual detector selection
    """
    return render(request, 'custom_scan.html')


@login_required
@require_http_methods(["GET"])
def passive_scan_page(request):
    """
    Passive Testing page with passive detector selection
    """
    return render(request, 'passive_scan.html')


# Scanner pages - 5 main categories
@login_required
def reconnaissance_scan(request):
    """Reconnaissance Scanner - subdomain, directory, secrets, CVE"""
    context = {
        'scanner_name': 'Reconnaissance Scanner',
        'scanner_icon': '🔍',
        'scanner_description': 'Discover subdomains, directories, secrets, and known vulnerabilities'
    }
    return render(request, 'scans/reconnaissance.html', context)


@login_required
def web_scan(request):
    """Web Application Scanner - XSS, SQLi, CSRF, LFI, XXE, SSTI, etc"""
    context = {
        'scanner_name': 'Web Application Scanner',
        'scanner_icon': '🌐',
        'scanner_description': 'Comprehensive web vulnerability testing with 15+ detectors'
    }
    return render(request, 'scans/web.html', context)


@login_required
def api_scan(request):
    """API Security Scanner - JWT, GraphQL, OAuth, NoSQL, Rate Limiting"""
    context = {
        'scanner_name': 'API Security Scanner',
        'scanner_icon': '🔌',
        'scanner_description': 'API security testing including JWT, GraphQL, and OAuth'
    }
    return render(request, 'scans/api.html', context)


@login_required
def mobile_scan(request):
    """Mobile App Scanner - Android/iOS security testing"""
    context = {
        'scanner_name': 'Mobile App Scanner',
        'scanner_icon': '📱',
        'scanner_description': 'Mobile application security analysis for Android and iOS'
    }
    return render(request, 'scans/mobile.html', context)


@login_required
def comprehensive_scan(request):
    """Comprehensive Scanner - All 40+ detectors"""
    context = {
        'scanner_name': 'Comprehensive Security Scan',
        'scanner_icon': '🛡️',
        'scanner_description': 'Run all 40+ security detectors for complete coverage'
    }
    return render(request, 'scans/comprehensive.html', context)


@login_required
def pricing_page(request):
    """Pricing page with plan comparison"""
    plans = Plan.objects.filter(is_active=True).order_by('price')
    return render(request, 'pricing.html', {'plans': plans})


@login_required
def xss_scan(request):
    """XSS Scanner page"""
    context = {
        'scanner_name': 'XSS Scanner',
        'scanner_icon': '🔍',
        'scanner_description': 'Cross-Site Scripting detection with advanced payloads'
    }
    return render(request, 'scans/xss.html', context)


@login_required
def sqli_scan(request):
    """SQL Injection Scanner page"""
    context = {
        'scanner_name': 'SQL Injection Scanner',
        'scanner_icon': '💉',
        'scanner_description': 'Detect SQL injection vulnerabilities with multiple techniques'
    }
    return render(request, 'scans/sqli.html', context)


@login_required
def ssrf_scan(request):
    """SSRF Scanner page"""
    context = {
        'scanner_name': 'SSRF Scanner',
        'scanner_icon': '🌐',
        'scanner_description': 'Server-Side Request Forgery detection with OOB callbacks'
    }
    return render(request, 'scans/ssrf.html', context)


@login_required
def jwt_scan(request):
    """JWT Analyzer page"""
    context = {
        'scanner_name': 'JWT Analyzer',
        'scanner_icon': '🔐',
        'scanner_description': 'JWT token security and algorithm confusion testing'
    }
    return render(request, 'scans/jwt.html', context)


@login_required
def lfi_scan(request):
    """LFI/RFI Scanner page"""
    context = {
        'scanner_name': 'LFI/RFI Scanner',
        'scanner_icon': '📂',
        'scanner_description': 'Local and remote file inclusion vulnerability detection'
    }
    return render(request, 'scans/lfi.html', context)


@login_required
def idor_scan(request):
    """IDOR Scanner page"""
    context = {
        'scanner_name': 'IDOR Scanner',
        'scanner_icon': '🔑',
        'scanner_description': 'Insecure Direct Object Reference testing with fuzzing'
    }
    return render(request, 'scans/idor.html', context)


@login_required
def cmdi_scan(request):
    """Command Injection Scanner page"""
    context = {
        'scanner_name': 'Command Injection Scanner',
        'scanner_icon': '⚡',
        'scanner_description': 'OS command injection detection with multiple techniques'
    }
    return render(request, 'scans/cmdi.html', context)


@login_required
def csrf_scan(request):
    """CSRF Scanner page"""
    context = {
        'scanner_name': 'CSRF Scanner',
        'scanner_icon': '🔄',
        'scanner_description': 'Cross-Site Request Forgery token validation testing'
    }
    return render(request, 'scans/csrf.html', context)


@login_required
def graphql_scan(request):
    """GraphQL Scanner page"""
    context = {
        'scanner_name': 'GraphQL Scanner',
        'scanner_icon': '🚀',
        'scanner_description': 'GraphQL introspection, injection, and authorization testing'
    }
    return render(request, 'scans/graphql.html', context)


@login_required
def xxe_scan(request):
    """XXE Scanner page"""
    context = {
        'scanner_name': 'XXE Scanner',
        'scanner_icon': '📄',
        'scanner_description': 'XML External Entity injection detection'
    }
    return render(request, 'scans/xxe.html', context)


@login_required
def ssti_scan(request):
    """SSTI Scanner page"""
    context = {
        'scanner_name': 'SSTI Scanner',
        'scanner_icon': '🎭',
        'scanner_description': 'Server-Side Template Injection testing for multiple engines'
    }
    return render(request, 'scans/ssti.html', context)


@login_required
def headers_scan(request):
    """Security Headers Scanner page"""
    context = {
        'scanner_name': 'Security Headers Scanner',
        'scanner_icon': '🛡️',
        'scanner_description': 'HTTP security header analysis and recommendations'
    }
    return render(request, 'scans/headers.html', context)

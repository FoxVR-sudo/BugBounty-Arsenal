"""Landing page views for marketing and public pages"""
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods


@require_http_methods(["GET"])
def landing_page(request):
    """Landing page view - marketing page for unauthenticated users"""
    return render(request, 'landing.html')


@require_http_methods(["GET"])
def login_page(request):
    """Login page view - renders login form"""
    return render(request, 'login.html')


@require_http_methods(["GET"])
def signup_page(request):
    """Signup page view - renders signup form"""
    return render(request, 'signup.html')


@require_http_methods(["GET"])
def pricing_page(request):
    """Pricing page view - renders pricing plans"""
    return render(request, 'pricing.html')


@login_required
@require_http_methods(["GET"])
def dashboard_page(request):
    """Dashboard page view - main app interface for authenticated users"""
    return render(request, 'dashboard.html')

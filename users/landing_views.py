"""Landing page views for marketing and public pages"""
from django.shortcuts import render
from django.views.decorators.http import require_http_methods


@require_http_methods(["GET"])
def landing_page(request):
    """Landing page view - marketing page for unauthenticated users"""
    return render(request, 'landing.html')

from django.db import models
from django.conf import settings


class Plan(models.Model):
    """Subscription plan model"""
    
    name = models.CharField(max_length=50, unique=True)  # FREE, BASIC, PRO, ENTERPRISE
    display_name = models.CharField(max_length=100)
    description = models.TextField(blank=True, help_text='Plan description for landing page')
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00, help_text='Monthly price in USD')
    
    # Scan limits
    scans_per_day = models.IntegerField(default=3, help_text='Daily scan limit (-1 = unlimited)')
    scans_per_month = models.IntegerField(default=100, help_text='Monthly scan limit (-1 = unlimited)')
    concurrent_scans = models.IntegerField(default=1, help_text='Number of concurrent scans allowed')
    max_urls_per_scan = models.IntegerField(default=10, help_text='Maximum URLs per scan')
    
    # Storage limits
    storage_limit_mb = models.IntegerField(default=100, help_text='Storage limit in MB for scan results')
    retention_days = models.IntegerField(default=7, help_text='How many days to keep scan results')
    
    # Detector limits
    max_detectors = models.IntegerField(default=15, help_text='Maximum detectors available (-1 = all)')
    allowed_scan_types = models.JSONField(default=list, help_text='Allowed scan types: web, api, mobile, etc.')
    
    # Features
    features = models.JSONField(default=list, help_text='List of feature names for display')
    
    # Legacy support
    limits = models.JSONField(default=dict, help_text='Legacy limits field (deprecated)')
    
    # Status
    is_active = models.BooleanField(default=True)
    is_popular = models.BooleanField(default=False, help_text='Show "Most Popular" badge')
    order = models.IntegerField(default=0, help_text='Display order on pricing page')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'plans'
        ordering = ['order', 'price']
    
    def __str__(self):
        return self.display_name


class Subscription(models.Model):
    """User subscription model"""
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('cancelled', 'Cancelled'),
        ('expired', 'Expired'),
        ('trialing', 'Trialing'),
    ]
    
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='subscription')
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT, related_name='subscriptions')
    
    # Stripe integration
    stripe_customer_id = models.CharField(max_length=100, blank=True)
    stripe_subscription_id = models.CharField(max_length=100, blank=True)
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    current_period_start = models.DateTimeField(null=True, blank=True)
    current_period_end = models.DateTimeField(null=True, blank=True)
    cancel_at_period_end = models.BooleanField(default=False)
    
    # Usage tracking
    scans_used_today = models.IntegerField(default=0)
    last_scan_reset = models.DateField(auto_now_add=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'subscriptions'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['stripe_customer_id']),
        ]
    
    def __str__(self):
        return f"{self.user.email} - {self.plan.name} ({self.status})"
    
    def reset_daily_usage(self):
        """Reset daily scan usage"""
        from datetime import date
        today = date.today()
        if self.last_scan_reset < today:
            self.scans_used_today = 0
            self.last_scan_reset = today
            self.save()
    
    def can_start_scan(self):
        """Check if user can start a new scan"""
        self.reset_daily_usage()
        limits = self.plan.limits
        max_scans = limits.get('scans_per_day', 5)
        return self.scans_used_today < max_scans or max_scans == -1  # -1 = unlimited
    
    def increment_scan_usage(self):
        """Increment scan counter"""
        self.scans_used_today += 1
        self.save()

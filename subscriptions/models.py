from django.db import models
from django.conf import settings


class Plan(models.Model):
    """Subscription plan model"""
    
    name = models.CharField(max_length=50, unique=True)  # FREE, PRO
    display_name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    # Dynamic limits stored as JSON
    limits = models.JSONField(default=dict)  # {"scans_per_day": 5, "concurrent_scans": 1, ...}
    features = models.JSONField(default=list)  # ["Basic scanning", "Email reports", ...]
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'plans'
        ordering = ['price']
    
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

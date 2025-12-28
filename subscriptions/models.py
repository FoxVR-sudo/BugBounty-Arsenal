from django.db import models
from django.conf import settings


class Plan(models.Model):
    """Subscription plan model - Updated v3.0"""
    
    PLAN_NAMES = [
        ('free', 'Free'),
        ('pro', 'Pro'),
        ('enterprise', 'Enterprise'),
    ]
    
    name = models.CharField(max_length=50, unique=True, choices=PLAN_NAMES)
    display_name = models.CharField(max_length=100)
    description = models.TextField(blank=True, help_text='Plan description for landing page')
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00, help_text='Monthly price in USD')
    
    # NEW v3.0: Scan limits (simplified)
    scans_per_day = models.IntegerField(default=3, help_text='Daily scan limit (-1 = unlimited)')
    scans_per_month = models.IntegerField(default=10, help_text='Monthly scan limit (-1 = unlimited)')
    concurrent_scans = models.IntegerField(default=1, help_text='Number of concurrent scans allowed')
    
    # Storage limits
    storage_limit_mb = models.IntegerField(default=100, help_text='Storage limit in MB for scan results')
    retention_days = models.IntegerField(default=7, help_text='How many days to keep scan results')
    
    # NEW v3.0: Scanner access (NOT detector limits, all plans see all scanners)
    # Access is controlled by scan count, not detector type
    allow_dangerous_tools = models.BooleanField(default=False, help_text='Allow Nuclei, custom payloads (Enterprise only)')
    
    # NEW v3.0: Team collaboration
    allow_teams = models.BooleanField(default=False, help_text='Enable team features (Pro & Enterprise)')
    max_team_members = models.IntegerField(default=0, help_text='Maximum team members (0 = no teams)')
    
    # NEW v3.0: Integrations
    allow_integrations = models.BooleanField(default=False, help_text='Enable third-party integrations (Pro & Enterprise)')
    max_integrations = models.IntegerField(default=0, help_text='Maximum active integrations')
    
    # Features
    features = models.JSONField(default=list, help_text='List of feature names for display')
    
    # Status
    is_active = models.BooleanField(default=True)
    is_popular = models.BooleanField(default=False, help_text='Show "Most Popular" badge')
    order = models.IntegerField(default=0, help_text='Display order on pricing page')
    
    # Stripe product ID
    stripe_price_id = models.CharField(max_length=100, blank=True, null=True, help_text='Stripe Price ID')
    stripe_product_id = models.CharField(max_length=100, blank=True, null=True, help_text='Stripe Product ID')
    
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
    
    # Usage tracking (NEW v3.0: monthly tracking added)
    scans_used_today = models.IntegerField(default=0)
    scans_used_this_month = models.IntegerField(default=0)
    last_scan_reset = models.DateField(auto_now_add=True)
    last_monthly_reset = models.DateField(null=True, blank=True)  # Changed to allow null for migration
    
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
        if self.last_scan_reset is None or self.last_scan_reset < today:
            self.scans_used_today = 0
            self.last_scan_reset = today
            self.save()
    
    def reset_monthly_usage(self):
        """Reset monthly scan usage (NEW v3.0)"""
        from datetime import date
        today = date.today()
        # Reset if it's a new month
        if self.last_monthly_reset is None or self.last_monthly_reset.month != today.month or self.last_monthly_reset.year != today.year:
            self.scans_used_this_month = 0
            self.last_monthly_reset = today
            self.save()
    
    def can_start_scan(self):
        """Check if user can start a new scan (NEW v3.0: checks both daily and monthly)"""
        self.reset_daily_usage()
        self.reset_monthly_usage()
        
        # Check daily limit
        daily_limit = self.plan.scans_per_day
        if daily_limit != -1 and self.scans_used_today >= daily_limit:
            return False, f"Daily limit reached ({daily_limit} scans/day)"
        
        # Check monthly limit
        monthly_limit = self.plan.scans_per_month
        if monthly_limit != -1 and self.scans_used_this_month >= monthly_limit:
            return False, f"Monthly limit reached ({monthly_limit} scans/month)"
        
        return True, "OK"
    
    def increment_scan_usage(self):
        """Increment scan counter (NEW v3.0: both daily and monthly)"""
        self.scans_used_today += 1
        self.scans_used_this_month += 1
        self.save()
    
    def can_use_dangerous_tools(self):
        """Check if user can use Nuclei/payloads (NEW v3.0: Enterprise only)"""
        return self.plan.allow_dangerous_tools
    
    def can_create_team(self):
        """Check if user can create teams (NEW v3.0: Pro & Enterprise)"""
        return self.plan.allow_teams
    
    def can_add_integration(self):
        """Check if user can add integrations (NEW v3.0: Pro & Enterprise)"""
        return self.plan.allow_integrations


class Payment(models.Model):
    """Payment transaction model"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('succeeded', 'Succeeded'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='payments')
    subscription = models.ForeignKey(Subscription, on_delete=models.SET_NULL, null=True, blank=True, related_name='payments')
    
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='usd')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Stripe IDs
    stripe_payment_intent_id = models.CharField(max_length=100, blank=True, null=True)
    stripe_invoice_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Metadata
    description = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'payments'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['stripe_payment_intent_id']),
        ]
    
    def __str__(self):
        return f"{self.user.email} - ${self.amount} ({self.status})"

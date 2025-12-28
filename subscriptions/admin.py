from django.contrib import admin
from django.utils.html import format_html
from .models import Plan, Subscription


@admin.register(Plan)
class PlanAdmin(admin.ModelAdmin):
    """Plan admin with full control over all settings - Updated v3.0"""
    
    list_display = ['display_name', 'name', 'price_display', 'scans_per_day', 'scans_per_month', 'allow_dangerous_tools', 'allow_teams', 'allow_integrations', 'is_active', 'is_popular', 'order']
    list_filter = ['is_active', 'is_popular', 'allow_dangerous_tools', 'allow_teams', 'allow_integrations']
    search_fields = ['name', 'display_name', 'description']
    list_editable = ['is_active', 'is_popular', 'order']
    ordering = ['order', 'price']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'display_name', 'description', 'price', 'is_active', 'is_popular', 'order')
        }),
        ('Scan Limits (v3.0)', {
            'fields': ('scans_per_day', 'scans_per_month', 'concurrent_scans'),
            'description': 'FREE: 3/day 10/month | PRO: 100/day 500/month | ENTERPRISE: -1 (unlimited)'
        }),
        ('Storage & Retention', {
            'fields': ('storage_limit_mb', 'retention_days')
        }),
        ('NEW v3.0: Access Control', {
            'fields': ('allow_dangerous_tools', 'allow_teams', 'max_team_members', 'allow_integrations', 'max_integrations'),
            'description': 'Dangerous tools (Nuclei/payloads): Enterprise only | Teams: Pro & Enterprise | Integrations: Pro & Enterprise'
        }),
        ('Features List', {
            'fields': ('features',),
            'description': 'List of features to display on pricing page'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ['created_at', 'updated_at']
    
    def price_display(self, obj):
        if obj.price == 0:
            return format_html('<span style="color: green; font-weight: bold;">{}</span>', 'FREE')
        return format_html('<span style="font-weight: bold;">${}/mo</span>', obj.price)
    price_display.short_description = 'Price'


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    """Subscription admin with usage tracking"""
    
    list_display = ['user_email', 'plan_name', 'status', 'usage_display', 'storage_info', 'created_at']
    list_filter = ['status', 'plan__name', 'created_at']
    search_fields = ['user__email', 'stripe_customer_id', 'stripe_subscription_id']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    fieldsets = (
        ('User & Plan', {
            'fields': ('user', 'plan', 'status')
        }),
        ('Stripe Integration', {
            'fields': ('stripe_customer_id', 'stripe_subscription_id'),
            'classes': ('collapse',)
        }),
        ('Billing Period', {
            'fields': ('current_period_start', 'current_period_end', 'cancel_at_period_end')
        }),
        ('Usage Tracking', {
            'fields': ('scans_used_today', 'last_scan_reset')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User'
    user_email.admin_order_field = 'user__email'
    
    def plan_name(self, obj):
        color = 'green' if obj.plan.price == 0 else 'blue'
        return format_html('<span style="color: {}; font-weight: bold;">{}</span>', color, obj.plan.display_name)
    plan_name.short_description = 'Plan'
    plan_name.admin_order_field = 'plan__name'
    
    def usage_display(self, obj):
        daily_limit = obj.plan.scans_per_day
        used = obj.scans_used_today
        
        if daily_limit == -1:
            return format_html('<span style="color: green;">{} / ∞</span>', used)
        
        percentage = (used / daily_limit * 100) if daily_limit > 0 else 0
        color = 'red' if percentage >= 90 else ('orange' if percentage >= 70 else 'green')
        
        return format_html('<span style="color: {};">{} / {}</span>', color, used, daily_limit)
    usage_display.short_description = 'Daily Usage'
    
    def storage_info(self, obj):
        return f'{obj.plan.storage_limit_mb} MB limit'
    storage_info.short_description = 'Storage'
    
    actions = ['reset_daily_usage', 'activate_subscriptions', 'cancel_subscriptions']
    
    def reset_daily_usage(self, request, queryset):
        for sub in queryset:
            sub.reset_daily_usage()
        self.message_user(request, f"✅ Reset daily usage for {queryset.count()} subscriptions")
    reset_daily_usage.short_description = "Reset daily scan usage"
    
    def activate_subscriptions(self, request, queryset):
        queryset.update(status='active')
        self.message_user(request, f'✅ Activated {queryset.count()} subscriptions')
    activate_subscriptions.short_description = 'Activate selected subscriptions'
    
    def cancel_subscriptions(self, request, queryset):
        queryset.update(status='cancelled', cancel_at_period_end=True)
        self.message_user(request, f'⚠️ Cancelled {queryset.count()} subscriptions')
    cancel_subscriptions.short_description = 'Cancel selected subscriptions'

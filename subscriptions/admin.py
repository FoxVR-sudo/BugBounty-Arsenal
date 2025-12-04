from django.contrib import admin
from .models import Plan, Subscription


@admin.register(Plan)
class PlanAdmin(admin.ModelAdmin):
    """Plan admin"""
    
    list_display = ['name', 'display_name', 'price', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'display_name']
    ordering = ['price']
    
    fieldsets = (
        ('Basic Info', {'fields': ('name', 'display_name', 'price', 'is_active')}),
        ('Configuration', {'fields': ('limits', 'features')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )
    
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    """Subscription admin"""
    
    list_display = ['user', 'plan', 'status', 'scans_used_today', 'current_period_end', 'created_at']
    list_filter = ['status', 'plan', 'created_at']
    search_fields = ['user__email', 'stripe_customer_id', 'stripe_subscription_id']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Basic Info', {'fields': ('user', 'plan', 'status')}),
        ('Stripe', {'fields': ('stripe_customer_id', 'stripe_subscription_id')}),
        ('Billing Period', {'fields': ('current_period_start', 'current_period_end', 'cancel_at_period_end')}),
        ('Usage', {'fields': ('scans_used_today', 'last_scan_reset')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )
    
    readonly_fields = ['created_at', 'updated_at']
    
    actions = ['reset_daily_usage']
    
    def reset_daily_usage(self, request, queryset):
        """Reset daily scan usage for selected subscriptions"""
        for sub in queryset:
            sub.reset_daily_usage()
        self.message_user(request, f"Reset daily usage for {queryset.count()} subscriptions")
    reset_daily_usage.short_description = "Reset daily scan usage"

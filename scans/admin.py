from django.contrib import admin
from django.utils.html import format_html
from .models import Scan, AuditLog, ApiKey
from .category_models import ScanCategory, DetectorConfig, CategoryDetectorOrder


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    """Scan admin with full management capabilities"""
    
    list_display = ['id', 'user_email', 'target_short', 'scan_type', 'status_colored', 'vulnerabilities_found', 'duration', 'created_at']
    list_filter = ['status', 'scan_type', 'created_at']
    search_fields = ['target', 'user__email', 'id']
    readonly_fields = ['created_at', 'updated_at', 'started_at', 'completed_at', 'celery_task_id']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    fieldsets = (
        ('Basic Info', {
            'fields': ('user', 'target', 'scan_type', 'status')
        }),
        ('Execution', {
            'fields': ('pid', 'celery_task_id', 'started_at', 'completed_at', 'progress', 'current_step')
        }),
        ('Results', {
            'fields': ('report_path', 'vulnerabilities_found', 'severity_counts', 'raw_results')
        }),
        ('Storage', {
            'fields': ('report_size_bytes', 'expires_at')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['cancel_scans', 'delete_old_scans']
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User'
    user_email.admin_order_field = 'user__email'
    
    def target_short(self, obj):
        if len(obj.target) > 50:
            return obj.target[:47] + '...'
        return obj.target
    target_short.short_description = 'Target'
    
    def status_colored(self, obj):
        colors = {
            'pending': 'gray',
            'running': 'blue',
            'completed': 'green',
            'failed': 'red',
            'stopped': 'orange',
        }
        color = colors.get(obj.status, 'black')
        return format_html('<span style="color: {}; font-weight: bold;">{}</span>', color, obj.status.upper())
    status_colored.short_description = 'Status'
    
    def duration(self, obj):
        if obj.completed_at and obj.started_at:
            delta = obj.completed_at - obj.started_at
            minutes = int(delta.total_seconds() / 60)
            seconds = int(delta.total_seconds() % 60)
            if minutes > 0:
                return f'{minutes}m {seconds}s'
            return f'{seconds}s'
        return '-'
    duration.short_description = 'Duration'
    
    def cancel_scans(self, request, queryset):
        queryset.filter(status__in=['pending', 'running']).update(status='stopped')
        self.message_user(request, f'✅ Cancelled {queryset.count()} scans')
    cancel_scans.short_description = 'Cancel selected scans'
    
    def delete_old_scans(self, request, queryset):
        count = queryset.count()
        queryset.delete()
        self.message_user(request, f'🗑️ Deleted {count} scans')
    delete_old_scans.short_description = 'Delete selected scans'


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Audit log admin"""
    
    list_display = ['id', 'user', 'event_type', 'ip_address', 'created_at']
    list_filter = ['event_type', 'created_at']
    search_fields = ['user__email', 'event_type', 'description']
    readonly_fields = ['user', 'event_type', 'description', 'ip_address', 'user_agent', 'extra_data', 'created_at']
    ordering = ['-created_at']
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    """API Key admin"""
    
    list_display = ['name', 'user', 'is_active', 'last_used_at', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'user__email', 'key']
    readonly_fields = ['key', 'last_used_at', 'created_at']
    ordering = ['-created_at']


# ===========================
# V3.0 CATEGORY ADMIN PANELS
# ===========================

@admin.register(ScanCategory)
class ScanCategoryAdmin(admin.ModelAdmin):
    """Scan Category admin for v3.0"""
    
    list_display = ['icon', 'display_name', 'name', 'required_plan', 'detector_count', 'is_active', 'order']
    list_filter = ['required_plan', 'is_active']
    search_fields = ['name', 'display_name', 'description']
    readonly_fields = ['detector_count', 'created_at', 'updated_at']
    ordering = ['order', 'name']
    
    fieldsets = (
        ('Basic Info', {
            'fields': ('name', 'display_name', 'description', 'icon')
        }),
        ('Access Control', {
            'fields': ('required_plan', 'is_active')
        }),
        ('Display', {
            'fields': ('order', 'detector_count')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['update_detector_counts', 'activate_categories', 'deactivate_categories']
    
    def update_detector_counts(self, request, queryset):
        """Recalculate detector counts"""
        for category in queryset:
            category.update_detector_count()
        self.message_user(request, f'✅ Updated detector counts for {queryset.count()} categories')
    update_detector_counts.short_description = 'Update detector counts'
    
    def activate_categories(self, request, queryset):
        """Activate categories"""
        count = queryset.update(is_active=True)
        self.message_user(request, f'✅ Activated {count} categories')
    activate_categories.short_description = 'Activate selected categories'
    
    def deactivate_categories(self, request, queryset):
        """Deactivate categories"""
        count = queryset.update(is_active=False)
        self.message_user(request, f'⛔ Deactivated {count} categories')
    deactivate_categories.short_description = 'Deactivate selected categories'


@admin.register(DetectorConfig)
class DetectorConfigAdmin(admin.ModelAdmin):
    """Detector Configuration admin for v3.0"""
    
    list_display = [
        'display_name', 'name', 'severity_colored', 'is_dangerous_flag', 
        'is_beta_flag', 'category_count', 'total_executions', 'total_findings', 
        'average_time', 'is_active'
    ]
    list_filter = ['severity', 'is_dangerous', 'is_beta', 'is_active', 'requires_oob']
    search_fields = ['name', 'display_name', 'description', 'tags']
    readonly_fields = [
        'total_executions', 'total_findings', 'average_execution_time', 
        'last_executed_at', 'created_at', 'updated_at'
    ]
    ordering = ['execution_order', 'name']
    filter_horizontal = ['categories']
    
    fieldsets = (
        ('Basic Info', {
            'fields': ('name', 'display_name', 'description')
        }),
        ('Categories', {
            'fields': ('categories',)
        }),
        ('Classification', {
            'fields': ('severity', 'tags', 'is_dangerous', 'requires_oob', 'is_beta')
        }),
        ('Execution', {
            'fields': ('execution_order', 'timeout_seconds', 'max_concurrency')
        }),
        ('Status', {
            'fields': ('is_active',)
        }),
        ('Statistics', {
            'fields': (
                'total_executions', 'total_findings', 'average_execution_time', 
                'last_executed_at'
            ),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['mark_dangerous', 'unmark_dangerous', 'activate_detectors', 'deactivate_detectors']
    
    def severity_colored(self, obj):
        """Colored severity badge"""
        colors = {
            'critical': '#d32f2f',
            'high': '#f57c00',
            'medium': '#fbc02d',
            'low': '#388e3c',
            'info': '#1976d2',
        }
        color = colors.get(obj.severity, '#757575')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, obj.severity.upper()
        )
    severity_colored.short_description = 'Severity'
    
    def is_dangerous_flag(self, obj):
        """Dangerous detector flag"""
        if obj.is_dangerous:
            return format_html('<span style="color: red; font-weight: bold;">🔴 YES</span>')
        return '—'
    is_dangerous_flag.short_description = 'Dangerous'
    
    def is_beta_flag(self, obj):
        """Beta flag"""
        if obj.is_beta:
            return format_html('<span style="color: orange;">⚠️ BETA</span>')
        return '—'
    is_beta_flag.short_description = 'Beta'
    
    def category_count(self, obj):
        """Number of categories"""
        return obj.categories.count()
    category_count.short_description = 'Categories'
    
    def average_time(self, obj):
        """Average execution time formatted"""
        if obj.average_execution_time > 0:
            return f'{obj.average_execution_time:.2f}s'
        return '—'
    average_time.short_description = 'Avg Time'
    
    def mark_dangerous(self, request, queryset):
        """Mark as dangerous (Enterprise only)"""
        count = queryset.update(is_dangerous=True)
        self.message_user(request, f'🔴 Marked {count} detectors as DANGEROUS')
    mark_dangerous.short_description = 'Mark as DANGEROUS (Enterprise only)'
    
    def unmark_dangerous(self, request, queryset):
        """Unmark as dangerous"""
        count = queryset.update(is_dangerous=False)
        self.message_user(request, f'✅ Unmarked {count} detectors as dangerous')
    unmark_dangerous.short_description = 'Unmark as dangerous'
    
    def activate_detectors(self, request, queryset):
        """Activate detectors"""
        count = queryset.update(is_active=True)
        self.message_user(request, f'✅ Activated {count} detectors')
    activate_detectors.short_description = 'Activate selected detectors'
    
    def deactivate_detectors(self, request, queryset):
        """Deactivate detectors"""
        count = queryset.update(is_active=False)
        self.message_user(request, f'⛔ Deactivated {count} detectors')
    deactivate_detectors.short_description = 'Deactivate selected detectors'


@admin.register(CategoryDetectorOrder)
class CategoryDetectorOrderAdmin(admin.ModelAdmin):
    """Category-specific detector ordering admin"""
    
    list_display = ['category', 'detector', 'order', 'is_enabled']
    list_filter = ['category', 'is_enabled']
    search_fields = ['category__name', 'detector__name']
    ordering = ['category', 'order']
    
    fieldsets = (
        ('Assignment', {
            'fields': ('category', 'detector')
        }),
        ('Configuration', {
            'fields': ('order', 'is_enabled')
        }),
    )

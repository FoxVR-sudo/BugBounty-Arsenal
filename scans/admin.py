from django.contrib import admin
from django.utils.html import format_html
from .models import Scan, AuditLog, ApiKey


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

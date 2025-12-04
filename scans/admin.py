from django.contrib import admin
from .models import Scan, AuditLog, ApiKey


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    """Scan admin"""
    
    list_display = ['id', 'user', 'target', 'scan_type', 'status', 'vulnerabilities_found', 'created_at']
    list_filter = ['status', 'scan_type', 'created_at']
    search_fields = ['target', 'user__email']
    readonly_fields = ['created_at', 'updated_at', 'started_at', 'completed_at']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Basic Info', {'fields': ('user', 'target', 'scan_type', 'status')}),
        ('Execution', {'fields': ('pid', 'started_at', 'completed_at')}),
        ('Results', {'fields': ('report_path', 'vulnerabilities_found', 'severity_counts')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )


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

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User
from .audit_models import ScanAuditLog
from .team_models import Team, TeamMember, TeamInvitation
from .integration_models import Integration


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom User admin - Updated v3.0"""
    
    list_display = ['email', 'full_name', 'phone', 'phone_verified', 'company_name', 'company_verified', 'is_admin', 'is_verified', 'is_active', 'created_at']
    list_filter = ['is_admin', 'is_verified', 'phone_verified', 'company_verified', 'is_active', 'is_staff', 'created_at']
    search_fields = ['email', 'full_name', 'first_name', 'last_name', 'phone', 'company_name']
    ordering = ['-created_at']
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'middle_name', 'last_name', 'full_name', 'address')}),
        ('Phone verification', {'fields': ('phone', 'phone_verified', 'phone_verification_code', 'phone_verification_expires')}),
        ('Company info (Enterprise)', {'fields': ('company_name', 'company_registration_number', 'company_address', 'company_country', 'company_verified', 'company_verification_date')}),
        ('Permissions', {'fields': ('is_admin', 'is_verified', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Stripe', {'fields': ('stripe_customer_id',)}),
        ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'first_name', 'middle_name', 'last_name', 'phone'),
        }),
    )
    
    readonly_fields = ['created_at', 'updated_at', 'last_login', 'full_name', 'company_verification_date']


@admin.register(ScanAuditLog)
class ScanAuditLogAdmin(admin.ModelAdmin):
    """Scan audit log admin"""
    
    list_display = ['user', 'action', 'scan_type', 'target', 'ip_address', 'vulnerabilities_found', 'created_at']
    list_filter = ['action', 'scan_type', 'created_at', 'used_nuclei', 'used_custom_payloads']
    search_fields = ['user__email', 'target', 'ip_address']
    ordering = ['-created_at']
    readonly_fields = ['created_at']
    
    fieldsets = (
        (None, {'fields': ('scan', 'user', 'action', 'scan_type', 'target')}),
        ('Network info', {'fields': ('ip_address', 'user_agent', 'geo_country', 'geo_city')}),
        ('Results', {'fields': ('vulnerabilities_found', 'severity_critical', 'severity_high', 'severity_medium', 'severity_low', 'duration_seconds')}),
        ('Dangerous tools', {'fields': ('used_nuclei', 'used_custom_payloads', 'used_brute_force')}),
        ('Metadata', {'fields': ('metadata', 'error_message', 'created_at')}),
    )


@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    """Team admin"""
    
    list_display = ['name', 'owner', 'member_count', 'max_members', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'owner__email']
    ordering = ['-created_at']
    readonly_fields = ['invite_code', 'created_at', 'updated_at', 'member_count']
    
    fieldsets = (
        (None, {'fields': ('name', 'description', 'owner', 'max_members')}),
        ('Status', {'fields': ('is_active', 'invite_code')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )


@admin.register(TeamMember)
class TeamMemberAdmin(admin.ModelAdmin):
    """Team member admin"""
    
    list_display = ['user', 'team', 'role', 'is_active', 'joined_at']
    list_filter = ['role', 'is_active', 'joined_at']
    search_fields = ['user__email', 'team__name']
    ordering = ['-joined_at']
    readonly_fields = ['joined_at', 'updated_at']
    
    fieldsets = (
        (None, {'fields': ('team', 'user', 'role', 'invited_by')}),
        ('Permissions', {'fields': ('can_create_scans', 'can_view_all_scans', 'can_delete_scans', 'can_manage_members')}),
        ('Status', {'fields': ('is_active',)}),
        ('Timestamps', {'fields': ('joined_at', 'updated_at')}),
    )


@admin.register(TeamInvitation)
class TeamInvitationAdmin(admin.ModelAdmin):
    """Team invitation admin"""
    
    list_display = ['email', 'team', 'invited_by', 'role', 'status', 'created_at', 'expires_at']
    list_filter = ['status', 'role', 'created_at']
    search_fields = ['email', 'team__name', 'invited_by__email']
    ordering = ['-created_at']
    readonly_fields = ['token', 'created_at', 'updated_at', 'accepted_at']
    
    fieldsets = (
        (None, {'fields': ('team', 'email', 'invited_by', 'role')}),
        ('Status', {'fields': ('status', 'token', 'expires_at')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at', 'accepted_at')}),
    )


@admin.register(Integration)
class IntegrationAdmin(admin.ModelAdmin):
    """Integration admin"""
    
    list_display = ['name', 'integration_type', 'user', 'team', 'status', 'total_triggers', 'last_triggered_at']
    list_filter = ['integration_type', 'status', 'is_active', 'created_at']
    search_fields = ['name', 'user__email', 'team__name']
    ordering = ['-created_at']
    readonly_fields = ['created_at', 'updated_at', 'last_triggered_at', 'last_error_at', 'total_triggers', 'successful_triggers', 'failed_triggers']
    
    fieldsets = (
        (None, {'fields': ('user', 'team', 'integration_type', 'name')}),
        ('Configuration', {'fields': ('config', 'events')}),
        ('Status', {'fields': ('status', 'is_active')}),
        ('Error tracking', {'fields': ('last_error', 'last_error_at', 'error_count')}),
        ('Statistics', {'fields': ('total_triggers', 'successful_triggers', 'failed_triggers', 'last_triggered_at')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )

from rest_framework import serializers
from .models import Scan, Vulnerability, AuditLog, ApiKey


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Serializer for Vulnerability model"""
    
    class Meta:
        model = Vulnerability
        fields = ['id', 'title', 'severity', 'detector', 'url', 'payload', 
                  'evidence', 'description', 'status_code', 'response_time',
                  'is_verified', 'notes', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class ScanSerializer(serializers.ModelSerializer):
    """Serializer for Scan model"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    scan_category = serializers.CharField(source='scan_category.name', read_only=True)
    enabled_detectors = serializers.ListField(
        child=serializers.CharField(),
        write_only=True,
        required=False,
        help_text="List of detector names to run (optional, defaults to all for scan type)"
    )
    
    class Meta:
        model = Scan
        fields = ['id', 'user', 'user_email', 'target', 'scan_type', 'scan_category',
                  'status', 'progress', 'current_step', 'severity_counts', 'vulnerabilities_found',
                  'enabled_detectors',
                  'started_at', 'completed_at', 'report_path', 'celery_task_id', 'created_at']
        read_only_fields = ['id', 'user', 'status', 'progress', 'current_step', 'severity_counts', 
                           'vulnerabilities_found', 'started_at', 'completed_at', 
                           'report_path', 'celery_task_id', 'created_at']

    def create(self, validated_data):
        # Extract enabled_detectors before creating the model
        enabled_detectors = validated_data.pop('enabled_detectors', [])
        
        # User is set from request context in viewset
        validated_data['user'] = self.context['request'].user
        # Ensure raw_results has a default value for NOT NULL constraint
        if 'raw_results' not in validated_data:
            validated_data['raw_results'] = '{}'  # String representation for SQLite
        
        # Create the scan instance
        scan = super().create(validated_data)
        
        # Store enabled_detectors in the context for later use by start_async_scan
        # We'll pass it via the scan_config parameter
        scan._enabled_detectors = enabled_detectors
        
        return scan


class ScanDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for Scan model with full results"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    scan_category = serializers.CharField(source='scan_category.name', read_only=True)
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    
    class Meta:
        model = Scan
        fields = ['id', 'user', 'user_email', 'target', 'scan_type', 'scan_category', 'status',
                  'progress', 'current_step', 'severity_counts', 'vulnerabilities_found',
                  'vulnerabilities', 'raw_results',
                  'started_at', 'completed_at', 'report_path', 'celery_task_id', 
                  'created_at', 'updated_at', 'pid']
        read_only_fields = ['id', 'user', 'status', 'severity_counts', 
                           'vulnerabilities_found', 'vulnerabilities', 'raw_results',
                           'started_at', 'completed_at', 
                           'report_path', 'celery_task_id', 'created_at', 'updated_at', 'pid']


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for AuditLog model (read-only)"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = ['id', 'user', 'user_email', 'event_type', 'description', 
                  'ip_address', 'user_agent', 'extra_data', 'created_at']
        read_only_fields = ['id', 'user', 'event_type', 'description', 
                           'ip_address', 'user_agent', 'extra_data', 'created_at']


class ApiKeySerializer(serializers.ModelSerializer):
    """Serializer for ApiKey model"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    
    class Meta:
        model = ApiKey
        fields = ['id', 'user', 'user_email', 'key', 'name', 'is_active', 
                  'created_at', 'last_used_at']
        read_only_fields = ['id', 'user', 'key', 'created_at', 'last_used_at']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)

from rest_framework import serializers
from .models import Scan, AuditLog, ApiKey


class ScanSerializer(serializers.ModelSerializer):
    """Serializer for Scan model"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    
    class Meta:
        model = Scan
        fields = ['id', 'user', 'user_email', 'target', 'scan_type', 
                  'status', 'progress', 'current_step', 'severity_counts', 'vulnerabilities_found', 
                  'started_at', 'completed_at', 'report_path', 'celery_task_id', 'created_at']
        read_only_fields = ['id', 'user', 'status', 'progress', 'current_step', 'severity_counts', 
                           'vulnerabilities_found', 'started_at', 'completed_at', 
                           'report_path', 'celery_task_id', 'created_at']

    def create(self, validated_data):
        # User is set from request context in viewset
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class ScanDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for Scan model with full results"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    
    class Meta:
        model = Scan
        fields = '__all__'
        read_only_fields = ['id', 'user', 'status', 'severity_counts', 
                           'vulnerabilities_found', 'started_at', 'completed_at', 
                           'report_path', 'celery_task_id', 'created_at', 'pid']


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

from rest_framework import serializers
from .models import Plan, Subscription


class PlanSerializer(serializers.ModelSerializer):
    """Serializer for Plan model"""
    
    class Meta:
        model = Plan
        fields = ['id', 'name', 'display_name', 'price', 
                  'limits', 'features', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class SubscriptionSerializer(serializers.ModelSerializer):
    """Serializer for Subscription model"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    plan_name = serializers.CharField(source='plan.display_name', read_only=True)
    
    class Meta:
        model = Subscription
        fields = ['id', 'user', 'user_email', 'plan', 'plan_name', 'status', 
                  'stripe_customer_id', 'stripe_subscription_id',
                  'current_period_start', 'current_period_end', 'cancel_at_period_end',
                  'scans_used_today', 'last_scan_reset', 'created_at', 'updated_at']
        read_only_fields = ['id', 'user', 'scans_used_today', 'last_scan_reset', 
                           'created_at', 'updated_at']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class SubscriptionUsageSerializer(serializers.ModelSerializer):
    """Serializer for subscription usage information"""
    plan_name = serializers.CharField(source='plan.display_name', read_only=True)
    plan_limits = serializers.JSONField(source='plan.limits', read_only=True)
    can_scan = serializers.SerializerMethodField()
    
    class Meta:
        model = Subscription
        fields = ['id', 'plan_name', 'plan_limits', 'status',
                  'scans_used_today', 'can_scan', 
                  'current_period_end', 'cancel_at_period_end']
        read_only_fields = ['id', 'plan_name', 'plan_limits', 'status',
                           'scans_used_today', 'can_scan', 
                           'current_period_end', 'cancel_at_period_end']

    def get_can_scan(self, obj):
        return obj.can_start_scan()

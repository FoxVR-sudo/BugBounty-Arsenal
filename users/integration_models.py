"""
Integration models for third-party services
Available for Pro and Enterprise plans
"""
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError


class Integration(models.Model):
    """
    Third-party service integrations
    Supported: Slack, Jira, Discord, Telegram, GitHub, GitLab, Webhooks
    """
    
    INTEGRATION_TYPES = [
        ('slack', 'Slack'),
        ('jira', 'Jira'),
        ('discord', 'Discord'),
        ('telegram', 'Telegram'),
        ('github', 'GitHub'),
        ('gitlab', 'GitLab'),
        ('webhook', 'Custom Webhook'),
        ('email', 'Email Alerts'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('error', 'Error'),
    ]
    
    EVENT_TYPES = [
        ('scan_completed', 'Scan Completed'),
        ('scan_failed', 'Scan Failed'),
        ('vulnerability_found', 'Vulnerability Found'),
        ('critical_vulnerability', 'Critical Vulnerability'),
        ('daily_report', 'Daily Report'),
        ('weekly_report', 'Weekly Report'),
    ]
    
    # Owner
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='integrations'
    )
    team = models.ForeignKey(
        'Team',
        on_delete=models.CASCADE,
        related_name='integrations',
        null=True,
        blank=True,
        help_text='Team integration (optional)'
    )
    
    # Integration details
    integration_type = models.CharField(max_length=20, choices=INTEGRATION_TYPES)
    name = models.CharField(max_length=255, help_text='Integration name/description')
    
    # Configuration (stored as JSON)
    config = models.JSONField(
        default=dict,
        help_text='Integration configuration (API keys, URLs, etc.)'
    )
    
    # Events to trigger
    events = models.JSONField(
        default=list,
        help_text='List of events that trigger this integration'
    )
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    is_active = models.BooleanField(default=True)
    
    # Error tracking
    last_error = models.TextField(blank=True)
    last_error_at = models.DateTimeField(null=True, blank=True)
    error_count = models.IntegerField(default=0)
    
    # Statistics
    total_triggers = models.IntegerField(default=0, help_text='Total times triggered')
    successful_triggers = models.IntegerField(default=0)
    failed_triggers = models.IntegerField(default=0)
    last_triggered_at = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'integrations'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'integration_type']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"{self.get_integration_type_display()} - {self.name}"
    
    def clean(self):
        """Validate integration configuration"""
        # Check user's subscription plan
        if hasattr(self.user, 'subscription'):
            plan = self.user.subscription.plan
            if plan not in ['pro', 'enterprise']:
                raise ValidationError('Integrations are only available for Pro and Enterprise plans')
        
        # Validate required config fields
        required_fields = self._get_required_config_fields()
        for field in required_fields:
            if field not in self.config:
                raise ValidationError(f'Missing required configuration field: {field}')
    
    def _get_required_config_fields(self):
        """Get required config fields based on integration type"""
        config_requirements = {
            'slack': ['webhook_url'],
            'jira': ['url', 'username', 'api_token', 'project_key'],
            'discord': ['webhook_url'],
            'telegram': ['bot_token', 'chat_id'],
            'github': ['token', 'repository'],
            'gitlab': ['token', 'project_id'],
            'webhook': ['url'],
            'email': ['recipients'],
        }
        return config_requirements.get(self.integration_type, [])
    
    def test_connection(self):
        """
        Test integration connection
        Returns (success: bool, message: str)
        """
        # TODO: Implement actual testing logic for each integration type
        try:
            if self.integration_type == 'slack':
                return self._test_slack()
            elif self.integration_type == 'jira':
                return self._test_jira()
            elif self.integration_type == 'discord':
                return self._test_discord()
            elif self.integration_type == 'webhook':
                return self._test_webhook()
            else:
                return True, 'Test connection not implemented yet'
        except Exception as e:
            return False, str(e)
    
    def _test_slack(self):
        """Test Slack webhook"""
        import requests
        url = self.config.get('webhook_url')
        response = requests.post(url, json={'text': 'BugBounty Arsenal - Connection test'}, timeout=10)
        if response.status_code == 200:
            return True, 'Slack connection successful'
        return False, f'Slack connection failed: {response.status_code}'
    
    def _test_discord(self):
        """Test Discord webhook"""
        import requests
        url = self.config.get('webhook_url')
        response = requests.post(url, json={'content': 'BugBounty Arsenal - Connection test'}, timeout=10)
        if response.status_code in [200, 204]:
            return True, 'Discord connection successful'
        return False, f'Discord connection failed: {response.status_code}'
    
    def _test_webhook(self):
        """Test custom webhook"""
        import requests
        url = self.config.get('url')
        headers = self.config.get('headers', {})
        response = requests.post(url, json={'test': True}, headers=headers, timeout=10)
        if 200 <= response.status_code < 300:
            return True, 'Webhook connection successful'
        return False, f'Webhook connection failed: {response.status_code}'
    
    def _test_jira(self):
        """Test Jira connection"""
        # TODO: Implement Jira API test
        return True, 'Jira test not implemented yet'
    
    def trigger(self, event_type, data):
        """
        Trigger integration with event data
        Returns (success: bool, message: str)
        """
        if not self.is_active:
            return False, 'Integration is inactive'
        
        if event_type not in self.events:
            return False, f'Event {event_type} not configured for this integration'
        
        self.total_triggers += 1
        
        try:
            success, message = self._send_notification(event_type, data)
            
            if success:
                self.successful_triggers += 1
                self.error_count = 0  # Reset error count on success
            else:
                self.failed_triggers += 1
                self.error_count += 1
                self.last_error = message
                self.last_error_at = models.DateTimeField(auto_now=True)
                
                # Disable integration after 5 consecutive failures
                if self.error_count >= 5:
                    self.is_active = False
                    self.status = 'error'
            
            from django.utils import timezone
            self.last_triggered_at = timezone.now()
            self.save()
            
            return success, message
            
        except Exception as e:
            self.failed_triggers += 1
            self.error_count += 1
            self.last_error = str(e)
            from django.utils import timezone
            self.last_error_at = timezone.now()
            self.save()
            return False, str(e)
    
    def _send_notification(self, event_type, data):
        """Send notification based on integration type"""
        if self.integration_type == 'slack':
            return self._send_slack(event_type, data)
        elif self.integration_type == 'discord':
            return self._send_discord(event_type, data)
        elif self.integration_type == 'webhook':
            return self._send_webhook(event_type, data)
        elif self.integration_type == 'email':
            return self._send_email(event_type, data)
        else:
            return False, f'Integration type {self.integration_type} not implemented yet'
    
    def _send_slack(self, event_type, data):
        """Send Slack notification"""
        import requests
        
        message = self._format_message(event_type, data)
        url = self.config.get('webhook_url')
        
        payload = {
            'text': message['title'],
            'attachments': [{
                'color': message['color'],
                'fields': [
                    {'title': k, 'value': v, 'short': True}
                    for k, v in message['fields'].items()
                ]
            }]
        }
        
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            return True, 'Slack notification sent'
        return False, f'Slack error: {response.status_code}'
    
    def _send_discord(self, event_type, data):
        """Send Discord notification"""
        import requests
        
        message = self._format_message(event_type, data)
        url = self.config.get('webhook_url')
        
        payload = {
            'content': message['title'],
            'embeds': [{
                'title': event_type.replace('_', ' ').title(),
                'color': int(message['color'].replace('#', ''), 16),
                'fields': [
                    {'name': k, 'value': v, 'inline': True}
                    for k, v in message['fields'].items()
                ]
            }]
        }
        
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code in [200, 204]:
            return True, 'Discord notification sent'
        return False, f'Discord error: {response.status_code}'
    
    def _send_webhook(self, event_type, data):
        """Send custom webhook"""
        import requests
        
        url = self.config.get('url')
        headers = self.config.get('headers', {})
        
        payload = {
            'event': event_type,
            'data': data,
            'timestamp': str(models.DateTimeField(auto_now=True))
        }
        
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        if 200 <= response.status_code < 300:
            return True, 'Webhook notification sent'
        return False, f'Webhook error: {response.status_code}'
    
    def _send_email(self, event_type, data):
        """Send email notification"""
        from django.core.mail import send_mail
        from django.conf import settings as django_settings
        
        message = self._format_message(event_type, data)
        recipients = self.config.get('recipients', [])
        
        send_mail(
            subject=message['title'],
            message='\n'.join([f"{k}: {v}" for k, v in message['fields'].items()]),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipients,
            fail_silently=False,
        )
        
        return True, 'Email sent'
    
    def _format_message(self, event_type, data):
        """Format notification message"""
        colors = {
            'scan_completed': '#28a745',  # Green
            'scan_failed': '#dc3545',  # Red
            'vulnerability_found': '#ffc107',  # Yellow
            'critical_vulnerability': '#dc3545',  # Red
        }
        
        return {
            'title': f"🔍 {event_type.replace('_', ' ').title()}",
            'color': colors.get(event_type, '#007bff'),
            'fields': {
                'Target': data.get('target', 'N/A'),
                'Scan Type': data.get('scan_type', 'N/A'),
                'Vulnerabilities': str(data.get('vulnerabilities_found', 0)),
                'Status': data.get('status', 'N/A'),
            }
        }

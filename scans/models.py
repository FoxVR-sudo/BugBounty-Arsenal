from django.db import models
from django.conf import settings
from django.utils import timezone


class Scan(models.Model):
    """Scan model"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('stopped', 'Stopped'),
    ]
    
    SCAN_TYPE_CHOICES = [
        ('reconnaissance', 'Reconnaissance'),
        ('web_security', 'Web Security'),
        ('vulnerability', 'Vulnerability Scan'),
        ('api_security', 'API Security'),
        ('mobile', 'Mobile Security'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scans')
    target = models.CharField(max_length=500)
    scan_type = models.CharField(max_length=50, choices=SCAN_TYPE_CHOICES, default='web_security')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Scan execution
    pid = models.IntegerField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=100, blank=True, null=True, help_text='Celery task ID for async execution')
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Results
    report_path = models.CharField(max_length=500, blank=True)
    vulnerabilities_found = models.IntegerField(default=0)
    severity_counts = models.JSONField(default=dict, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'scans'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.scan_type} - {self.target} ({self.status})"
    
    def start_async_scan(self, scan_config: dict = None):
        """
        Start the scan asynchronously using Celery.
        
        Args:
            scan_config: Optional configuration dict for the scan
            
        Returns:
            Celery task result
        """
        from scans.tasks import execute_scan_task
        
        if scan_config is None:
            scan_config = {}
        
        # Prepare scan configuration
        config = {
            'target': self.target,
            'scan_type': self.scan_type,
            'user_tier': getattr(self.user, 'subscription', {}).get('plan', {}).get('name', 'free'),
            'options': scan_config,
        }
        
        # Start the Celery task
        task = execute_scan_task.apply_async(args=[self.id, config])
        
        # Store task ID
        self.celery_task_id = task.id
        self.status = 'pending'
        self.save(update_fields=['celery_task_id', 'status'])
        
        return task
    
    def cancel_scan(self):
        """Cancel a running or pending scan."""
        from scans.tasks import cancel_scan_task
        
        if self.status in ['running', 'pending']:
            # Revoke the Celery task if it exists
            if self.celery_task_id:
                from celery.result import AsyncResult
                AsyncResult(self.celery_task_id).revoke(terminate=True)
            
            # Update status
            self.status = 'stopped'
            self.completed_at = timezone.now()
            self.save(update_fields=['status', 'completed_at'])
            
            return True
        return False
    
    def get_task_status(self):
        """Get the current status of the Celery task."""
        if not self.celery_task_id:
            return None
        
        from celery.result import AsyncResult
        task = AsyncResult(self.celery_task_id)
        
        return {
            'task_id': self.celery_task_id,
            'state': task.state,
            'info': task.info if task.info else {},
        }


class AuditLog(models.Model):
    """Audit log for tracking admin actions"""
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    event_type = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    extra_data = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'audit_logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['event_type']),
        ]
    
    def __str__(self):
        return f"{self.event_type} - {self.created_at}"


class ApiKey(models.Model):
    """API keys for external integrations"""
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='api_keys')
    name = models.CharField(max_length=100)
    key = models.CharField(max_length=100, unique=True)
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api_keys'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} - {self.user.email}"
    
    def regenerate_key(self):
        """Generate a new random API key"""
        import secrets
        self.key = secrets.token_urlsafe(32)
        self.save()
        return self.key
    
    def save(self, *args, **kwargs):
        """Auto-generate key on creation"""
        if not self.key:
            import secrets
            self.key = secrets.token_urlsafe(32)
        super().save(*args, **kwargs)

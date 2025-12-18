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
    
    # Progress tracking
    progress = models.IntegerField(default=0, help_text='Scan progress percentage (0-100)')
    current_step = models.CharField(max_length=200, blank=True, help_text='Current scan step/phase')
    
    # Results
    report_path = models.CharField(max_length=500, blank=True)
    vulnerabilities_found = models.IntegerField(default=0)
    severity_counts = models.JSONField(default=dict, blank=True)
    raw_results = models.JSONField(default=dict, blank=True, help_text='Full scan results data')
    
    # Storage management
    report_size_bytes = models.BigIntegerField(default=0, help_text='Total size of all report files in bytes')
    expires_at = models.DateTimeField(null=True, blank=True, help_text='When this scan result will be auto-deleted')
    
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
            scan_config: Optional configuration dict containing:
                - enabled_detectors: List of detector names to run
                - options: Scan options (concurrency, timeout, etc.)
            
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
                        'enabled_detectors': scan_config.get('enabled_detectors', []),
            'options': scan_config,
        }
        
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            # Try to start Celery task
            task = execute_scan_task.apply_async(args=[self.id, config])
            
            # Store task ID
            self.celery_task_id = task.id
            self.status = 'pending'
            self.save(update_fields=['celery_task_id', 'status'])
            
            logger.info(f"Scan {self.id} started with Celery task {task.id}")
            return task
        except Exception as e:
            # Celery not available - fallback to immediate execution
            logger.warning(f"Celery not available: {e}")
            self.status = 'running'
            self.save(update_fields=['status'])
            logger.info(f"Scan {self.id} started without Celery (test mode)")
            return None
    
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
    
    def calculate_expiration(self):
        """Calculate when this scan should expire based on user tier."""
        if not self.completed_at:
            return None
        
        # Get user tier from subscription
        try:
            tier = self.user.subscription.plan.name.lower()
        except:
            tier = 'free'
        
        # Expiration periods by tier
        retention_days = {
            'free': 7,
            'basic': 30,
            'pro': 90,
            'enterprise': 365,
        }
        
        days = retention_days.get(tier, 7)
        from datetime import timedelta
        return self.completed_at + timedelta(days=days)
    
    def calculate_storage_size(self):
        """Calculate total storage used by this scan's files."""
        import os
        total_size = 0
        
        if self.report_path and os.path.exists(self.report_path):
            total_size += os.path.getsize(self.report_path)
        
        # Check for export files
        report_dir = os.path.dirname(self.report_path) if self.report_path else 'reports'
        scan_files = [
            f'{report_dir}/scan_{self.id}.html',
            f'{report_dir}/scan_{self.id}.pdf',
            f'{report_dir}/scan_{self.id}.json',
            f'{report_dir}/scan_{self.id}.csv',
        ]
        
        for file_path in scan_files:
            if os.path.exists(file_path):
                total_size += os.path.getsize(file_path)
        
        return total_size
    
    def update_storage_size(self):
        """Update the report_size_bytes field."""
        self.report_size_bytes = self.calculate_storage_size()
        self.save(update_fields=['report_size_bytes'])
    
    def is_expired(self):
        """Check if this scan has expired."""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at
    
    def delete_files(self):
        """Delete all files associated with this scan."""
        import os
        deleted_files = []
        
        if self.report_path and os.path.exists(self.report_path):
            os.remove(self.report_path)
            deleted_files.append(self.report_path)
        
        # Delete export files
        report_dir = os.path.dirname(self.report_path) if self.report_path else 'reports'
        scan_files = [
            f'{report_dir}/scan_{self.id}.html',
            f'{report_dir}/scan_{self.id}.pdf',
            f'{report_dir}/scan_{self.id}.json',
            f'{report_dir}/scan_{self.id}.csv',
        ]
        
        for file_path in scan_files:
            if os.path.exists(file_path):
                os.remove(file_path)
                deleted_files.append(file_path)
        
        return deleted_files
    
    def parse_and_store_findings(self):
        """Parse raw_results and create Vulnerability records."""
        if not self.raw_results:
            return 0
        
        findings = self.raw_results.get('findings', [])
        count = 0
        
        # Clear existing vulnerabilities first
        self.vulnerabilities.all().delete()
        
        for finding in findings:
            try:
                vuln = Vulnerability.objects.create(
                    scan=self,
                    title=finding.get('type', 'Unknown'),
                    description=finding.get('description', ''),
                    severity=finding.get('severity', 'low').lower(),
                    detector=finding.get('detector', 'unknown'),
                    url=finding.get('url', ''),
                    payload=finding.get('payload', ''),
                    evidence=finding.get('evidence', ''),
                    request_headers=finding.get('request_headers', {}),
                    response_headers=finding.get('response_headers', {}),
                    status_code=finding.get('status', None),
                    response_time=finding.get('response_time', None),
                    raw_data=finding,
                )
                count += 1
            except Exception as e:
                import logging
                logging.error(f"Error storing vulnerability: {e}")
                continue
        
        return count


class Vulnerability(models.Model):
    """Individual vulnerability finding from a scan"""
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    title = models.CharField(max_length=500, help_text='Vulnerability type/title')
    description = models.TextField(blank=True, help_text='Detailed description')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='low')
    detector = models.CharField(max_length=100, blank=True, help_text='Which detector found this')
    url = models.TextField(blank=True, help_text='Vulnerable URL')
    payload = models.TextField(blank=True, help_text='Payload used for exploitation')
    evidence = models.TextField(blank=True, help_text='Evidence of the vulnerability')
    request_headers = models.JSONField(default=dict, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    response_time = models.FloatField(null=True, blank=True, help_text='Response time in seconds')
    raw_data = models.JSONField(default=dict, blank=True, help_text='Full raw finding data')
    is_verified = models.BooleanField(default=False, help_text='User verified this finding')
    notes = models.TextField(blank=True, help_text='User notes')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'vulnerabilities'
        ordering = ['-severity', '-created_at']
        indexes = [
            models.Index(fields=['scan', 'severity']),
            models.Index(fields=['detector']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.severity} ({self.scan_id})"


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

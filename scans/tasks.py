"""
Celery tasks for asynchronous scan execution.

This module contains Celery tasks that execute security scans in the background,
integrating with the existing detector system and updating scan results in real-time.
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from celery import shared_task
from django.utils import timezone
from scans.websocket_utils import send_scan_update, send_scan_complete, send_scan_error

# Add project root to path to import scanner module
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def execute_scan_task(self, scan_id: int, scan_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a security scan asynchronously.
    
    Args:
        scan_id: The ID of the Scan model instance
        scan_config: Configuration dictionary containing:
            - target: Target URL or domain
            - scan_type: Type of scan to perform
            - user_tier: User's subscription tier
            - enabled_detectors: List of detector names to run
            - options: Additional scan options
    
    Returns:
        Dictionary with scan results and metadata
    """
    from scans.models import Scan
    
    try:
        # Get the scan instance
        scan = Scan.objects.get(id=scan_id)
        
        # Update status to running
        scan.status = 'running'
        scan.started_at = timezone.now()
        scan.progress = 0
        scan.current_step = 'Initializing scanner...'
        scan.save(update_fields=['status', 'started_at', 'progress', 'current_step'])
        
        # Send WebSocket update
        send_scan_update(scan_id, {
            'status': 'running',
            'progress': 0,
            'current_step': 'Initializing scanner...',
            'started_at': scan.started_at.isoformat()
        })
        
        logger.info(f"Starting scan {scan_id} for target: {scan_config['target']}")
        
        # Extract configuration
        target = scan_config['target']
        scan_type = scan_config.get('scan_type', 'web_security')
        user_tier = scan_config.get('user_tier', 'free')
        enabled_detectors = scan_config.get('enabled_detectors', [])
        options = scan_config.get('options', {})
        
        # If no specific detectors selected, use all based on scan type
        if not enabled_detectors:
            # Import detector mappings
            from django.conf import settings
            enabled_detectors = settings.SCANNER_DETECTOR_MAPPING.get(scan_type, [])
        
        logger.info(f"Scan {scan_id} will run {len(enabled_detectors)} detectors: {enabled_detectors}")

        
        # Prepare scan context
        scan_context = {
            'scan_id': scan_id,
            'user_tier': user_tier,
            'scan_mode': options.get('scan_mode', 'normal'),
            'output_dir': f'reports/scan_{scan_id}',
            'auto_confirm': True,  # Auto-confirm for async execution
            'concurrency': options.get('concurrency', 10),
            'timeout': options.get('timeout', 15),
            'per_host_rate': options.get('per_host_rate', 1.0),
            'allow_destructive': options.get('allow_destructive', False),
            'bypass_cloudflare': options.get('bypass_cloudflare', False),
            'enable_forbidden_probe': options.get('enable_forbidden_probe', False),
            'enabled_detectors': enabled_detectors,
        }
        
        # Import scanner module
        import scanner
        
        # Update progress
        scan.progress = 10
        scan.current_step = f'Preparing scan targets... ({len(enabled_detectors)} detectors)'
        scan.save(update_fields=['progress', 'current_step'])
        send_scan_update(scan_id, {
            'progress': 10,
            'current_step': f'Preparing scan targets... ({len(enabled_detectors)} detectors)'
        })
        
        # Prepare targets list
        targets = [target] if isinstance(target, str) else target
        
        # Update progress
        scan.progress = 20
        scan.current_step = f'Starting {len(enabled_detectors)} detectors...'
        scan.save(update_fields=['progress', 'current_step'])
        send_scan_update(scan_id, {
            'progress': 20,
            'current_step': f'Starting {len(enabled_detectors)} detectors...',
            'total_detectors': len(enabled_detectors)
        })
        
        # Execute the scan
        logger.info(f"Executing scan with context: {scan_context}")
        results, metadata = scanner.run_scan(
            targets=targets,
            concurrency=scan_context['concurrency'],
            timeout=scan_context['timeout'],
            per_host_rate=scan_context['per_host_rate'],
            allow_destructive=scan_context['allow_destructive'],
            output_dir=scan_context['output_dir'],
            auto_confirm=scan_context['auto_confirm'],
            bypass_cloudflare=scan_context['bypass_cloudflare'],
            enable_forbidden_probe=scan_context['enable_forbidden_probe'],
            scan_mode=scan_context['scan_mode'],
            user_tier=user_tier,
            extra_context={
                'celery_task_id': self.request.id,
                'enabled_detectors': enabled_detectors,
            },
        )
        
        # Update progress
        scan.progress = 70
        scan.current_step = 'Processing results...'
        scan.save(update_fields=['progress', 'current_step'])
        send_scan_update(scan_id, {
            'progress': 70,
            'current_step': 'Processing results...'
        })
        
        # Process results
        vulnerabilities_found = 0
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        
        # Count vulnerabilities by severity
        # Each result is already a single vulnerability finding
        for result in results:
            # Check if result has issues array (old format) or is direct finding (new format)
            issues = result.get('issues', [])
            if issues:
                # Old format with issues array
                vulnerabilities_found += len(issues)
                for issue in issues:
                    severity = issue.get('severity', 'info').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    else:
                        severity_counts['info'] += 1
            else:
                # New format - result is direct finding
                vulnerabilities_found += 1
                severity = result.get('severity', 'info').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts['info'] += 1
        
        # Update progress
        scan.progress = 85
        scan.current_step = 'Generating report...'
        scan.save(update_fields=['progress', 'current_step'])
        send_scan_update(scan_id, {
            'progress': 85,
            'current_step': 'Generating report...',
            'vulnerabilities_found': vulnerabilities_found,
            'severity_counts': severity_counts
        })
        
        # Generate report
        report_path = f'reports/scan_{scan_id}/report.json'
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        report_data = {
            'scan_id': scan_id,
            'target': target,
            'scan_type': scan_type,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': timezone.now().isoformat(),
            'vulnerabilities_found': vulnerabilities_found,
            'severity_counts': severity_counts,
            'findings': [],
            'results': results,
            'metadata': metadata,
        }
        
        # Extract and flatten findings from results
        for result in results:
            # Check if result has issues array (old format) or is direct finding (new format)
            issues = result.get('issues', [])
            if issues:
                # Old format with issues array
                for issue in issues:
                    finding = {
                        'type': issue.get('type', 'Unknown'),
                        'severity': issue.get('severity', 'low'),
                        'url': issue.get('url', result.get('url', '')),
                        'detector': issue.get('detector', 'unknown'),
                        'description': issue.get('description', ''),
                        'evidence': issue.get('evidence', ''),
                        'payload': issue.get('payload', ''),
                        'status': issue.get('status', None),
                        'response_time': issue.get('response_time', None),
                        'request_headers': issue.get('request_headers', {}),
                        'response_headers': issue.get('response_headers', {}),
                    }
                    report_data['findings'].append(finding)
            else:
                # New format - result is direct finding
                finding = {
                    'type': result.get('type', 'Unknown'),
                    'severity': result.get('severity', 'low'),
                    'url': result.get('url', ''),
                    'detector': result.get('detector', 'unknown'),
                    'description': result.get('description', ''),
                    'evidence': result.get('evidence', ''),
                    'payload': result.get('payload', ''),
                    'status': result.get('status', None),
                    'response_time': result.get('response_time', None),
                    'request_headers': result.get('request_headers', {}),
                    'response_headers': result.get('response_headers', {}),
                }
                report_data['findings'].append(finding)
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Update scan with results
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.report_path = report_path
        scan.raw_results = report_data
        scan.vulnerabilities_found = vulnerabilities_found
        scan.severity_counts = severity_counts
        scan.progress = 95
        scan.current_step = 'Storing findings...'
        scan.save(update_fields=[
            'status', 'completed_at', 'report_path', 'raw_results',
            'vulnerabilities_found', 'severity_counts',
            'progress', 'current_step'
        ])
        
        # Parse and store individual findings in database
        findings_count = scan.parse_and_store_findings()
        logger.info(f"Stored {findings_count} findings in database for scan {scan_id}")
        
        # Update progress to completed
        scan.progress = 100
        scan.current_step = 'Scan completed'
        scan.save(update_fields=['progress', 'current_step'])
        
        # Send completion update via WebSocket
        send_scan_complete(scan_id, {
            'status': 'completed',
            'progress': 100,
            'completed_at': scan.completed_at.isoformat(),
            'vulnerabilities_found': vulnerabilities_found,
            'severity_counts': severity_counts,
            'report_path': report_path
        })
        
        logger.info(f"Scan {scan_id} completed successfully. Found {vulnerabilities_found} vulnerabilities.")
        
        return {
            'scan_id': scan_id,
            'status': 'completed',
            'vulnerabilities_found': vulnerabilities_found,
            'severity_counts': severity_counts,
            'report_path': report_path,
        }
        
    except Scan.DoesNotExist:
        error_msg = f"Scan with ID {scan_id} not found"
        logger.error(error_msg)
        return {'scan_id': scan_id, 'status': 'failed', 'error': error_msg}
        
    except Exception as e:
        error_msg = f"Scan {scan_id} failed: {str(e)}"
        logger.exception(error_msg)
        
        # Update scan status to failed
        try:
            scan = Scan.objects.get(id=scan_id)
            scan.status = 'failed'
            scan.completed_at = timezone.now()
            scan.progress = 0
            scan.current_step = f'Error: {str(e)}'
            scan.save(update_fields=['status', 'completed_at', 'progress', 'current_step'])
            
            # Send error via WebSocket
            send_scan_error(scan_id, {
                'status': 'failed',
                'error': str(e),
                'completed_at': scan.completed_at.isoformat()
            })
        except Exception as save_error:
            logger.error(f"Failed to update scan status: {save_error}")
        
        # Retry the task if retries are available
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying scan {scan_id} (attempt {self.request.retries + 1}/{self.max_retries})")
            raise self.retry(exc=e, countdown=60)
        
        return {
            'scan_id': scan_id,
            'status': 'failed',
            'error': str(e),
        }


@shared_task
def cancel_scan_task(scan_id: int) -> Dict[str, Any]:
    """
    Cancel a running scan.
    
    Args:
        scan_id: The ID of the Scan model instance to cancel
        
    Returns:
        Dictionary with cancellation status
    """
    from scans.models import Scan
    from celery.result import AsyncResult
    
    try:
        scan = Scan.objects.get(id=scan_id)
        
        if scan.status not in ['running', 'pending']:
            return {
                'scan_id': scan_id,
                'status': 'already_stopped',
                'message': f'Scan is already {scan.status}'
            }
        
        # Try to revoke the Celery task
        # Note: This requires the task_id to be stored, which we'll add to the model
        
        # Update scan status
        scan.status = 'stopped'
        scan.completed_at = timezone.now()
        scan.save(update_fields=['status', 'completed_at'])
        
        logger.info(f"Scan {scan_id} cancelled successfully")
        
        return {
            'scan_id': scan_id,
            'status': 'stopped',
            'message': 'Scan cancelled successfully'
        }
        
    except Scan.DoesNotExist:
        error_msg = f"Scan with ID {scan_id} not found"
        logger.error(error_msg)
        return {'scan_id': scan_id, 'status': 'error', 'error': error_msg}
        
    except Exception as e:
        error_msg = f"Failed to cancel scan {scan_id}: {str(e)}"
        logger.exception(error_msg)
        return {'scan_id': scan_id, 'status': 'error', 'error': str(e)}


@shared_task
def cleanup_old_scans_task(days: int = 30) -> Dict[str, Any]:
    """
    Clean up old scan reports and data.
    
    Args:
        days: Delete scans older than this many days
        
    Returns:
        Dictionary with cleanup statistics
    """
    from scans.models import Scan
    from datetime import timedelta
    import shutil
    
    try:
        cutoff_date = timezone.now() - timedelta(days=days)
        old_scans = Scan.objects.filter(created_at__lt=cutoff_date)
        
        deleted_count = 0
        deleted_size = 0
        
        for scan in old_scans:
            # Delete report files
            if scan.report_path and os.path.exists(scan.report_path):
                report_dir = os.path.dirname(scan.report_path)
                if os.path.exists(report_dir):
                    # Calculate size before deletion
                    for root, dirs, files in os.walk(report_dir):
                        for f in files:
                            fp = os.path.join(root, f)
                            deleted_size += os.path.getsize(fp)
                    
                    shutil.rmtree(report_dir)
            
            # Delete scan record
            scan.delete()
            deleted_count += 1
        
        logger.info(f"Cleaned up {deleted_count} old scans, freed {deleted_size / (1024*1024):.2f} MB")
        
        return {
            'status': 'success',
            'deleted_count': deleted_count,
            'deleted_size_mb': deleted_size / (1024*1024),
            'cutoff_date': cutoff_date.isoformat(),
        }
        
    except Exception as e:
        error_msg = f"Failed to cleanup old scans: {str(e)}"
        logger.exception(error_msg)
        return {'status': 'error', 'error': str(e)}

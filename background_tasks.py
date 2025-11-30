"""
Background tasks for monitoring scan status and updating database.
"""
import time
import os
import json
import psutil
from pathlib import Path
from datetime import datetime
from threading import Thread
from database import get_db_session
from models import Scan, ScanStatus


def generate_html_report_from_findings(job_id: str, findings_file: Path) -> str:
    """Generate simple HTML report from scanner_findings.json"""
    try:
        with open(findings_file, 'r') as f:
            data = json.load(f)
        
        results = data.get("results", [])
        
        # Group by severity
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for finding in results:
            severity = finding.get("severity", "info").lower()
            if severity not in by_severity:
                severity = "info"
            by_severity[severity].append(finding)
        
        # Count totals
        total = len(results)
        severity_counts = {k: len(v) for k, v in by_severity.items()}
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Scan Report - {job_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a1a; color: #e0e0e0; padding: 20px; }}
        .header {{ background: #2a2a2a; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .summary {{ display: flex; gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #2a2a2a; padding: 15px; border-radius: 6px; flex: 1; }}
        .finding {{ background: #2a2a2a; padding: 15px; margin: 10px 0; border-radius: 6px; border-left: 4px solid; }}
        .critical {{ border-color: #dc2626; }}
        .high {{ border-color: #ea580c; }}
        .medium {{ border-color: #f59e0b; }}
        .low {{ border-color: #10b981; }}
        .info {{ border-color: #3b82f6; }}
        .url {{ color: #60a5fa; word-break: break-all; }}
        h1, h2, h3 {{ color: #f3f4f6; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Security Scan Report</h1>
        <p><strong>Scan ID:</strong> {job_id}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="summary">
        <div class="stat-card">
            <h3>Total Findings</h3>
            <h2>{total}</h2>
        </div>
        <div class="stat-card" style="border-left: 3px solid #dc2626;">
            <h3>Critical</h3>
            <h2>{severity_counts['critical']}</h2>
        </div>
        <div class="stat-card" style="border-left: 3px solid #ea580c;">
            <h3>High</h3>
            <h2>{severity_counts['high']}</h2>
        </div>
        <div class="stat-card" style="border-left: 3px solid #f59e0b;">
            <h3>Medium</h3>
            <h2>{severity_counts['medium']}</h2>
        </div>
        <div class="stat-card" style="border-left: 3px solid #10b981;">
            <h3>Low</h3>
            <h2>{severity_counts['low']}</h2>
        </div>
    </div>
"""
        
        # Add findings by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if by_severity[severity]:
                html += f"\n    <h2>{severity.upper()} ({len(by_severity[severity])})</h2>\n"
                for finding in by_severity[severity]:
                    html += f"""
    <div class="finding {severity}">
        <h3>{finding.get('type', 'Unknown')}</h3>
        <p class="url">📍 {finding.get('url', 'N/A')}</p>
        <p>{finding.get('description', 'No description')}</p>
        <p><small><strong>Detector:</strong> {finding.get('detector', 'N/A')} | <strong>Confidence:</strong> {finding.get('confidence', 'unknown')}</small></p>
    </div>
"""
        
        html += """
</body>
</html>"""
        
        # Save HTML report
        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)
        report_path = report_dir / f"{job_id}_report.html"
        
        with open(report_path, 'w') as f:
            f.write(html)
        
        return str(report_path)
        
    except Exception as e:
        print(f"Error generating HTML report for {job_id}: {e}")
        return ""


def monitor_scan_status(job_id: str, pid: int):
    """
    Background thread to monitor scan process and update database.
    Checks if process is still running and updates status when complete.
    """
    def check_process():
        max_wait = 3600  # Max 1 hour
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                proc = psutil.Process(pid)
                if not proc.is_running():
                    # Process finished - update database with final progress
                    with get_db_session() as db:
                        scan = db.query(Scan).filter(Scan.job_id == job_id).first()
                        if scan and scan.status == ScanStatus.RUNNING:
                            # Read final progress from file
                            progress_file = os.path.join("scan_progress", f"{job_id}.json")
                            if os.path.exists(progress_file):
                                try:
                                    with open(progress_file, 'r') as f:
                                        progress_data = json.load(f)
                                    scan.total_urls = progress_data.get("total_urls", 0)
                                    scan.urls_scanned = progress_data.get("urls_scanned", 0)
                                    scan.progress_percentage = 100
                                    scan.vulnerabilities_found = progress_data.get("vulnerabilities_found", 0)
                                except Exception as e:
                                    print(f"Error reading progress file for {job_id}: {e}")
                            
                            # Generate HTML report from findings if available
                            if not scan.report_path:
                                # Try to find scanner_findings.json
                                recon_base = Path("recon_output")
                                base_job_id = job_id[:-1]  # Handle ±1 second timestamp
                                for pattern in [f"{job_id}*", f"{base_job_id}[0-9]*"]:
                                    for scan_dir in recon_base.glob(pattern):
                                        findings_file = None
                                        for json_file in scan_dir.rglob("*scanner_findings.json"):
                                            findings_file = json_file
                                            break
                                        
                                        if findings_file and findings_file.exists():
                                            report_path = generate_html_report_from_findings(job_id, findings_file)
                                            if report_path:
                                                scan.report_path = report_path
                                                print(f"✓ Generated HTML report: {report_path}")
                                            break
                                    
                                    if scan.report_path:
                                        break
                            
                            scan.status = ScanStatus.COMPLETED
                            scan.completed_at = datetime.now()
                            db.commit()
                            print(f"✓ Scan {job_id} marked as completed")
                    break
                time.sleep(5)  # Check every 5 seconds
            except psutil.NoSuchProcess:
                # Process already terminated
                with get_db_session() as db:
                    scan = db.query(Scan).filter(Scan.job_id == job_id).first()
                    if scan and scan.status == ScanStatus.RUNNING:
                        # Read final progress from file
                        progress_file = os.path.join("scan_progress", f"{job_id}.json")
                        if os.path.exists(progress_file):
                            try:
                                with open(progress_file, 'r') as f:
                                    progress_data = json.load(f)
                                scan.total_urls = progress_data.get("total_urls", 0)
                                scan.urls_scanned = progress_data.get("urls_scanned", 0)
                                scan.progress_percentage = 100
                                scan.vulnerabilities_found = progress_data.get("vulnerabilities_found", 0)
                            except Exception as e:
                                print(f"Error reading progress file for {job_id}: {e}")
                        
                        # Generate HTML report from findings if available
                        if not scan.report_path:
                            # Try to find scanner_findings.json
                            recon_base = Path("recon_output")
                            base_job_id = job_id[:-1]  # Handle ±1 second timestamp
                            for pattern in [f"{job_id}*", f"{base_job_id}[0-9]*"]:
                                for scan_dir in recon_base.glob(pattern):
                                    findings_file = None
                                    for json_file in scan_dir.rglob("*scanner_findings.json"):
                                        findings_file = json_file
                                        break
                                    
                                    if findings_file and findings_file.exists():
                                        report_path = generate_html_report_from_findings(job_id, findings_file)
                                        if report_path:
                                            scan.report_path = report_path
                                            print(f"✓ Generated HTML report: {report_path}")
                                        break
                                
                                if scan.report_path:
                                    break
                        
                        scan.status = ScanStatus.COMPLETED
                        scan.completed_at = datetime.now()
                        db.commit()
                        print(f"✓ Scan {job_id} marked as completed")
                break
            except Exception as e:
                print(f"Error monitoring scan {job_id}: {e}")
                time.sleep(10)
    
    thread = Thread(target=check_process, daemon=True)
    thread.start()


def parse_vulnerability_count(report_path: str) -> int:
    """
    Parse HTML report to count vulnerabilities.
    Looks for vulnerability sections in the report.
    """
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Count different vulnerability markers
        count = 0
        
        # Common patterns in reports
        patterns = [
            '🔴 CRITICAL',
            '🟠 HIGH',
            '🟡 MEDIUM',
            '⚠️ Potential',
            'Vulnerability:',
            'Finding:',
        ]
        
        for pattern in patterns:
            count += content.count(pattern)
        
        return count
    except Exception as e:
        print(f"Error parsing report {report_path}: {e}")
        return 0

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
    """Generate comprehensive HTML report from scanner_findings.json with detailed vulnerability information"""
    try:
        with open(findings_file, 'r') as f:
            data = json.load(f)
        
        results = data.get("results", [])
        scan_metadata = data.get("metadata", {})
        
        # Extract scan information from metadata
        target = scan_metadata.get("targets_scanned", ["N/A"])[0] if scan_metadata.get("targets_scanned") else "N/A"
        total_urls = scan_metadata.get("total_targets_scanned", "N/A")
        scan_duration = scan_metadata.get("duration", 0)
        scan_start = scan_metadata.get("start_time", "N/A")
        scan_end = scan_metadata.get("end_time", "N/A")
        
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
        
        # Remediation suggestions database
        remediation_db = {
            "XSS": {
                "description": "Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users.",
                "impact": "Attackers can steal session cookies, redirect users to malicious sites, or modify page content.",
                "remediation": [
                    "Sanitize and validate all user input before displaying it",
                    "Use Content Security Policy (CSP) headers",
                    "Encode output data (HTML entity encoding)",
                    "Use frameworks that auto-escape by default (React, Angular)",
                    "Implement HttpOnly and Secure flags on cookies"
                ]
            },
            "SQL Injection": {
                "description": "SQL Injection allows attackers to interfere with database queries by injecting malicious SQL code.",
                "impact": "Complete database compromise, data theft, data manipulation, or server takeover.",
                "remediation": [
                    "Always use parameterized queries (prepared statements)",
                    "Use ORM frameworks (SQLAlchemy, Django ORM)",
                    "Apply principle of least privilege for database accounts",
                    "Validate and sanitize all user inputs",
                    "Implement WAF rules to detect SQL injection attempts"
                ]
            },
            "SSRF": {
                "description": "Server-Side Request Forgery allows attackers to make the server perform requests to unintended locations.",
                "impact": "Access to internal services, cloud metadata endpoints (AWS, Azure), port scanning, and data exfiltration.",
                "remediation": [
                    "Validate and whitelist allowed URLs/IPs",
                    "Block requests to private IP ranges (RFC1918)",
                    "Use network segmentation",
                    "Disable URL redirects in HTTP libraries",
                    "Implement egress filtering"
                ]
            },
            "Command Injection": {
                "description": "Command Injection allows execution of arbitrary system commands on the server.",
                "impact": "Complete server compromise, data theft, malware installation, lateral movement.",
                "remediation": [
                    "Never pass user input directly to system commands",
                    "Use language-specific APIs instead of shell commands",
                    "Implement strict input validation with whitelists",
                    "Run services with minimal privileges",
                    "Use containerization and sandboxing"
                ]
            },
            "Missing Security Headers": {
                "description": "Security headers protect against various attacks by instructing browsers how to handle your site.",
                "impact": "Increased vulnerability to XSS, clickjacking, MIME sniffing, and man-in-the-middle attacks.",
                "remediation": [
                    "Implement Content-Security-Policy (CSP)",
                    "Add X-Frame-Options: DENY or SAMEORIGIN",
                    "Set X-Content-Type-Options: nosniff",
                    "Use Strict-Transport-Security (HSTS)",
                    "Add Referrer-Policy for privacy"
                ]
            },
            "Secret": {
                "description": "Exposed secrets (API keys, passwords, tokens) in code or responses pose severe security risks.",
                "impact": "Unauthorized access to services, data breaches, financial loss, account takeover.",
                "remediation": [
                    "Never hardcode secrets in source code",
                    "Use environment variables or secret management tools (Vault, AWS Secrets Manager)",
                    "Rotate exposed credentials immediately",
                    "Implement secret scanning in CI/CD pipelines",
                    "Use .gitignore to prevent committing sensitive files"
                ]
            }
        }
        
        # Generate HTML with enhanced styling
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Comprehensive Security Report - {job_id}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            padding: 30px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ 
            background: linear-gradient(135deg, #2a2a3e 0%, #1f2937 100%);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        .header h1 {{ 
            font-size: 2.5rem;
            margin-bottom: 15px;
            color: #60a5fa;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        .metadata {{ 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        .metadata-item {{ 
            background: rgba(0,0,0,0.2);
            padding: 10px 15px;
            border-radius: 6px;
        }}
        .metadata-label {{ 
            font-size: 0.85rem;
            color: #9ca3af;
            margin-bottom: 5px;
        }}
        .metadata-value {{ 
            font-size: 1.1rem;
            color: #f3f4f6;
            font-weight: 600;
        }}
        .summary {{ 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{ 
            background: linear-gradient(135deg, #2a2a3e 0%, #1f2937 100%);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-card h3 {{ 
            font-size: 0.9rem;
            color: #9ca3af;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stat-card h2 {{ 
            font-size: 2.5rem;
            font-weight: 700;
        }}
        .severity-section {{ margin: 40px 0; }}
        .severity-header {{ 
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 1.5rem;
            font-weight: 700;
        }}
        .critical-header {{ background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); }}
        .high-header {{ background: linear-gradient(135deg, #ea580c 0%, #c2410c 100%); }}
        .medium-header {{ background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }}
        .low-header {{ background: linear-gradient(135deg, #10b981 0%, #059669 100%); }}
        .info-header {{ background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); }}
        .finding {{ 
            background: #2a2a3e;
            padding: 25px;
            margin: 20px 0;
            border-radius: 10px;
            border-left: 5px solid;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }}
        .finding.critical {{ border-color: #dc2626; }}
        .finding.high {{ border-color: #ea580c; }}
        .finding.medium {{ border-color: #f59e0b; }}
        .finding.low {{ border-color: #10b981; }}
        .finding.info {{ border-color: #3b82f6; }}
        .finding-title {{ 
            font-size: 1.4rem;
            margin-bottom: 15px;
            color: #f3f4f6;
            font-weight: 600;
        }}
        .finding-section {{ 
            margin: 15px 0;
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 6px;
        }}
        .section-title {{ 
            font-size: 0.85rem;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
            font-weight: 600;
        }}
        .url {{ 
            color: #60a5fa;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 0.95rem;
            padding: 5px 0;
        }}
        .description {{ 
            color: #d1d5db;
            line-height: 1.8;
            margin: 10px 0;
        }}
        .detail-grid {{ 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }}
        .detail-item {{ 
            background: rgba(0,0,0,0.3);
            padding: 10px;
            border-radius: 4px;
        }}
        .detail-label {{ 
            font-size: 0.75rem;
            color: #9ca3af;
            text-transform: uppercase;
        }}
        .detail-value {{ 
            font-size: 0.95rem;
            color: #e5e7eb;
            margin-top: 5px;
            font-family: 'Courier New', monospace;
        }}
        .remediation {{ 
            background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
            border: 1px solid #374151;
        }}
        .remediation h4 {{ 
            color: #60a5fa;
            margin-bottom: 10px;
            font-size: 1.1rem;
        }}
        .remediation ul {{ 
            list-style: none;
            padding-left: 0;
        }}
        .remediation li {{ 
            padding: 8px 0 8px 25px;
            position: relative;
            color: #d1d5db;
        }}
        .remediation li:before {{ 
            content: "✓";
            position: absolute;
            left: 0;
            color: #10b981;
            font-weight: bold;
        }}
        .impact-badge {{ 
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            margin: 5px 5px 5px 0;
        }}
        .impact-critical {{ background: #dc2626; color: white; }}
        .impact-high {{ background: #ea580c; color: white; }}
        .impact-medium {{ background: #f59e0b; color: white; }}
        .impact-low {{ background: #10b981; color: white; }}
        .code-block {{ 
            background: #1f2937;
            padding: 15px;
            border-radius: 6px;
            border-left: 3px solid #60a5fa;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            color: #e5e7eb;
            margin: 10px 0;
        }}
        .confidence-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .confidence-high {{ background: #10b981; color: white; }}
        .confidence-medium {{ background: #f59e0b; color: white; }}
        .confidence-low {{ background: #6b7280; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Comprehensive Security Assessment Report</h1>
            <div class="metadata">
                <div class="metadata-item">
                    <div class="metadata-label">Scan ID</div>
                    <div class="metadata-value">{job_id}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Report Generated</div>
                    <div class="metadata-value">{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Scan Target</div>
                    <div class="metadata-value">{target}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">URLs Scanned</div>
                    <div class="metadata-value">{total_urls}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Scan Duration</div>
                    <div class="metadata-value">{round(scan_duration, 2)}s</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Scan Started</div>
                    <div class="metadata-value">{scan_start}</div>
                </div>
            </div>
        </div>
        
        <div class="summary">
            <div class="stat-card" style="border-top: 4px solid #60a5fa;">
                <h3>Total Findings</h3>
                <h2 style="color: #60a5fa;">{total}</h2>
            </div>
            <div class="stat-card" style="border-top: 4px solid #dc2626;">
                <h3>Critical</h3>
                <h2 style="color: #dc2626;">{severity_counts['critical']}</h2>
            </div>
            <div class="stat-card" style="border-top: 4px solid #ea580c;">
                <h3>High</h3>
                <h2 style="color: #ea580c;">{severity_counts['high']}</h2>
            </div>
            <div class="stat-card" style="border-top: 4px solid #f59e0b;">
                <h3>Medium</h3>
                <h2 style="color: #f59e0b;">{severity_counts['medium']}</h2>
            </div>
            <div class="stat-card" style="border-top: 4px solid #10b981;">
                <h3>Low</h3>
                <h2 style="color: #10b981;">{severity_counts['low']}</h2>
            </div>
        </div>
"""
        
        # Add detailed findings by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if by_severity[severity]:
                html += f"""
        <div class="severity-section">
            <div class="severity-header {severity}-header">
                {severity.upper()} SEVERITY FINDINGS ({len(by_severity[severity])})
            </div>
"""
                
                for idx, finding in enumerate(by_severity[severity], 1):
                    vuln_type = finding.get('type', 'Unknown Vulnerability')
                    url = finding.get('url', 'N/A')
                    description = finding.get('description', 'No description available')
                    detector = finding.get('detector', 'N/A')
                    confidence = finding.get('confidence', 'unknown')
                    payload = finding.get('payload', finding.get('evidence', ''))
                    method = finding.get('method', 'GET')
                    how_found = finding.get('how_found', 'N/A')
                    evidence_path = finding.get('evidence_path', '')
                    repro_command = finding.get('repro_command', '')
                    
                    # Get remediation info
                    remediation_info = None
                    for key in remediation_db:
                        if key.lower() in vuln_type.lower():
                            remediation_info = remediation_db[key]
                            break
                    
                    confidence_class = f"confidence-{confidence.lower()}" if confidence.lower() in ['high', 'medium', 'low'] else "confidence-low"
                    
                    html += f"""
            <div class="finding {severity}">
                <div class="finding-title">
                    #{idx}: {vuln_type}
                    <span class="{confidence_class} confidence-badge">{confidence.upper()} CONFIDENCE</span>
                </div>
                
                <div class="finding-section">
                    <div class="section-title">📍 Affected URL</div>
                    <div class="url">{url}</div>
                </div>
                
                <div class="finding-section">
                    <div class="section-title">📝 Description</div>
                    <div class="description">{description}</div>
                </div>
                
                <div class="finding-section">
                    <div class="section-title">🔍 How It Was Found</div>
                    <div class="description" style="color: #fbbf24;">{how_found}</div>
                </div>
                
                <div class="detail-grid">
                    <div class="detail-item">
                        <div class="detail-label">Detection Method</div>
                        <div class="detail-value">{detector}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">HTTP Method</div>
                        <div class="detail-value">{method}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Severity Level</div>
                        <div class="detail-value">{severity.upper()}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Confidence Score</div>
                        <div class="detail-value">{confidence.upper()}</div>
                    </div>
                </div>
"""
                    
                    # Add evidence path if available
                    if evidence_path:
                        html += f"""
                <div class="finding-section">
                    <div class="section-title">📂 Evidence Location</div>
                    <div class="code-block" style="font-size: 0.8rem;">{evidence_path}</div>
                </div>
"""
                    
                    if payload:
                        html += f"""
                <div class="finding-section">
                    <div class="section-title">🔬 Payload / Evidence</div>
                    <div class="code-block">{payload}</div>
                </div>
"""
                    
                    # Add reproduction command if available
                    if repro_command:
                        html += f"""
                <div class="finding-section">
                    <div class="section-title">🔄 Reproduction Command</div>
                    <div class="code-block" style="background: #0f172a; color: #22d3ee;">{repro_command}</div>
                </div>
"""
                    
                    if remediation_info:
                        html += f"""
                <div class="remediation">
                    <h4>🛡️ Security Impact</h4>
                    <p style="color: #d1d5db; margin-bottom: 15px;">{remediation_info['description']}</p>
                    <p style="color: #fca5a5; margin-bottom: 15px;"><strong>Potential Impact:</strong> {remediation_info['impact']}</p>
                    
                    <h4>✅ Remediation Steps</h4>
                    <ul>
"""
                        for step in remediation_info['remediation']:
                            html += f"                        <li>{step}</li>\n"
                        
                        html += """                    </ul>
                </div>
"""
                    
                    html += "            </div>\n"
                
                html += "        </div>\n"
        
        html += """
    </div>
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

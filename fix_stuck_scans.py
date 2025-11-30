#!/usr/bin/env python3
"""
Fix stuck scans that are marked as RUNNING but have actually completed.
Checks logs and progress files to update database with correct status.
"""
import os
import json
from datetime import datetime
from database import SessionLocal
from models import Scan, ScanStatus

def fix_stuck_scans():
    """Find and fix all scans stuck in RUNNING status."""
    db = SessionLocal()
    
    try:
        # Find all running scans
        running_scans = db.query(Scan).filter(Scan.status == ScanStatus.RUNNING).all()
        
        if not running_scans:
            print("✓ No stuck scans found")
            return
        
        print(f"Found {len(running_scans)} running scans, checking each...")
        print()
        
        for scan in running_scans:
            job_id = scan.job_id
            print(f"Checking scan: {job_id}")
            
            # Check log file for completion
            log_path = f"scan_logs/scan_{job_id}.log"
            if os.path.exists(log_path):
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    log_content = f.read()
                
                # Check if scan completed
                if "Full recon completed successfully" in log_content or "Scan completed" in log_content:
                    print(f"  → Log shows completion")
                    
                    # Try to find progress file (may be +1 second due to timing)
                    progress_file = None
                    base_job_id = job_id[:-1]  # Remove last digit
                    
                    for suffix in ['4', '5', '6', '7', '8', '9', '0', '1', '2', '3']:
                        test_file = f"scan_progress/{base_job_id}{suffix}.json"
                        if os.path.exists(test_file):
                            progress_file = test_file
                            print(f"  → Found progress file: {test_file}")
                            break
                    
                    # Parse log for findings count
                    findings_count = 0
                    urls_count = 0
                    
                    # Look for "Findings: X" in log
                    import re
                    findings_match = re.search(r'Findings:\s*(\d+)', log_content)
                    if findings_match:
                        findings_count = int(findings_match.group(1))
                    
                    # Look for "Scanned: X URLs" or "Live: X hosts"
                    urls_match = re.search(r'(?:Scanned|Live):\s*(\d+)\s+(?:URLs|hosts)', log_content)
                    if urls_match:
                        urls_count = int(urls_match.group(1))
                    
                    # If we found progress file, use its data
                    if progress_file:
                        try:
                            with open(progress_file, 'r') as f:
                                progress = json.load(f)
                            
                            scan.total_urls = progress.get("total_urls", urls_count)
                            scan.urls_scanned = progress.get("urls_scanned", urls_count)
                            scan.vulnerabilities_found = progress.get("vulnerabilities_found", findings_count)
                        except Exception as e:
                            print(f"  ⚠️  Could not read progress file: {e}")
                            scan.total_urls = urls_count
                            scan.urls_scanned = urls_count
                            scan.vulnerabilities_found = findings_count
                    else:
                        print(f"  → Using data from log")
                        scan.total_urls = urls_count
                        scan.urls_scanned = urls_count
                        scan.vulnerabilities_found = findings_count
                    
                    scan.progress_percentage = 100
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.now()
                    db.commit()
                    
                    print(f"  ✓ Updated to COMPLETED")
                    print(f"    Progress: {scan.progress_percentage}%")
                    print(f"    URLs: {scan.urls_scanned}/{scan.total_urls}")
                    print(f"    Findings: {scan.vulnerabilities_found}")
                else:
                    print(f"  → Scan appears to be genuinely running")
            else:
                print(f"  → No log file found yet")
            
            print()
    
    finally:
        db.close()

if __name__ == "__main__":
    print("=" * 60)
    print("Fixing Stuck Scans")
    print("=" * 60)
    print()
    fix_stuck_scans()
    print("=" * 60)
    print("Done!")

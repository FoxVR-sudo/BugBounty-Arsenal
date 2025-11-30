#!/usr/bin/env python3
"""
Fix stuck scans that are marked as RUNNING but have actually completed.
Checks logs and progress files to update database with correct status.
Handles timestamp variations (±1 second) between database and filesystem.
"""
import os
import json
import re
from datetime import datetime
from database import SessionLocal
from models import Scan, ScanStatus

def fix_stuck_scans():
    """Find and fix all scans stuck in RUNNING status."""
    db = SessionLocal()
    
    try:
        # Find all running/failed scans
        stuck_scans = db.query(Scan).filter(
            Scan.status.in_([ScanStatus.RUNNING, ScanStatus.FAILED])
        ).all()
        
        if not stuck_scans:
            print("✓ No stuck scans found")
            return
        
        print(f"Found {len(stuck_scans)} stuck scans, checking each...")
        print()
        
        for scan in stuck_scans:
            job_id = scan.job_id
            print(f"Checking scan: {job_id}")
            
            # Check log file for completion
            log_path = f"scan_logs/scan_{job_id}.log"
            if not os.path.exists(log_path):
                print(f"  ⚠️  No log file found")
                continue
            
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
            
            # Check if scan completed
            if "Full recon completed successfully" not in log_content and "Scan completed" not in log_content:
                print(f"  → Scan appears to be genuinely running")
                continue
            
            print(f"  ✓ Log shows completion")
            
            # Find actual output directory (may have ±1 second timestamp difference)
            base_job_id = job_id[:-1]  # Remove last digit
            found_dir = None
            
            # Try finding recon output with nearby timestamps (0-9)
            for i in range(10):
                test_id = base_job_id + str(i)
                # Try both with and without target suffix
                for target_suffix in ['_httpbin.org', '_' + scan.target.replace('/', '_'), '']:
                    test_dir = f"recon_output/{test_id}{target_suffix}"
                    if os.path.exists(test_dir):
                        found_dir = test_dir
                        print(f"  ✓ Found output: {test_id}{target_suffix}")
                        break
                if found_dir:
                    break
            
            # Parse findings and URLs from log
            findings_match = re.search(r'Findings:\s*(\d+)', log_content)
            findings_count = int(findings_match.group(1)) if findings_match else 0
            
            urls_match = re.search(r'(?:Scanned|Live):\s*(\d+)\s+(?:URLs|hosts)', log_content)
            urls_count = int(urls_match.group(1)) if urls_match else 0
            
            # Update database
            scan.status = ScanStatus.COMPLETED
            scan.progress_percentage = 100
            scan.total_urls = urls_count if urls_count > 0 else scan.total_urls
            scan.urls_scanned = urls_count if urls_count > 0 else scan.urls_scanned
            scan.vulnerabilities_found = findings_count
            scan.completed_at = datetime.now()
            db.commit()
            
            print(f"  ✅ FIXED!")
            print(f"     Status: COMPLETED")
            print(f"     Progress: 100%")
            print(f"     URLs: {scan.urls_scanned}/{scan.total_urls}")
            print(f"     Findings: {scan.vulnerabilities_found}")
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


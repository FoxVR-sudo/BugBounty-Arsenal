#!/usr/bin/env python3
"""
Test script to simulate scan progress for demo purposes
"""
import os
import django
import time
import json
from datetime import datetime

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from scans.models import Scan
from users.models import User

def create_demo_scan():
    """Create a demo scan with progress updates"""
    # Get first user
    user = User.objects.first()
    if not user:
        print("No users found")
        return
    
    # Create scan
    scan = Scan.objects.create(
        user=user,
        target="https://demo.testfire.net",
        scan_type="web_security",
        status="running",
        raw_results="{}",  # Initialize raw_results
        results={}
    )
    
    print(f"Created scan {scan.id} for {scan.target}")
    
    # Simulate progress
    detectors = [
        "XSS Pattern Detection",
        "SQL Injection Testing",
        "CSRF Token Analysis",
        "Security Headers Check",
        "SSRF Detection",
        "LFI/RFI Testing",
        "Command Injection",
        "IDOR Testing",
        "JWT Analyzer",
        "GraphQL Security",
        "XXE Testing",
        "SSTI Detection"
    ]
    
    vulnerabilities = []
    
    for i, detector in enumerate(detectors):
        # Update progress
        progress = int((i + 1) / len(detectors) * 100)
        scan.progress = progress
        
        # Simulate finding vulnerabilities
        if i % 3 == 0:  # Every 3rd detector finds something
            vuln = {
                "type": detector.lower().replace(" ", "_"),
                "title": f"Potential {detector} Vulnerability",
                "severity": ["high", "medium", "low"][i % 3],
                "description": f"Found potential security issue in {detector}",
                "url": f"{scan.target}/test/{i}",
                "payload": f"test_payload_{i}"
            }
            vulnerabilities.append(vuln)
        
        scan.vulnerabilities_found = len(vulnerabilities)
        scan.results = {"vulnerabilities": vulnerabilities}
        scan.save()
        
        print(f"[{progress}%] Running: {detector}")
        time.sleep(2)  # Simulate work
    
    # Mark as completed
    scan.status = "completed"
    scan.completed_at = datetime.now()
    scan.save()
    
    print(f"\n✅ Scan completed! Found {len(vulnerabilities)} vulnerabilities")
    print(f"Scan ID: {scan.id}")
    return scan

if __name__ == "__main__":
    scan = create_demo_scan()

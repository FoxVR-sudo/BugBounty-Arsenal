#!/usr/bin/env python3
"""
Manual Bug Hunting Assistant with Screenshot Evidence 📸
Helps with manual testing and automatic evidence collection

Features:
- Guided manual testing workflows
- Automatic screenshot capture using Linux Mint screenshot tool
- Evidence organization
- PoC report generation with screenshots
- Safe, manual approach - you control everything
"""

import subprocess
import time
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

class ManualBugHunter:
    """
    Assistant for manual bug hunting with evidence collection
    """
    
    def __init__(self, target: str, output_dir: str = "bug_evidence"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.evidence_items = []
        self.screenshots_dir = self.output_dir / "screenshots"
        self.screenshots_dir.mkdir(exist_ok=True)
        
        print(f"\n📸 Manual Bug Hunting Assistant")
        print(f"Target: {target}")
        print(f"Evidence: {output_dir}")
        print("=" * 70)
    
    def start_hunt(self):
        """Start guided bug hunting session"""
        print("\n🎯 Bug Hunting Workflows Available:")
        print("1. IDOR Testing")
        print("2. XSS Testing")
        print("3. SQL Injection Testing")
        print("4. Authentication Testing")
        print("5. API Security Testing")
        print("6. Custom Manual Test")
        print("0. Exit")
        
        while True:
            choice = input("\n👉 Select workflow (0-6): ").strip()
            
            if choice == "0":
                break
            elif choice == "1":
                self.idor_workflow()
            elif choice == "2":
                self.xss_workflow()
            elif choice == "3":
                self.sqli_workflow()
            elif choice == "4":
                self.auth_workflow()
            elif choice == "5":
                self.api_workflow()
            elif choice == "6":
                self.custom_workflow()
            else:
                print("❌ Invalid choice")
        
        self.generate_final_report()
    
    def idor_workflow(self):
        """Guided IDOR testing workflow"""
        print("\n" + "=" * 70)
        print("🔍 IDOR Testing Workflow")
        print("=" * 70)
        
        print("\n📋 Steps:")
        print("1. Login to your test account")
        print("2. Navigate to your profile/data endpoint")
        print("3. Note your user ID in the URL")
        print("4. Try changing ID to another user's")
        print("5. Take screenshots of both requests")
        
        input("\n⏸️  Press Enter when you've logged in...")
        
        # Get user's own ID
        own_id = input("📝 Your user ID: ").strip()
        own_url = input("📝 Your profile URL: ").strip()
        
        print(f"\n✅ Recorded your data:")
        print(f"   ID: {own_id}")
        print(f"   URL: {own_url}")
        
        self.take_screenshot("idor_own_profile", 
                           "Screenshot of your own profile (authorized access)")
        
        # Test IDOR
        print(f"\n🔬 Now try accessing another user:")
        test_id = input("📝 Test user ID to try: ").strip()
        test_url = own_url.replace(own_id, test_id)
        
        print(f"\n👉 Test URL: {test_url}")
        print("📌 Copy this URL to browser and press Enter")
        
        input("\n⏸️  Press Enter after testing...")
        
        result = input("❓ Did you see unauthorized data? (yes/no): ").strip().lower()
        
        if result == "yes":
            print("\n💀 IDOR CONFIRMED!")
            self.take_screenshot("idor_unauthorized_access",
                               f"Unauthorized access to user {test_id}")
            
            # Collect details
            sensitive_data = input("📝 What sensitive data did you see? ").strip()
            
            self.add_evidence(
                vuln_type="IDOR",
                severity="HIGH",
                title="Insecure Direct Object Reference",
                description=f"Can access user {test_id}'s data by changing ID parameter",
                steps=[
                    f"1. Login as user {own_id}",
                    f"2. Access {own_url}",
                    f"3. Change ID to {test_id}: {test_url}",
                    f"4. Observe unauthorized access to: {sensitive_data}"
                ],
                impact="Any user can access other users' private data",
                screenshots=["idor_own_profile.png", "idor_unauthorized_access.png"]
            )
            
            print("✅ Evidence recorded!")
        else:
            print("✅ No IDOR found (app is secure)")
    
    def xss_workflow(self):
        """Guided XSS testing workflow"""
        print("\n" + "=" * 70)
        print("🔍 XSS Testing Workflow")
        print("=" * 70)
        
        print("\n📋 Steps:")
        print("1. Find input field (search, comment, profile)")
        print("2. Try simple payload: <script>alert('XSS')</script>")
        print("3. Submit and check if executed")
        print("4. Take screenshot if successful")
        
        input("\n⏸️  Press Enter when ready...")
        
        endpoint = input("📝 Where are you testing? (e.g., /search, /comment): ").strip()
        payload = input("📝 Payload you're trying: ").strip()
        
        print(f"\n👉 Testing: {endpoint}")
        print(f"👉 Payload: {payload}")
        print("\n📌 Submit the payload and check browser")
        
        input("\n⏸️  Press Enter after testing...")
        
        result = input("❓ Did alert() execute? (yes/no): ").strip().lower()
        
        if result == "yes":
            print("\n💀 XSS CONFIRMED!")
            self.take_screenshot("xss_alert_executed",
                               f"XSS payload executed at {endpoint}")
            
            self.add_evidence(
                vuln_type="XSS",
                severity="HIGH",
                title="Reflected Cross-Site Scripting",
                description=f"XSS vulnerability in {endpoint}",
                steps=[
                    f"1. Navigate to {endpoint}",
                    f"2. Input payload: {payload}",
                    f"3. Submit form",
                    f"4. Alert executed in browser"
                ],
                impact="Session hijacking, credential theft, malicious redirects",
                screenshots=["xss_alert_executed.png"]
            )
            
            print("✅ Evidence recorded!")
        else:
            print("✅ No XSS found (input is sanitized)")
    
    def sqli_workflow(self):
        """Guided SQL Injection testing workflow"""
        print("\n" + "=" * 70)
        print("🔍 SQL Injection Testing Workflow")
        print("=" * 70)
        
        print("\n📋 Steps:")
        print("1. Find parameter (id, search, filter)")
        print("2. Try: ' OR '1'='1")
        print("3. Check for error messages or unexpected data")
        print("4. Take screenshots")
        
        input("\n⏸️  Press Enter when ready...")
        
        param = input("📝 Parameter name: ").strip()
        url = input("📝 Full URL: ").strip()
        
        print(f"\n👉 Try adding: ' OR '1'='1")
        print(f"👉 Full URL: {url}")
        
        input("\n⏸️  Press Enter after testing...")
        
        result = input("❓ See SQL error or unexpected data? (yes/no): ").strip().lower()
        
        if result == "yes":
            print("\n💀 SQL INJECTION CONFIRMED!")
            self.take_screenshot("sqli_error",
                               "SQL error message or unexpected data")
            
            error_msg = input("📝 Error message (if any): ").strip()
            
            self.add_evidence(
                vuln_type="SQLi",
                severity="CRITICAL",
                title="SQL Injection Vulnerability",
                description=f"SQL injection in parameter '{param}'",
                steps=[
                    f"1. Navigate to {url}",
                    f"2. Inject payload: ' OR '1'='1",
                    f"3. Observe error: {error_msg}",
                ],
                impact="Database compromise, data theft, authentication bypass",
                screenshots=["sqli_error.png"]
            )
            
            print("✅ Evidence recorded!")
        else:
            print("✅ No SQLi found (parameterized queries)")
    
    def auth_workflow(self):
        """Authentication testing workflow"""
        print("\n" + "=" * 70)
        print("🔍 Authentication Testing Workflow")
        print("=" * 70)
        
        print("\n📋 Test cases:")
        print("1. Brute force protection")
        print("2. Password reset flow")
        print("3. Session fixation")
        print("4. Logout functionality")
        
        test_type = input("👉 Which test? (1-4): ").strip()
        
        if test_type == "1":
            print("\n🔬 Testing brute force protection...")
            print("Try 10+ wrong passwords and check if account locks")
            
            input("\n⏸️  Press Enter after testing...")
            
            locked = input("❓ Account locked or rate limited? (yes/no): ").strip().lower()
            
            if locked == "no":
                print("\n⚠️ WEAK BRUTE FORCE PROTECTION!")
                self.take_screenshot("no_rate_limit",
                                   "Multiple failed attempts without blocking")
                
                self.add_evidence(
                    vuln_type="Auth",
                    severity="MEDIUM",
                    title="No Brute Force Protection",
                    description="Account allows unlimited login attempts",
                    steps=[
                        "1. Try wrong password 10+ times",
                        "2. No rate limiting observed",
                        "3. No account lockout"
                    ],
                    impact="Brute force attacks, credential stuffing",
                    screenshots=["no_rate_limit.png"]
                )
                
                print("✅ Evidence recorded!")
        
        # Add more auth tests...
    
    def api_workflow(self):
        """API testing workflow"""
        print("\n" + "=" * 70)
        print("🔍 API Security Testing Workflow")
        print("=" * 70)
        
        print("\n📋 Steps:")
        print("1. Open browser DevTools (F12)")
        print("2. Go to Network tab")
        print("3. Perform action (login, search, etc)")
        print("4. Find API calls")
        print("5. Copy as cURL")
        
        input("\n⏸️  Press Enter when you have API call...")
        
        endpoint = input("📝 API endpoint: ").strip()
        method = input("📝 HTTP method (GET/POST): ").strip()
        
        print("\n🔬 Security checks:")
        print("1. Remove authentication header and retry")
        print("2. Change user ID in request")
        print("3. Try different HTTP methods")
        
        self.take_screenshot("api_request",
                           f"API call: {method} {endpoint}")
        
        finding = input("\n❓ Found security issue? (yes/no): ").strip().lower()
        
        if finding == "yes":
            issue_desc = input("📝 Describe the issue: ").strip()
            
            self.take_screenshot("api_vulnerability",
                               "API security issue demonstrated")
            
            self.add_evidence(
                vuln_type="API",
                severity="HIGH",
                title="API Security Issue",
                description=issue_desc,
                steps=[
                    f"1. Call API: {method} {endpoint}",
                    "2. See screenshot for details"
                ],
                impact="Depends on specific API vulnerability",
                screenshots=["api_request.png", "api_vulnerability.png"]
            )
            
            print("✅ Evidence recorded!")
    
    def custom_workflow(self):
        """Custom manual test"""
        print("\n" + "=" * 70)
        print("🔍 Custom Manual Test")
        print("=" * 70)
        
        vuln_type = input("📝 Vulnerability type: ").strip()
        title = input("📝 Finding title: ").strip()
        description = input("📝 Description: ").strip()
        
        print("\n📸 Taking screenshots...")
        print("Take as many screenshots as needed")
        print("Type 'done' when finished")
        
        screenshots = []
        i = 1
        while True:
            cmd = input(f"\nScreenshot #{i} name (or 'done'): ").strip()
            if cmd.lower() == 'done':
                break
            
            self.take_screenshot(cmd, f"Evidence screenshot {i}")
            screenshots.append(f"{cmd}.png")
            i += 1
        
        severity = input("\n📝 Severity (LOW/MEDIUM/HIGH/CRITICAL): ").strip().upper()
        impact = input("📝 Security impact: ").strip()
        
        self.add_evidence(
            vuln_type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            steps=["See screenshots for reproduction"],
            impact=impact,
            screenshots=screenshots
        )
        
        print("✅ Evidence recorded!")
    
    def take_screenshot(self, name: str, description: str):
        """Take screenshot using Linux Mint screenshot tool"""
        filename = f"{name}.png"
        filepath = self.screenshots_dir / filename
        
        print(f"\n📸 Taking screenshot: {name}")
        print("⏰ You have 3 seconds to focus the window...")
        time.sleep(3)
        
        # Use gnome-screenshot (Linux Mint default)
        try:
            subprocess.run([
                'gnome-screenshot',
                '-f', str(filepath)
            ], check=True)
            
            print(f"✅ Screenshot saved: {filename}")
            return str(filepath)
        
        except FileNotFoundError:
            # Try xfce4-screenshooter (alternative)
            try:
                subprocess.run([
                    'xfce4-screenshooter',
                    '-f', '-s', str(filepath)
                ], check=True)
                print(f"✅ Screenshot saved: {filename}")
                return str(filepath)
            except:
                print(f"❌ Screenshot tool not found")
                print("   Manual: Press PrtScn and save as {filename}")
                return None
    
    def add_evidence(self, vuln_type: str, severity: str, title: str,
                    description: str, steps: List[str], impact: str,
                    screenshots: List[str]):
        """Add evidence item"""
        self.evidence_items.append({
            "vuln_type": vuln_type,
            "severity": severity,
            "title": title,
            "description": description,
            "steps_to_reproduce": steps,
            "impact": impact,
            "screenshots": screenshots,
            "timestamp": datetime.now().isoformat()
        })
    
    def generate_final_report(self):
        """Generate final HackerOne report"""
        if not self.evidence_items:
            print("\n⚠️  No evidence collected")
            return
        
        print("\n" + "=" * 70)
        print("📝 Generating HackerOne Report")
        print("=" * 70)
        
        # Save JSON
        json_file = self.output_dir / "evidence.json"
        with open(json_file, 'w') as f:
            json.dump({
                "target": self.target,
                "findings": self.evidence_items,
                "total": len(self.evidence_items)
            }, f, indent=2)
        
        # Generate markdown report
        md_file = self.output_dir / "HACKERONE_SUBMISSION.md"
        self._generate_markdown_report(md_file)
        
        print(f"\n✅ Report generated!")
        print(f"📄 Markdown: {md_file}")
        print(f"📸 Screenshots: {self.screenshots_dir}/")
        print(f"\n🎯 Ready to submit to HackerOne!")
    
    def _generate_markdown_report(self, output_file: Path):
        """Generate markdown report"""
        md = f"""# Bug Bounty Report - {self.target}

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  
**Total Findings:** {len(self.evidence_items)}

---

"""
        
        for i, evidence in enumerate(self.evidence_items, 1):
            md += f"""## Finding #{i}: {evidence['title']}

**Vulnerability Type:** {evidence['vuln_type']}  
**Severity:** {evidence['severity']}

### Description

{evidence['description']}

### Steps to Reproduce

"""
            
            for step in evidence['steps_to_reproduce']:
                md += f"{step}\n"
            
            md += f"""
### Impact

{evidence['impact']}

### Screenshots

"""
            
            for screenshot in evidence['screenshots']:
                md += f"![Evidence]({screenshot})\n\n"
            
            md += "---\n\n"
        
        md += """
## Summary

All findings have been manually verified with screenshot evidence.
Each vulnerability is reproducible following the steps provided.

Ready for submission to HackerOne bug bounty program.

---

**Generated by Manual Bug Hunting Assistant 📸**
"""
        
        output_file.write_text(md)


def main():
    """Main entry point"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python manual_hunter.py <target>")
        print("\nExample: python manual_hunter.py https://www.syfe.com")
        print("\n📸 Manual testing with screenshot evidence collection")
        sys.exit(1)
    
    target = sys.argv[1]
    
    hunter = ManualBugHunter(target)
    hunter.start_hunt()


if __name__ == "__main__":
    main()

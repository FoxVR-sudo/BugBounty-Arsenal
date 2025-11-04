#!/usr/bin/env python3
"""
SAFE Reconnaissance Mode 🔍
Passive information gathering without exploitation

This is a SAFE version that only performs:
- Public endpoint discovery
- Security header analysis
- Technology fingerprinting
- No exploitation attempts
- No data extraction

Safe for initial reconnaissance on any target
"""

import asyncio
import aiohttp
from aiohttp import ClientTimeout
import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

class SafeReconScanner:
    """
    Safe reconnaissance scanner - no exploitation
    Only passive information gathering
    """
    
    def __init__(self, target_url: str, output_dir: str = "recon_results"):
        self.target_url = target_url.rstrip('/')
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.findings = []
        
        print(f"\n🔍 SAFE MODE - Passive Reconnaissance")
        print(f"Target: {target_url}")
        print(f"Output: {output_dir}")
        print("=" * 70)
        print("✅ Safe mode: No exploitation, only public information gathering")
        print("=" * 70)
    
    async def scan(self):
        """Run safe reconnaissance"""
        print("\n[*] Starting safe reconnaissance...")
        
        timeout = ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            await asyncio.gather(
                self.check_security_headers(session),
                self.discover_endpoints(session),
                self.check_technologies(session),
                self.check_robots_txt(session),
                self.check_sitemap(session),
                return_exceptions=True
            )
        
        # Generate report
        await self.generate_report()
        
        print(f"\n✅ Reconnaissance complete!")
        print(f"📊 Findings: {len(self.findings)}")
        print(f"📁 Report: {self.output_dir}/recon_report.md")
    
    async def check_security_headers(self, session: aiohttp.ClientSession):
        """Check security headers (passive)"""
        print(f"\n[1/5] Checking security headers...")
        
        try:
            async with session.get(self.target_url) as response:
                headers = response.headers
                
                # Check for missing security headers
                security_headers = {
                    'Strict-Transport-Security': 'HSTS',
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': 'Clickjacking protection',
                    'Content-Security-Policy': 'CSP',
                    'X-XSS-Protection': 'XSS filter',
                    'Referrer-Policy': 'Referrer control'
                }
                
                missing = []
                present = []
                
                for header, description in security_headers.items():
                    if header not in headers:
                        missing.append(f"{header} ({description})")
                    else:
                        present.append(f"{header}: {headers[header][:50]}")
                
                if missing:
                    self.add_finding(
                        "Missing Security Headers",
                        "MEDIUM",
                        f"Missing {len(missing)} security headers: {', '.join(missing)}",
                        {"missing": missing, "present": present}
                    )
                    print(f"   ⚠️  Missing {len(missing)} security headers")
                else:
                    print(f"   ✅ All security headers present")
                
                # Check server header
                if 'Server' in headers:
                    server = headers['Server']
                    self.add_finding(
                        "Server Header Disclosure",
                        "INFO",
                        f"Server header reveals: {server}",
                        {"server": server}
                    )
                    print(f"   ℹ️  Server: {server}")
        
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    async def discover_endpoints(self, session: aiohttp.ClientSession):
        """Discover common public endpoints"""
        print(f"\n[2/5] Discovering public endpoints...")
        
        # Safe, common public endpoints
        common_endpoints = [
            '/.well-known/security.txt',
            '/robots.txt',
            '/sitemap.xml',
            '/api/health',
            '/api/status',
            '/api/version',
            '/health',
            '/status',
            '/ping'
        ]
        
        discovered = []
        
        for endpoint in common_endpoints:
            url = f"{self.target_url}{endpoint}"
            try:
                async with session.get(url) as response:
                    if response.status == 200:
                        discovered.append({
                            "endpoint": endpoint,
                            "status": response.status,
                            "content_type": response.headers.get('Content-Type', 'unknown')
                        })
                        print(f"   ✅ Found: {endpoint}")
            except:
                pass
        
        if discovered:
            self.add_finding(
                "Public Endpoints Discovered",
                "INFO",
                f"Found {len(discovered)} public endpoints",
                {"endpoints": discovered}
            )
    
    async def check_technologies(self, session: aiohttp.ClientSession):
        """Fingerprint technologies (passive)"""
        print(f"\n[3/5] Fingerprinting technologies...")
        
        try:
            async with session.get(self.target_url) as response:
                headers = response.headers
                html = await response.text()
                
                technologies = []
                
                # Check headers for tech indicators
                if 'X-Powered-By' in headers:
                    technologies.append(f"Powered by: {headers['X-Powered-By']}")
                
                # Check HTML for framework indicators
                frameworks = {
                    'React': ['react', '_react', 'reactroot'],
                    'Angular': ['ng-', 'angular'],
                    'Vue': ['vue', 'v-'],
                    'Next.js': ['next', '__next'],
                    'WordPress': ['wp-content', 'wordpress'],
                    'Django': ['csrfmiddlewaretoken'],
                }
                
                html_lower = html.lower()
                for framework, indicators in frameworks.items():
                    if any(indicator in html_lower for indicator in indicators):
                        technologies.append(framework)
                
                if technologies:
                    self.add_finding(
                        "Technology Stack",
                        "INFO",
                        f"Detected: {', '.join(technologies)}",
                        {"technologies": technologies}
                    )
                    print(f"   ✅ Technologies: {', '.join(technologies)}")
                else:
                    print(f"   ℹ️  No obvious technology indicators")
        
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    async def check_robots_txt(self, session: aiohttp.ClientSession):
        """Check robots.txt for interesting paths"""
        print(f"\n[4/5] Checking robots.txt...")
        
        try:
            async with session.get(f"{self.target_url}/robots.txt") as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Extract disallowed paths
                    disallowed = [line.split(':')[1].strip() 
                                for line in content.split('\n') 
                                if line.strip().startswith('Disallow:')]
                    
                    if disallowed:
                        self.add_finding(
                            "Robots.txt Analysis",
                            "INFO",
                            f"Found {len(disallowed)} disallowed paths",
                            {"disallowed_paths": disallowed[:10]}  # First 10
                        )
                        print(f"   ✅ Found {len(disallowed)} disallowed paths")
                    else:
                        print(f"   ℹ️  Robots.txt exists but no disallowed paths")
                else:
                    print(f"   ℹ️  No robots.txt found")
        
        except Exception as e:
            print(f"   ℹ️  No robots.txt")
    
    async def check_sitemap(self, session: aiohttp.ClientSession):
        """Check sitemap.xml"""
        print(f"\n[5/5] Checking sitemap.xml...")
        
        try:
            async with session.get(f"{self.target_url}/sitemap.xml") as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Count URLs in sitemap
                    url_count = content.count('<loc>')
                    
                    self.add_finding(
                        "Sitemap Available",
                        "INFO",
                        f"Sitemap contains ~{url_count} URLs",
                        {"url_count": url_count}
                    )
                    print(f"   ✅ Sitemap found with ~{url_count} URLs")
                else:
                    print(f"   ℹ️  No sitemap.xml found")
        
        except Exception as e:
            print(f"   ℹ️  No sitemap.xml")
    
    def add_finding(self, title: str, severity: str, description: str, evidence: Dict):
        """Add a finding"""
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        })
    
    async def generate_report(self):
        """Generate reconnaissance report"""
        print("\n[*] Generating report...")
        
        report = {
            "target": self.target_url,
            "scan_date": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": self.findings
        }
        
        # Save JSON
        json_file = self.output_dir / "recon_report.json"
        json_file.write_text(json.dumps(report, indent=2))
        
        # Generate markdown
        md_file = self.output_dir / "recon_report.md"
        self._generate_markdown(report, md_file)
        
        print(f"✅ Reports saved")
    
    def _generate_markdown(self, report: Dict, output_file: Path):
        """Generate markdown report"""
        md = f"""# Reconnaissance Report - {report['target']}

**Scan Date:** {report['scan_date']}  
**Total Findings:** {report['total_findings']}

---

"""
        
        for i, finding in enumerate(report['findings'], 1):
            md += f"""## {i}. {finding['title']}

**Severity:** {finding['severity']}  
**Description:** {finding['description']}

### Evidence

```json
{json.dumps(finding['evidence'], indent=2)}
```

---

"""
        
        md += """
## Summary

This is a **passive reconnaissance report** with no exploitation attempts.
All information gathered is publicly accessible.

Next steps:
1. Review findings for potential security issues
2. If authorized, proceed with deeper testing
3. Follow responsible disclosure for any vulnerabilities

---

**Generated by BugBounty-Arsenal Safe Recon Mode 🔍**
"""
        
        output_file.write_text(md)


async def main():
    """Main entry point"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python safe_recon.py <target_url>")
        print("\nExample: python safe_recon.py https://example.com")
        print("\n✅ Safe mode: No exploitation, only public info gathering")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    scanner = SafeReconScanner(target_url)
    await scanner.scan()


if __name__ == "__main__":
    asyncio.run(main())

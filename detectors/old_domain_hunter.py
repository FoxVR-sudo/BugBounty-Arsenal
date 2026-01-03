"""
Old Domain & Abandoned Systems Hunter
Discovers forgotten old domains, acquisitions, and abandoned admin panels
"""
import requests
import re
from typing import Dict, List, Any
import time


class OldDomainHunter:
    """
    Hunts for old and forgotten systems:
    - Old company domains (company-old.com)
    - Acquired company domains
    - Development/staging environments
    - Forgotten admin panels
    - Legacy systems
    """
    
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.base_domain = self.extract_base_domain(target)
        self.findings = []
        
        # Old domain patterns
        self.old_patterns = [
            'old-{domain}',
            '{domain}-old',
            'legacy-{domain}',
            '{domain}-legacy',
            'archive-{domain}',
            '{domain}-archive',
            'backup-{domain}',
            '{domain}-backup',
            'v1-{domain}',
            'v2-{domain}',
            '{domain}-v1',
            '{domain}-v2',
        ]
        
        # Development/staging patterns
        self.dev_patterns = [
            'dev-{domain}',
            '{domain}-dev',
            'development-{domain}',
            'staging-{domain}',
            '{domain}-staging',
            'test-{domain}',
            '{domain}-test',
            'demo-{domain}',
            '{domain}-demo',
            'sandbox-{domain}',
        ]
        
        # Old admin panel paths
        self.old_admin_paths = [
            '/admin-old',
            '/admin.old',
            '/admin_old',
            '/old-admin',
            '/legacy-admin',
            '/admin-backup',
            '/adminpanel-old',
            '/wp-admin-old',
            '/administrator-old',
            '/manage-old',
            '/control-old',
            '/cpanel-old',
        ]
        
    def run(self) -> Dict[str, Any]:
        """Main execution method"""
        try:
            # Check old domain variations
            self.check_old_domains()
            
            # Check development domains
            self.check_dev_domains()
            
            # Check old admin panels on current domain
            self.check_old_admin_panels()
            
            # Check common old URLs
            self.check_old_urls()
            
            return {
                'vulnerable': len(self.findings) > 0,
                'severity': self.calculate_severity(),
                'findings': self.findings,
                'domains_checked': len(self.old_patterns) + len(self.dev_patterns),
                'details': {
                    'old_domains': [f for f in self.findings if f['type'] == 'old_domain'],
                    'dev_environments': [f for f in self.findings if f['type'] == 'dev_environment'],
                    'old_admin_panels': [f for f in self.findings if f['type'] == 'old_admin'],
                    'legacy_systems': [f for f in self.findings if f['type'] == 'legacy_system'],
                }
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'findings': []
            }
    
    def extract_base_domain(self, url: str) -> str:
        """Extract base domain from URL"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        # Remove www. if present
        domain = domain.replace('www.', '')
        # Get domain without TLD for pattern matching
        parts = domain.split('.')
        if len(parts) >= 2:
            return parts[0]
        return domain
    
    def check_old_domains(self):
        """Check for old domain variations"""
        for pattern in self.old_patterns[:8]:  # Limit to 8 patterns
            test_domain = pattern.replace('{domain}', self.base_domain)
            
            # Try with common TLDs
            for tld in ['.com', '.net', '.org']:
                url = f"http://{test_domain}{tld}"
                
                if self.check_domain_exists(url):
                    self.findings.append({
                        'type': 'old_domain',
                        'severity': 'high',
                        'url': url,
                        'domain': f"{test_domain}{tld}",
                        'description': f'Old/archived domain found: {test_domain}{tld}',
                        'risk': 'May contain outdated vulnerable systems or forgotten admin panels'
                    })
                
                time.sleep(0.2)
    
    def check_dev_domains(self):
        """Check for development/staging domains"""
        for pattern in self.dev_patterns[:8]:
            test_domain = pattern.replace('{domain}', self.base_domain)
            
            for tld in ['.com', '.net']:
                url = f"http://{test_domain}{tld}"
                
                if self.check_domain_exists(url):
                    self.findings.append({
                        'type': 'dev_environment',
                        'severity': 'critical',
                        'url': url,
                        'domain': f"{test_domain}{tld}",
                        'description': f'Development/staging environment exposed: {test_domain}{tld}',
                        'risk': 'Often has weaker security, debug enabled, and test credentials'
                    })
                
                time.sleep(0.2)
    
    def check_old_admin_panels(self):
        """Check for old admin panel paths on current domain"""
        for path in self.old_admin_paths:
            url = f"{self.target}{path}"
            
            try:
                response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                
                # Check if it looks like an admin panel
                if self.is_admin_panel(response):
                    self.findings.append({
                        'type': 'old_admin',
                        'severity': 'critical',
                        'url': url,
                        'status_code': response.status_code,
                        'description': f'Old admin panel found at: {path}',
                        'risk': 'May use outdated authentication or have default credentials'
                    })
                
                time.sleep(0.1)
            except:
                pass
    
    def check_old_urls(self):
        """Check for common old/legacy URLs"""
        old_urls = [
            '/old',
            '/legacy',
            '/archive',
            '/backup',
            '/v1',
            '/v2',
            '/old-site',
            '/legacy-site',
            '/mobile-old',
            '/app-old',
        ]
        
        for url_path in old_urls:
            url = f"{self.target}{url_path}"
            
            try:
                response = requests.get(url, timeout=10, verify=False)
                
                if response.status_code == 200 and len(response.content) > 500:
                    self.findings.append({
                        'type': 'legacy_system',
                        'severity': 'medium',
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'description': f'Legacy system/old version found at: {url_path}',
                        'risk': 'Old systems may have unpatched vulnerabilities'
                    })
                
                time.sleep(0.1)
            except:
                pass
    
    def check_domain_exists(self, url: str) -> bool:
        """Check if a domain/URL exists and is reachable"""
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            
            # Domain exists if we get any response (200, 403, 401, etc.)
            if response.status_code in [200, 301, 302, 401, 403]:
                return True
            
            return False
        except:
            return False
    
    def is_admin_panel(self, response) -> bool:
        """Check if response looks like an admin panel"""
        if response.status_code not in [200, 401, 403]:
            return False
        
        content_lower = response.text.lower()
        
        # Admin panel indicators
        admin_indicators = [
            'admin login',
            'administrator',
            'admin panel',
            'dashboard',
            'control panel',
            'management',
            'username',
            'password',
            'sign in',
            'login',
        ]
        
        # Count matches
        matches = sum(1 for indicator in admin_indicators if indicator in content_lower)
        
        return matches >= 3
    
    def calculate_severity(self) -> str:
        """Calculate overall severity"""
        if not self.findings:
            return 'info'
        
        severities = [f.get('severity', 'info') for f in self.findings]
        
        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        return 'low'


def detect(target: str) -> Dict[str, Any]:
    """Main detection function"""
    hunter = OldDomainHunter(target)
    return hunter.run()

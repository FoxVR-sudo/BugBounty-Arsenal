"""
JavaScript File Analyzer for 0-Day Hunting
Mines JavaScript files for hidden API endpoints, debug flags, and sensitive data
"""
import re
import requests
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any


class JSFileAnalyzer:
    """
    Analyzes JavaScript files to discover:
    - Hidden API endpoints
    - Debug flags and internal URLs
    - Hardcoded credentials
    - Feature flags
    - Internal logic and parameters
    """
    
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.findings = []
        self.js_files = []
        
    def run(self) -> Dict[str, Any]:
        """Main execution method"""
        try:
            # Step 1: Discover JS files
            self.discover_js_files()
            
            # Step 2: Analyze each JS file
            for js_url in self.js_files[:10]:  # Limit to 10 files
                self.analyze_js_file(js_url)
            
            return {
                'vulnerable': len(self.findings) > 0,
                'severity': self.calculate_severity(),
                'findings': self.findings,
                'js_files_analyzed': len(self.js_files),
                'details': {
                    'api_endpoints': [f for f in self.findings if f['type'] == 'api_endpoint'],
                    'debug_flags': [f for f in self.findings if f['type'] == 'debug_flag'],
                    'credentials': [f for f in self.findings if f['type'] == 'credentials'],
                    'internal_urls': [f for f in self.findings if f['type'] == 'internal_url'],
                }
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'findings': []
            }
    
    def discover_js_files(self):
        """Discover JavaScript files from the target"""
        try:
            # Get main page
            response = requests.get(self.target, timeout=10, verify=False)
            
            # Find JS files in HTML
            js_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
            matches = re.findall(js_pattern, response.text)
            
            for match in matches:
                js_url = urljoin(self.target, match)
                if js_url not in self.js_files:
                    self.js_files.append(js_url)
            
            # Common JS file paths
            common_paths = [
                '/js/main.js',
                '/js/app.js',
                '/static/js/bundle.js',
                '/assets/js/app.js',
                '/build/main.js',
            ]
            
            for path in common_paths:
                js_url = urljoin(self.target, path)
                if js_url not in self.js_files:
                    self.js_files.append(js_url)
                    
        except Exception as e:
            pass
    
    def analyze_js_file(self, js_url: str):
        """Analyze individual JavaScript file"""
        try:
            response = requests.get(js_url, timeout=10, verify=False)
            content = response.text
            
            # Pattern 1: API endpoints
            self.find_api_endpoints(content, js_url)
            
            # Pattern 2: Debug flags
            self.find_debug_flags(content, js_url)
            
            # Pattern 3: Credentials
            self.find_credentials(content, js_url)
            
            # Pattern 4: Internal URLs
            self.find_internal_urls(content, js_url)
            
            # Pattern 5: Feature flags
            self.find_feature_flags(content, js_url)
            
        except Exception as e:
            pass
    
    def find_api_endpoints(self, content: str, source: str):
        """Find API endpoints in JavaScript"""
        patterns = [
            r'["\']/(api|v1|v2|graphql|internal)/[a-zA-Z0-9/_-]+["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
            r'url\s*[:=]\s*["\']([^"\']+/api/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = match if isinstance(match, str) else match[-1]
                if '/api' in endpoint or '/internal' in endpoint:
                    self.findings.append({
                        'type': 'api_endpoint',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'source': source,
                        'description': f'Hidden API endpoint found: {endpoint}'
                    })
    
    def find_debug_flags(self, content: str, source: str):
        """Find debug flags and development features"""
        patterns = [
            r'debug\s*[:=]\s*(true|false|1|0)',
            r'isDebug\s*[:=]\s*(true|false)',
            r'DEBUG_MODE\s*[:=]\s*(true|false)',
            r'development\s*[:=]\s*(true|false)',
            r'enableDebug\s*[:=]\s*function',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self.findings.append({
                    'type': 'debug_flag',
                    'severity': 'low',
                    'flag': match,
                    'source': source,
                    'description': f'Debug flag found: {match} (may enable hidden features)'
                })
    
    def find_credentials(self, content: str, source: str):
        """Find hardcoded credentials"""
        patterns = [
            r'password\s*[:=]\s*["\']([^"\']{4,})["\']',
            r'apiKey\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'secret\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'token\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'api_key\s*[:=]\s*["\']([^"\']{10,})["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # Skip common placeholders
                if match.lower() in ['password', 'your-api-key', 'xxx', 'token', 'secret']:
                    continue
                    
                self.findings.append({
                    'type': 'credentials',
                    'severity': 'high',
                    'credential': match[:20] + '...' if len(match) > 20 else match,
                    'source': source,
                    'description': 'Potential hardcoded credential found in JavaScript'
                })
    
    def find_internal_urls(self, content: str, source: str):
        """Find internal/staging URLs"""
        patterns = [
            r'https?://[a-z0-9-]+\.(dev|staging|test|internal|local)[a-z0-9.-]+',
            r'https?://(dev|staging|test|internal)-[a-z0-9.-]+',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self.findings.append({
                    'type': 'internal_url',
                    'severity': 'medium',
                    'url': match,
                    'source': source,
                    'description': f'Internal/staging URL found: {match}'
                })
    
    def find_feature_flags(self, content: str, source: str):
        """Find feature flags that can be manipulated"""
        patterns = [
            r'isAdmin\s*[:=]\s*(true|false)',
            r'isPremium\s*[:=]\s*(true|false)',
            r'hasAccess\s*[:=]\s*(true|false)',
            r'featureFlag\s*[:=]\s*["\']([^"\']+)["\']',
            r'betaAccess\s*[:=]\s*(true|false)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self.findings.append({
                    'type': 'feature_flag',
                    'severity': 'medium',
                    'flag': match,
                    'source': source,
                    'description': f'Feature flag found: {match} (potential privilege escalation)'
                })
    
    def calculate_severity(self) -> str:
        """Calculate overall severity based on findings"""
        if not self.findings:
            return 'info'
        
        severities = [f.get('severity', 'info') for f in self.findings]
        
        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        elif 'low' in severities:
            return 'low'
        return 'info'


def detect(target: str) -> Dict[str, Any]:
    """Main detection function called by the scanner framework"""
    analyzer = JSFileAnalyzer(target)
    return analyzer.run()

"""
Enhanced Parameter Fuzzer for 0-Day Discovery
Tests hidden parameters that bypass authorization and unlock admin features
"""
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Dict, List, Any
import time


class ParameterFuzzer:
    """
    Advanced parameter fuzzing for discovering hidden parameters:
    - Admin/role parameters
    - Debug/test parameters
    - Access level parameters
    - Feature flag parameters
    """
    
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.findings = []
        
        # Hidden parameter wordlist organized by category
        self.admin_params = [
            'admin', 'isAdmin', 'is_admin', 'role', 'user_role', 'access',
            'access_level', 'level', 'privilege', 'permissions', 'type',
            'user_type', 'account_type', 'is_staff', 'staff', 'superuser'
        ]
        
        self.debug_params = [
            'debug', 'test', 'dev', 'trace', 'verbose', 'show_errors',
            'print_errors', 'display_errors', 'show_debug', 'development',
            'testing', 'demo', 'sample', 'example'
        ]
        
        self.bypass_params = [
            'bypass', 'skip', 'override', 'force', 'ignore', 'disable',
            'no_check', 'skip_check', 'skip_auth', 'no_auth', 'bypass_auth'
        ]
        
        self.feature_params = [
            'beta', 'alpha', 'experimental', 'preview', 'early_access',
            'feature', 'enable', 'enabled', 'disabled', 'hidden', 'secret'
        ]
        
        self.access_params = [
            'internal', 'private', 'restricted', 'premium', 'pro',
            'enterprise', 'paid', 'subscription', 'vip', 'member'
        ]
        
        # Common endpoints to test
        self.test_endpoints = [
            '/',
            '/profile',
            '/user',
            '/account',
            '/dashboard',
            '/admin',
            '/api/user',
            '/api/profile',
            '/checkout',
            '/cart',
        ]
        
    def run(self) -> Dict[str, Any]:
        """Main execution method"""
        try:
            # Test each endpoint with parameter combinations
            for endpoint in self.test_endpoints[:5]:  # Limit to 5 endpoints
                url = urljoin(self.target, endpoint)
                
                # Get baseline response
                baseline = self.get_baseline(url)
                if not baseline:
                    continue
                
                # Test admin parameters
                self.test_param_category(url, self.admin_params, baseline, 'admin')
                
                # Test debug parameters
                self.test_param_category(url, self.debug_params, baseline, 'debug')
                
                # Test bypass parameters
                self.test_param_category(url, self.bypass_params, baseline, 'bypass')
                
                # Test feature parameters
                self.test_param_category(url, self.feature_params, baseline, 'feature')
                
                # Test access parameters
                self.test_param_category(url, self.access_params, baseline, 'access')
            
            return {
                'vulnerable': len(self.findings) > 0,
                'severity': self.calculate_severity(),
                'findings': self.findings,
                'parameters_tested': self.count_tested_params(),
                'details': {
                    'admin_params': [f for f in self.findings if f['category'] == 'admin'],
                    'debug_params': [f for f in self.findings if f['category'] == 'debug'],
                    'bypass_params': [f for f in self.findings if f['category'] == 'bypass'],
                    'feature_params': [f for f in self.findings if f['category'] == 'feature'],
                }
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'findings': []
            }
    
    def get_baseline(self, url: str) -> Dict[str, Any]:
        """Get baseline response for comparison"""
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=False)
            return {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content': response.text,
                'headers': dict(response.headers)
            }
        except:
            return None
    
    def test_param_category(self, url: str, params: List[str], baseline: Dict, category: str):
        """Test a category of parameters"""
        # Test with different values
        test_values = ['true', 'false', '1', '0', 'yes', 'no', 'admin', 'user']
        
        for param in params[:10]:  # Limit to 10 params per category
            for value in test_values[:4]:  # Test first 4 values
                # Add parameter to URL
                test_url = f"{url}?{param}={value}"
                
                try:
                    response = requests.get(test_url, timeout=10, verify=False, allow_redirects=False)
                    
                    # Check for interesting changes
                    if self.is_interesting_response(response, baseline):
                        self.findings.append({
                            'type': 'hidden_parameter',
                            'category': category,
                            'severity': self.determine_severity(category, response, baseline),
                            'parameter': param,
                            'value': value,
                            'url': test_url,
                            'baseline_status': baseline['status_code'],
                            'new_status': response.status_code,
                            'description': f'Hidden parameter discovered: {param}={value} changes response',
                            'impact': self.analyze_impact(response, baseline)
                        })
                    
                    time.sleep(0.05)  # Rate limiting
                except:
                    pass
    
    def is_interesting_response(self, response, baseline) -> bool:
        """Check if response is significantly different from baseline"""
        # Status code changed
        if response.status_code != baseline['status_code']:
            # Interesting status changes
            if response.status_code in [200, 302, 403] and baseline['status_code'] in [401, 404]:
                return True
        
        # Content length significantly different (>20%)
        new_length = len(response.content)
        baseline_length = baseline['content_length']
        
        if baseline_length > 0:
            diff_percent = abs(new_length - baseline_length) / baseline_length
            if diff_percent > 0.2:  # More than 20% difference
                return True
        
        # New interesting content appeared
        interesting_strings = [
            'admin', 'Administrator', 'debug', 'error', 'stack trace',
            'internal', 'restricted', 'unauthorized', 'forbidden',
            'premium', 'pro version', 'beta', 'hidden'
        ]
        
        for string in interesting_strings:
            if string.lower() in response.text.lower() and string.lower() not in baseline['content'].lower():
                return True
        
        return False
    
    def determine_severity(self, category: str, response, baseline) -> str:
        """Determine severity based on parameter category and response"""
        # Admin/bypass parameters are critical
        if category in ['admin', 'bypass']:
            if response.status_code == 200 and baseline['status_code'] in [401, 403]:
                return 'critical'
            return 'high'
        
        # Debug parameters are medium-high
        if category == 'debug':
            if 'error' in response.text.lower() or 'trace' in response.text.lower():
                return 'high'
            return 'medium'
        
        # Feature/access parameters are medium
        if category in ['feature', 'access']:
            return 'medium'
        
        return 'low'
    
    def analyze_impact(self, response, baseline) -> str:
        """Analyze the impact of the parameter"""
        impacts = []
        
        # Status code changes
        if response.status_code != baseline['status_code']:
            impacts.append(f"Status: {baseline['status_code']} → {response.status_code}")
        
        # Authentication bypass
        if baseline['status_code'] == 401 and response.status_code == 200:
            impacts.append("Authentication bypass")
        
        # Authorization bypass
        if baseline['status_code'] == 403 and response.status_code == 200:
            impacts.append("Authorization bypass")
        
        # Debug info exposure
        if 'debug' in response.text.lower() or 'trace' in response.text.lower():
            impacts.append("Debug information exposed")
        
        # Admin panel access
        if 'admin' in response.text.lower() and 'admin' not in baseline['content'].lower():
            impacts.append("Admin panel accessible")
        
        return '; '.join(impacts) if impacts else 'Response changed significantly'
    
    def count_tested_params(self) -> int:
        """Count total parameters tested"""
        return len(self.admin_params) + len(self.debug_params) + len(self.bypass_params) + \
               len(self.feature_params) + len(self.access_params)
    
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
    fuzzer = ParameterFuzzer(target)
    return fuzzer.run()

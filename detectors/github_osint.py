"""
GitHub OSINT Scanner - Advanced reconnaissance through GitHub
Finds leaked secrets, API keys, and sensitive information in public repositories
"""
import requests
import re
import time
from typing import Dict, List, Any
from urllib.parse import urlparse


class GitHubOSINT:
    """
    GitHub reconnaissance for finding:
    - Leaked API keys and credentials
    - Exposed secrets in code
    - Developer commits with sensitive data
    - Organization information
    - Repository vulnerabilities
    """
    
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.domain = self.extract_domain(target)
        self.findings = []
        
        # GitHub API (unauthenticated has rate limits)
        self.github_api = "https://api.github.com"
        self.github_search = "https://api.github.com/search/code"
        
        # Sensitive patterns to search for
        self.secret_patterns = {
            'api_key': [
                'api_key',
                'apikey',
                'api-key',
                'key',
            ],
            'password': [
                'password',
                'passwd',
                'pwd',
                'pass',
            ],
            'token': [
                'token',
                'auth_token',
                'access_token',
                'secret_token',
            ],
            'secret': [
                'secret',
                'api_secret',
                'client_secret',
                'app_secret',
            ],
            'credentials': [
                'credentials',
                'creds',
                'credential',
            ],
            'database': [
                'db_password',
                'database_password',
                'mysql_password',
                'postgres_password',
            ],
            'aws': [
                'aws_access_key_id',
                'aws_secret_access_key',
                'AWS_ACCESS_KEY',
                'AWS_SECRET_KEY',
            ],
        }
        
        # File extensions to check
        self.sensitive_extensions = [
            '.env',
            '.config',
            '.ini',
            '.yml',
            '.yaml',
            '.json',
            '.xml',
            '.properties',
            '.conf',
        ]
        
    def run(self) -> Dict[str, Any]:
        """Main execution method"""
        try:
            # Search for domain in GitHub
            self.search_domain_mentions()
            
            # Search for common secret files
            self.search_secret_files()
            
            # Search for hardcoded credentials
            self.search_hardcoded_secrets()
            
            # Search for exposed configs
            self.search_config_files()
            
            return {
                'vulnerable': len(self.findings) > 0,
                'severity': self.calculate_severity(),
                'findings': self.findings,
                'searches_performed': 4,
                'details': {
                    'leaked_secrets': [f for f in self.findings if f['type'] == 'secret'],
                    'exposed_configs': [f for f in self.findings if f['type'] == 'config'],
                    'credentials': [f for f in self.findings if f['type'] == 'credentials'],
                    'api_keys': [f for f in self.findings if f['type'] == 'api_key'],
                }
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'findings': []
            }
    
    def extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        # Remove www. and port
        domain = domain.replace('www.', '').split(':')[0]
        return domain
    
    def search_domain_mentions(self):
        """Search for domain mentions in GitHub repositories"""
        try:
            # Search GitHub code for domain
            query = f'"{self.domain}"'
            
            response = requests.get(
                self.github_search,
                params={'q': query, 'per_page': 10},
                headers={'Accept': 'application/vnd.github.v3+json'},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('total_count', 0) > 0:
                    for item in data.get('items', [])[:5]:  # Limit to 5 results
                        self.findings.append({
                            'type': 'domain_mention',
                            'severity': 'medium',
                            'repository': item.get('repository', {}).get('full_name'),
                            'file': item.get('name'),
                            'url': item.get('html_url'),
                            'description': f'Domain {self.domain} found in public repository',
                            'risk': 'May expose internal URLs, API endpoints, or configuration details'
                        })
            
            time.sleep(2)  # Rate limiting
            
        except Exception as e:
            pass
    
    def search_secret_files(self):
        """Search for common secret files (.env, config.json, etc.)"""
        secret_files = [
            '.env',
            'config.json',
            'credentials.json',
            'secrets.json',
            'api_keys.txt',
            '.aws/credentials',
        ]
        
        for filename in secret_files[:3]:  # Limit searches
            try:
                query = f'"{self.domain}" filename:{filename}'
                
                response = requests.get(
                    self.github_search,
                    params={'q': query, 'per_page': 5},
                    headers={'Accept': 'application/vnd.github.v3+json'},
                    timeout=15
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get('total_count', 0) > 0:
                        for item in data.get('items', [])[:3]:
                            self.findings.append({
                                'type': 'secret',
                                'severity': 'critical',
                                'repository': item.get('repository', {}).get('full_name'),
                                'file': filename,
                                'url': item.get('html_url'),
                                'description': f'Sensitive file {filename} found containing {self.domain}',
                                'risk': 'May contain API keys, passwords, or other credentials'
                            })
                
                time.sleep(3)  # Rate limiting
                
            except:
                pass
    
    def search_hardcoded_secrets(self):
        """Search for hardcoded secrets in code"""
        # Search for common secret patterns
        secret_searches = [
            f'{self.domain} password',
            f'{self.domain} api_key',
            f'{self.domain} token',
        ]
        
        for search_term in secret_searches[:2]:  # Limit searches
            try:
                response = requests.get(
                    self.github_search,
                    params={'q': search_term, 'per_page': 5},
                    headers={'Accept': 'application/vnd.github.v3+json'},
                    timeout=15
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get('total_count', 0) > 0:
                        for item in data.get('items', [])[:2]:
                            self.findings.append({
                                'type': 'credentials',
                                'severity': 'high',
                                'repository': item.get('repository', {}).get('full_name'),
                                'file': item.get('name'),
                                'url': item.get('html_url'),
                                'search_term': search_term,
                                'description': f'Hardcoded credentials found for {self.domain}',
                                'risk': 'Credentials may be valid and usable for authentication'
                            })
                
                time.sleep(3)  # Rate limiting
                
            except:
                pass
    
    def search_config_files(self):
        """Search for exposed configuration files"""
        # Common config patterns that might expose sensitive info
        config_patterns = [
            f'"{self.domain}" extension:yml',
            f'"{self.domain}" extension:env',
        ]
        
        for pattern in config_patterns[:1]:  # Limit to 1 search
            try:
                response = requests.get(
                    self.github_search,
                    params={'q': pattern, 'per_page': 5},
                    headers={'Accept': 'application/vnd.github.v3+json'},
                    timeout=15
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get('total_count', 0) > 0:
                        for item in data.get('items', [])[:2]:
                            self.findings.append({
                                'type': 'config',
                                'severity': 'medium',
                                'repository': item.get('repository', {}).get('full_name'),
                                'file': item.get('name'),
                                'url': item.get('html_url'),
                                'description': f'Configuration file found referencing {self.domain}',
                                'risk': 'May contain database URLs, API endpoints, or service credentials'
                            })
                
                time.sleep(3)  # Rate limiting
                
            except:
                pass
    
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
    scanner = GitHubOSINT(target)
    return scanner.run()

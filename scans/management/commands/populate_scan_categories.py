"""
Management command to populate scan categories and detector configurations.
Run after migrations: python manage.py populate_scan_categories
"""
from django.core.management.base import BaseCommand
from scans.category_models import ScanCategory, DetectorConfig


class Command(BaseCommand):
    help = 'Populate scan categories and detector configurations for v3.0'

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING('Populating scan categories and detectors...'))
        
        # Create categories
        categories = self.create_categories()
        
        # Create detector configurations
        detectors = self.create_detectors()
        
        # Assign detectors to categories
        self.assign_to_categories(categories, detectors)
        
        # Update detector counts
        for category in categories.values():
            category.update_detector_count()
        
        self.stdout.write(self.style.SUCCESS(f'\n✅ Successfully created:'))
        self.stdout.write(f'   - {len(categories)} scan categories')
        self.stdout.write(f'   - {len(detectors)} detector configurations')
        
        # Show category summary
        self.stdout.write(self.style.SUCCESS('\n📊 Category Summary:'))
        for cat_name, category in categories.items():
            count = category.detector_count
            self.stdout.write(f'   {category.icon} {category.display_name}: {count} detectors ({category.required_plan})')

    def create_categories(self):
        """Create scan categories"""
        categories_data = [
            {
                'name': 'recon',
                'display_name': 'Reconnaissance Scan',
                'description': 'Subdomain enumeration, DNS records, WHOIS lookup, technology detection, and infrastructure mapping.',
                'required_plan': 'free',
                'icon': '🔍',
                'order': 1,
            },
            {
                'name': 'web',
                'display_name': 'Web Application Scan',
                'description': 'XSS, SQL injection, CSRF, CORS misconfigurations, security headers, open redirects, and common web vulnerabilities.',
                'required_plan': 'free',
                'icon': '🌐',
                'order': 2,
            },
            {
                'name': 'api',
                'display_name': 'API Security Scan',
                'description': 'GraphQL introspection, REST API testing, JWT vulnerabilities, OAuth misconfigurations, and API-specific attacks.',
                'required_plan': 'pro',
                'icon': '🔌',
                'order': 3,
            },
            {
                'name': 'vuln',
                'display_name': 'Vulnerability Scan',
                'description': 'CVE database scanning, known vulnerability detection, version checking, and exploit availability.',
                'required_plan': 'pro',
                'icon': '🛡️',
                'order': 4,
            },
            {
                'name': 'mobile',
                'display_name': 'Mobile Security Scan',
                'description': 'Android APK analysis, iOS IPA testing, mobile API security, and app-specific vulnerabilities.',
                'required_plan': 'pro',
                'icon': '📱',
                'order': 5,
            },
            {
                'name': 'custom',
                'display_name': 'Custom Scan (All Tools)',
                'description': 'ALL 40+ detectors including dangerous tools (Nuclei, brute force, custom payloads). Maximum coverage with full control over detector selection. Enterprise only.',
                'required_plan': 'enterprise',
                'icon': '⚡',
                'order': 6,
            },
        ]
        
        categories = {}
        for data in categories_data:
            category, created = ScanCategory.objects.update_or_create(
                name=data['name'],
                defaults=data
            )
            categories[data['name']] = category
            status = '✨ Created' if created else '♻️  Updated'
            self.stdout.write(f'{status}: {category.display_name}')
        
        return categories

    def create_detectors(self):
        """Create detector configurations for all 40+ detectors"""
        detectors_data = [
            # XSS & Injection Detectors
            {
                'name': 'xss_pattern_detector',
                'display_name': 'XSS Pattern Detection',
                'description': 'Cross-Site Scripting (XSS) vulnerability detection using pattern matching and payload reflection analysis.',
                'severity': 'high',
                'tags': ['xss', 'injection', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 10,
            },
            {
                'name': 'sql_pattern_detector',
                'display_name': 'SQL Injection Detection',
                'description': 'SQL injection vulnerability scanner using pattern matching and error-based detection.',
                'severity': 'critical',
                'tags': ['sqli', 'injection', 'owasp-top10', 'database'],
                'is_dangerous': False,
                'execution_order': 11,
            },
            {
                'name': 'nosql_injection_detector',
                'display_name': 'NoSQL Injection Detection',
                'description': 'NoSQL injection testing for MongoDB, CouchDB, and other NoSQL databases.',
                'severity': 'high',
                'tags': ['nosql', 'injection', 'database'],
                'is_dangerous': False,
                'execution_order': 12,
            },
            {
                'name': 'command_injection_detector',
                'display_name': 'Command Injection Detection',
                'description': 'OS command injection vulnerability scanner.',
                'severity': 'critical',
                'tags': ['command-injection', 'rce', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 13,
            },
            {
                'name': 'lfi_detector',
                'display_name': 'Local File Inclusion (LFI)',
                'description': 'Local File Inclusion vulnerability detection with path traversal testing.',
                'severity': 'high',
                'tags': ['lfi', 'file-inclusion', 'path-traversal'],
                'is_dangerous': False,
                'execution_order': 14,
            },
            {
                'name': 'ssti_detector',
                'display_name': 'Server-Side Template Injection (SSTI)',
                'description': 'Template injection vulnerability scanner for Jinja2, Twig, Freemarker, and other engines.',
                'severity': 'critical',
                'tags': ['ssti', 'injection', 'rce'],
                'is_dangerous': False,
                'execution_order': 15,
            },
            {
                'name': 'xxe_detector',
                'display_name': 'XML External Entity (XXE)',
                'description': 'XXE vulnerability detection with file disclosure and SSRF testing.',
                'severity': 'high',
                'tags': ['xxe', 'xml', 'ssrf', 'file-disclosure'],
                'is_dangerous': False,
                'execution_order': 16,
            },
            
            # SSRF Detectors
            {
                'name': 'ssrf_detector',
                'display_name': 'SSRF Pattern Detection',
                'description': 'Server-Side Request Forgery (SSRF) vulnerability scanner using pattern matching.',
                'severity': 'high',
                'tags': ['ssrf', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 20,
            },
            {
                'name': 'advanced_ssrf_detector',
                'display_name': 'Advanced SSRF Detection',
                'description': 'Advanced SSRF testing with protocol smuggling and bypass techniques.',
                'severity': 'high',
                'tags': ['ssrf', 'advanced'],
                'is_dangerous': False,
                'execution_order': 21,
            },
            {
                'name': 'ssrf_oob_detector',
                'display_name': 'SSRF Out-of-Band Detection',
                'description': 'SSRF detection using out-of-band callbacks (Interactsh).',
                'severity': 'high',
                'tags': ['ssrf', 'oob', 'interactsh'],
                'is_dangerous': False,
                'requires_oob': True,
                'execution_order': 22,
            },
            
            # Security Headers & CORS
            {
                'name': 'security_headers_detector',
                'display_name': 'Security Headers Analysis',
                'description': 'Analyze HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).',
                'severity': 'medium',
                'tags': ['headers', 'security-headers', 'configuration'],
                'is_dangerous': False,
                'execution_order': 30,
            },
            {
                'name': 'cors_detector',
                'display_name': 'CORS Misconfiguration',
                'description': 'Cross-Origin Resource Sharing (CORS) misconfiguration detection.',
                'severity': 'medium',
                'tags': ['cors', 'configuration', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 31,
            },
            {
                'name': 'csrf_detector',
                'display_name': 'CSRF Detection',
                'description': 'Cross-Site Request Forgery (CSRF) vulnerability detection.',
                'severity': 'medium',
                'tags': ['csrf', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 32,
            },
            {
                'name': 'header_injection_detector',
                'display_name': 'Header Injection',
                'description': 'HTTP header injection and CRLF injection detection.',
                'severity': 'medium',
                'tags': ['header-injection', 'crlf'],
                'is_dangerous': False,
                'execution_order': 33,
            },
            
            # API & GraphQL
            {
                'name': 'graphql_detector',
                'display_name': 'GraphQL Security',
                'description': 'GraphQL endpoint detection and introspection.',
                'severity': 'info',
                'tags': ['graphql', 'api'],
                'is_dangerous': False,
                'execution_order': 40,
            },
            {
                'name': 'graphql_injection_detector',
                'display_name': 'GraphQL Injection',
                'description': 'GraphQL injection and mutation testing.',
                'severity': 'high',
                'tags': ['graphql', 'api', 'injection'],
                'is_dangerous': False,
                'execution_order': 41,
            },
            {
                'name': 'api_security_detector',
                'display_name': 'API Security Scanner',
                'description': 'REST API security testing including authentication, rate limiting, and data exposure.',
                'severity': 'medium',
                'tags': ['api', 'rest', 'security'],
                'is_dangerous': False,
                'execution_order': 42,
            },
            
            # Authentication & Authorization
            {
                'name': 'jwt_detector',
                'display_name': 'JWT Vulnerability Scanner',
                'description': 'JSON Web Token (JWT) security testing.',
                'severity': 'high',
                'tags': ['jwt', 'authentication', 'api'],
                'is_dangerous': False,
                'execution_order': 50,
            },
            {
                'name': 'jwt_vulnerability_scanner',
                'display_name': 'Advanced JWT Testing',
                'description': 'Advanced JWT vulnerability detection including algorithm confusion and key cracking.',
                'severity': 'high',
                'tags': ['jwt', 'authentication', 'advanced'],
                'is_dangerous': False,
                'execution_order': 51,
            },
            {
                'name': 'oauth_detector',
                'display_name': 'OAuth Misconfiguration',
                'description': 'OAuth 2.0 implementation vulnerability detection.',
                'severity': 'high',
                'tags': ['oauth', 'authentication'],
                'is_dangerous': False,
                'execution_order': 52,
            },
            {
                'name': 'auth_bypass_detector',
                'display_name': 'Authentication Bypass',
                'description': 'Authentication bypass vulnerability scanner.',
                'severity': 'critical',
                'tags': ['auth-bypass', 'authentication'],
                'is_dangerous': False,
                'execution_order': 53,
            },
            {
                'name': 'idor_detector',
                'display_name': 'IDOR Detection',
                'description': 'Insecure Direct Object Reference (IDOR) vulnerability detection.',
                'severity': 'high',
                'tags': ['idor', 'authorization', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 54,
            },
            
            # File & Upload Testing
            {
                'name': 'file_upload_detector',
                'display_name': 'File Upload Vulnerability',
                'description': 'File upload security testing including extension bypass and content validation.',
                'severity': 'high',
                'tags': ['file-upload', 'rce'],
                'is_dangerous': False,
                'execution_order': 60,
            },
            {
                'name': 'dir_listing_detector',
                'display_name': 'Directory Listing',
                'description': 'Directory listing and path disclosure detection.',
                'severity': 'low',
                'tags': ['directory-listing', 'information-disclosure'],
                'is_dangerous': False,
                'execution_order': 61,
            },
            
            # Information Disclosure
            {
                'name': 'secret_detector',
                'display_name': 'Secret & Credential Detection',
                'description': 'Detect exposed API keys, passwords, tokens, and credentials.',
                'severity': 'high',
                'tags': ['secrets', 'credentials', 'information-disclosure'],
                'is_dangerous': False,
                'execution_order': 70,
            },
            {
                'name': 'reflection_detector',
                'display_name': 'Parameter Reflection',
                'description': 'Detect reflected parameters that could lead to XSS or other attacks.',
                'severity': 'info',
                'tags': ['reflection', 'xss'],
                'is_dangerous': False,
                'execution_order': 71,
            },
            
            # Advanced Attacks
            {
                'name': 'prototype_pollution_detector',
                'display_name': 'Prototype Pollution',
                'description': 'JavaScript prototype pollution vulnerability detection.',
                'severity': 'high',
                'tags': ['prototype-pollution', 'javascript'],
                'is_dangerous': False,
                'execution_order': 80,
            },
            {
                'name': 'cache_poisoning_detector',
                'display_name': 'Cache Poisoning',
                'description': 'Web cache poisoning vulnerability detection.',
                'severity': 'medium',
                'tags': ['cache-poisoning'],
                'is_dangerous': False,
                'execution_order': 81,
            },
            {
                'name': 'race_condition_detector',
                'display_name': 'Race Condition',
                'description': 'Race condition vulnerability detection in critical operations.',
                'severity': 'high',
                'tags': ['race-condition', 'concurrency'],
                'is_dangerous': False,
                'execution_order': 82,
            },
            {
                'name': 'open_redirect_detector',
                'display_name': 'Open Redirect',
                'description': 'Open redirect vulnerability detection.',
                'severity': 'medium',
                'tags': ['open-redirect', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 83,
            },
            
            # Reconnaissance
            {
                'name': 'subdomain_takeover_detector',
                'display_name': 'Subdomain Takeover',
                'description': 'Detect subdomains vulnerable to takeover attacks.',
                'severity': 'high',
                'tags': ['subdomain-takeover', 'dns', 'reconnaissance'],
                'is_dangerous': False,
                'execution_order': 90,
            },
            
            # CVE & Vulnerability Database
            {
                'name': 'cve_database_detector',
                'display_name': 'CVE Database Scanner',
                'description': 'Scan for known CVEs and vulnerabilities from database.',
                'severity': 'critical',
                'tags': ['cve', 'vulnerability-database'],
                'is_dangerous': False,
                'execution_order': 100,
            },
            
            # Fuzzing & Brute Force (DANGEROUS - Enterprise only)
            {
                'name': 'fuzz_detector',
                'display_name': 'Smart Fuzzing',
                'description': 'Intelligent fuzzing for parameter discovery and input validation testing.',
                'severity': 'medium',
                'tags': ['fuzzing', 'testing'],
                'is_dangerous': True,
                'execution_order': 200,
            },
            {
                'name': 'brute_force_detector',
                'display_name': 'Brute Force Testing',
                'description': 'Brute force testing for authentication endpoints and admin panels. DANGEROUS - high request volume.',
                'severity': 'high',
                'tags': ['brute-force', 'authentication'],
                'is_dangerous': True,
                'execution_order': 201,
            },
            {
                'name': 'rate_limit_bypass_detector',
                'display_name': 'Rate Limit Bypass',
                'description': 'Test for rate limiting bypass vulnerabilities.',
                'severity': 'medium',
                'tags': ['rate-limiting', 'bypass'],
                'is_dangerous': True,
                'execution_order': 202,
            },
            
            # Utility detectors
            {
                'name': 'interactsh_client',
                'display_name': 'Interactsh OOB Client',
                'description': 'Out-of-band callback detection using Interactsh.',
                'severity': 'info',
                'tags': ['oob', 'utility'],
                'is_dangerous': False,
                'requires_oob': True,
                'execution_order': 300,
            },
            {
                'name': 'injector',
                'display_name': 'Payload Injector',
                'description': 'Generic payload injection utility.',
                'severity': 'info',
                'tags': ['utility', 'injection'],
                'is_dangerous': True,
                'execution_order': 301,
            },
        ]
        
        detectors = {}
        for data in detectors_data:
            detector, created = DetectorConfig.objects.update_or_create(
                name=data['name'],
                defaults=data
            )
            detectors[data['name']] = detector
            dangerous_mark = ' 🔴 DANGEROUS' if data.get('is_dangerous') else ''
            status = '✨' if created else '♻️ '
            self.stdout.write(f'{status} {detector.display_name}{dangerous_mark}')
        
        return detectors

    def assign_to_categories(self, categories, detectors):
        """Assign detectors to appropriate categories"""
        
        # Recon Scan
        recon_detectors = [
            'subdomain_takeover_detector',
            'security_headers_detector',
            'secret_detector',
            'dir_listing_detector',
        ]
        
        # Web Scan
        web_detectors = [
            'xss_pattern_detector',
            'sql_pattern_detector',
            'nosql_injection_detector',
            'command_injection_detector',
            'lfi_detector',
            'ssti_detector',
            'xxe_detector',
            'csrf_detector',
            'cors_detector',
            'header_injection_detector',
            'open_redirect_detector',
            'security_headers_detector',
            'reflection_detector',
            'file_upload_detector',
            'prototype_pollution_detector',
            'cache_poisoning_detector',
        ]
        
        # API Scan
        api_detectors = [
            'graphql_detector',
            'graphql_injection_detector',
            'api_security_detector',
            'jwt_detector',
            'jwt_vulnerability_scanner',
            'oauth_detector',
            'auth_bypass_detector',
            'idor_detector',
            'cors_detector',
            'rate_limit_bypass_detector',
        ]
        
        # Vuln Scan
        vuln_detectors = [
            'cve_database_detector',
            'auth_bypass_detector',
            'secret_detector',
        ]
        
        # Mobile Scan (placeholder - will be enhanced with mobile_scanner/ integration)
        mobile_detectors = [
            'api_security_detector',
            'jwt_detector',
            'oauth_detector',
            'ssl_pinning_detector',  # To be created
        ]
        
        # Custom Scan - ALL detectors (Enterprise only)
        custom_detectors = list(detectors.keys())
        
        # Assign detectors to categories
        assignments = {
            'recon': recon_detectors,
            'web': web_detectors,
            'api': api_detectors,
            'vuln': vuln_detectors,
            'mobile': [d for d in mobile_detectors if d in detectors],  # Only existing ones
            'custom': custom_detectors,
        }
        
        for cat_name, detector_names in assignments.items():
            category = categories[cat_name]
            for detector_name in detector_names:
                if detector_name in detectors:
                    detector = detectors[detector_name]
                    category.detectors.add(detector)
            
            count = len([d for d in detector_names if d in detectors])
            self.stdout.write(f'   ➡️  {category.display_name}: {count} detectors assigned')

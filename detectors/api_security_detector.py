"""
API Security Detector
=====================
Advanced detector for REST API security vulnerabilities including:
- Mass Assignment
- Excessive Data Exposure
- Broken Function Level Authorization (BFLA)
- API Key Leakage
- Insecure Direct Object References (IDOR)
- Missing Rate Limiting
- Verbose Error Messages
"""

import asyncio
import json
import re
from typing import Dict, List, Any
from detectors.registry import register_active

# Test payloads for Mass Assignment
MASS_ASSIGNMENT_FIELDS = [
    "is_admin", "isAdmin", "admin", "role", "is_verified", "verified",
    "premium", "is_premium", "pro", "is_pro", "subscription_level",
    "balance", "credits", "points", "permissions", "access_level"
]

# IDOR test patterns
IDOR_ID_PATTERNS = [
    r'/users?/(\d+)',
    r'/accounts?/(\d+)',
    r'/profiles?/(\d+)',
    r'/orders?/(\d+)',
    r'/invoices?/(\d+)',
    r'/documents?/(\d+)',
    r'[?&]id=(\d+)',
    r'[?&]user_id=(\d+)',
    r'[?&]account_id=(\d+)',
]

# Sensitive data patterns in responses
SENSITIVE_PATTERNS = {
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
    'api_key': r'\b[A-Za-z0-9]{32,}\b',
    'jwt': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    'password_hash': r'\$2[ayb]\$.{56}',
}

# Error messages that reveal too much
VERBOSE_ERROR_PATTERNS = [
    r'at line \d+',
    r'stack trace',
    r'SQLException',
    r'ORA-\d+',
    r'MySQL error',
    r'PostgreSQL',
    r'mongodb',
    r'Exception in thread',
    r'Traceback \(most recent call last\)',
    r'File ".*\.py"',
    r'/home/\w+/',
    r'/var/www/',
    r'C:\\',
]


@register_active
async def api_security_detector(session, url: str, context: dict) -> List[Dict[str, Any]]:
    """
    Main API security detector function.
    Tests for various API-specific vulnerabilities.
    """
    findings = []
    
    # Test 1: Mass Assignment vulnerability
    findings.extend(await test_mass_assignment(session, url, context))
    
    # Test 2: Excessive Data Exposure
    findings.extend(await test_excessive_data_exposure(session, url, context))
    
    # Test 3: IDOR (Insecure Direct Object Reference)
    findings.extend(await test_idor(session, url, context))
    
    # Test 4: Verbose Error Messages
    findings.extend(await test_verbose_errors(session, url, context))
    
    # Test 5: Missing Rate Limiting
    findings.extend(await test_rate_limiting(session, url, context))
    
    return findings


async def test_mass_assignment(session, url: str, context: dict) -> List[Dict[str, Any]]:
    """Test for Mass Assignment vulnerabilities."""
    findings = []
    
    # Skip non-API endpoints
    if not is_api_endpoint(url):
        return findings
    
    # Test with POST/PUT/PATCH
    for method in ['POST', 'PUT', 'PATCH']:
        for field in MASS_ASSIGNMENT_FIELDS[:5]:  # Test first 5 to avoid rate limits
            payload = {
                "name": "test_user",
                "email": "test@example.com",
                field: True  # Try to elevate privileges
            }
            
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': context.get('user_agent', 'BugBountyScanner/1.0')
                }
                
                resp = await session.request(
                    method,
                    url,
                    json=payload,
                    headers=headers,
                    timeout=context.get('timeout', 15),
                    allow_redirects=False
                )
                
                body = await resp.text()
                
                # Check if our field was accepted
                if field in body and resp.status in [200, 201]:
                    findings.append({
                        'type': 'Mass Assignment',
                        'severity': 'high',
                        'confidence': 'medium',
                        'url': url,
                        'method': method,
                        'evidence': f'Field "{field}" was accepted in {method} request. Server responded with status {resp.status} and the field appears in response.',
                        'payload': json.dumps(payload),
                        'impact': f'Attacker may be able to modify sensitive fields like "{field}" to escalate privileges or bypass restrictions.',
                        'recommendation': 'Implement allowlist-based parameter binding. Only accept explicitly defined fields in API requests.',
                        'cvss': 7.5,
                        'detector': 'api_security_detector'
                    })
                    break  # Found vulnerability for this field
                    
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue
    
    return findings


async def test_excessive_data_exposure(session, url: str, context: dict) -> List[Dict[str, Any]]:
    """Test for Excessive Data Exposure in API responses."""
    findings = []
    
    if not is_api_endpoint(url):
        return findings
    
    try:
        headers = {
            'Accept': 'application/json',
            'User-Agent': context.get('user_agent', 'BugBountyScanner/1.0')
        }
        
        resp = await session.get(
            url,
            headers=headers,
            timeout=context.get('timeout', 15),
            allow_redirects=True
        )
        
        body = await resp.text()
        
        # Check if response contains sensitive data
        exposed_data = []
        for data_type, pattern in SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, body)
            if matches:
                exposed_data.append({
                    'type': data_type,
                    'count': len(matches),
                    'sample': matches[0] if data_type != 'password_hash' else '[REDACTED]'
                })
        
        # Check for common sensitive field names in JSON
        if 'application/json' in resp.headers.get('Content-Type', ''):
            try:
                json_data = json.loads(body)
                sensitive_fields = find_sensitive_fields(json_data)
                if sensitive_fields:
                    exposed_data.append({
                        'type': 'sensitive_fields',
                        'fields': sensitive_fields
                    })
            except:
                pass
        
        if exposed_data:
            findings.append({
                'type': 'Excessive Data Exposure',
                'severity': 'medium',
                'confidence': 'high',
                'url': url,
                'method': 'GET',
                'evidence': f'API endpoint exposes sensitive data: {json.dumps(exposed_data, indent=2)}',
                'impact': 'API returns more data than necessary, potentially exposing sensitive information to unauthorized users.',
                'recommendation': 'Filter API responses to return only necessary fields. Implement field-level access controls.',
                'cvss': 5.3,
                'detector': 'api_security_detector'
            })
    
    except Exception:
        pass
    
    return findings


async def test_idor(session, url: str, context: dict) -> List[Dict[str, Any]]:
    """Test for IDOR (Insecure Direct Object Reference) vulnerabilities."""
    findings = []
    
    # Extract IDs from URL
    extracted_ids = []
    for pattern in IDOR_ID_PATTERNS:
        matches = re.findall(pattern, url)
        extracted_ids.extend(matches)
    
    if not extracted_ids:
        return findings
    
    original_id = extracted_ids[0]
    
    # Test with incremented/decremented IDs
    test_ids = [
        str(int(original_id) + 1),
        str(int(original_id) - 1),
        str(int(original_id) + 100),
        '1',
        '999999'
    ]
    
    try:
        # Get baseline response
        headers = {
            'User-Agent': context.get('user_agent', 'BugBountyScanner/1.0')
        }
        
        baseline_resp = await session.get(
            url,
            headers=headers,
            timeout=context.get('timeout', 15),
            allow_redirects=False
        )
        baseline_body = await baseline_resp.text()
        baseline_len = len(baseline_body)
        
        if baseline_resp.status not in [200, 201]:
            return findings  # Original ID doesn't work, skip
        
        # Test other IDs
        successful_tests = []
        for test_id in test_ids:
            test_url = url
            for pattern in IDOR_ID_PATTERNS:
                test_url = re.sub(pattern, f'/{test_id}' if '/' in pattern else f'id={test_id}', test_url)
            
            try:
                test_resp = await session.get(
                    test_url,
                    headers=headers,
                    timeout=context.get('timeout', 15),
                    allow_redirects=False
                )
                test_body = await test_resp.text()
                test_len = len(test_body)
                
                # If we get a valid response with different data
                if test_resp.status in [200, 201] and abs(test_len - baseline_len) > 100:
                    successful_tests.append({
                        'id': test_id,
                        'status': test_resp.status,
                        'length': test_len,
                        'url': test_url
                    })
                    
            except Exception:
                continue
        
        if successful_tests:
            findings.append({
                'type': 'IDOR (Insecure Direct Object Reference)',
                'severity': 'high',
                'confidence': 'high',
                'url': url,
                'method': 'GET',
                'evidence': f'Successfully accessed {len(successful_tests)} other objects by manipulating ID parameter. Original ID: {original_id}',
                'vulnerable_parameter': original_id,
                'test_results': successful_tests,
                'impact': 'Attacker can access other users\' data by manipulating ID parameters in the URL.',
                'recommendation': 'Implement proper authorization checks. Verify that the authenticated user has permission to access the requested resource.',
                'cvss': 8.1,
                'detector': 'api_security_detector'
            })
    
    except Exception:
        pass
    
    return findings


async def test_verbose_errors(session, url: str, context: dict) -> List[Dict[str, Any]]:
    """Test for verbose error messages that reveal implementation details."""
    findings = []
    
    # Malformed requests to trigger errors
    test_cases = [
        {'method': 'POST', 'json': {'invalid': 'json"'}},  # Malformed JSON
        {'method': 'GET', 'params': {'id': "'; DROP TABLE users--"}},  # SQL injection attempt
        {'method': 'GET', 'params': {'id': '../../../etc/passwd'}},  # Path traversal
        {'method': 'GET', 'params': {'id': 'null'}},  # Null value
    ]
    
    for test in test_cases:
        try:
            headers = {
                'User-Agent': context.get('user_agent', 'BugBountyScanner/1.0')
            }
            
            resp = await session.request(
                test['method'],
                url,
                headers=headers,
                timeout=context.get('timeout', 10),
                allow_redirects=False,
                **{k: v for k, v in test.items() if k != 'method'}
            )
            
            body = await resp.text()
            
            # Check for verbose error patterns
            found_patterns = []
            for pattern in VERBOSE_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    found_patterns.append(pattern)
            
            if found_patterns:
                findings.append({
                    'type': 'Verbose Error Messages',
                    'severity': 'low',
                    'confidence': 'high',
                    'url': url,
                    'method': test['method'],
                    'evidence': f'Server revealed implementation details in error message. Patterns found: {found_patterns[:3]}',
                    'impact': 'Error messages reveal technology stack, file paths, or internal structure, aiding attackers in reconnaissance.',
                    'recommendation': 'Implement generic error messages for users. Log detailed errors server-side only.',
                    'cvss': 3.7,
                    'detector': 'api_security_detector'
                })
                break  # One finding per endpoint
                
        except Exception:
            continue
    
    return findings


async def test_rate_limiting(session, url: str, context: dict) -> List[Dict[str, Any]]:
    """Test for missing rate limiting on API endpoints."""
    findings = []
    
    if not is_api_endpoint(url):
        return findings
    
    # Send 20 rapid requests
    requests_count = 20
    successful_requests = 0
    
    try:
        headers = {
            'User-Agent': context.get('user_agent', 'BugBountyScanner/1.0')
        }
        
        tasks = []
        for _ in range(requests_count):
            tasks.append(
                session.get(
                    url,
                    headers=headers,
                    timeout=5,
                    allow_redirects=False
                )
            )
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful responses (no rate limiting)
        for resp in responses:
            if not isinstance(resp, Exception) and resp.status == 200:
                successful_requests += 1
        
        # If more than 80% of requests succeeded, likely no rate limiting
        if successful_requests > requests_count * 0.8:
            findings.append({
                'type': 'Missing Rate Limiting',
                'severity': 'low',
                'confidence': 'medium',
                'url': url,
                'method': 'GET',
                'evidence': f'{successful_requests}/{requests_count} rapid requests succeeded without rate limiting.',
                'impact': 'API endpoint lacks rate limiting, allowing potential DoS attacks or brute force attempts.',
                'recommendation': 'Implement rate limiting per IP/user. Use algorithms like token bucket or sliding window.',
                'cvss': 4.3,
                'detector': 'api_security_detector'
            })
    
    except Exception:
        pass
    
    return findings


def is_api_endpoint(url: str) -> bool:
    """Check if URL is likely an API endpoint."""
    api_indicators = [
        '/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
        '/oauth/', '/auth/', '/users/', '/accounts/', '/data/',
        '.json', '/api', 'api.'
    ]
    
    url_lower = url.lower()
    return any(indicator in url_lower for indicator in api_indicators)


def find_sensitive_fields(data, prefix='') -> List[str]:
    """Recursively find sensitive field names in JSON data."""
    sensitive_keywords = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'private_key', 'privatekey', 'ssn', 'social_security', 'credit_card',
        'card_number', 'cvv', 'pin', 'auth', 'session', 'cookie'
    ]
    
    found_fields = []
    
    if isinstance(data, dict):
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            
            # Check if key name is sensitive
            if any(keyword in key.lower() for keyword in sensitive_keywords):
                found_fields.append(full_key)
            
            # Recurse into nested structures
            if isinstance(value, (dict, list)):
                found_fields.extend(find_sensitive_fields(value, full_key))
    
    elif isinstance(data, list):
        for i, item in enumerate(data[:3]):  # Check first 3 items only
            if isinstance(item, (dict, list)):
                found_fields.extend(find_sensitive_fields(item, f"{prefix}[{i}]"))
    
    return found_fields

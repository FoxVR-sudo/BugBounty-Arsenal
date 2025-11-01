# detectors/idor_detector.py
# Active IDOR (Insecure Direct Object Reference) detector
# Tests for authorization bypass by manipulating object IDs in URLs and parameters

import re
import uuid
import asyncio
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any

from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)


def extract_ids_from_url(url: str) -> List[Dict[str, Any]]:
    """
    Extract potential object IDs from URL path and query parameters.
    Returns list of dicts with: {type, location, param, value, original_url}
    """
    ids = []
    parsed = urlparse(url)
    
    # Extract from path - look for numeric IDs
    # e.g., /api/users/123, /documents/456/view
    path_parts = [p for p in parsed.path.split('/') if p]
    for i, part in enumerate(path_parts):
        # Numeric IDs
        if re.match(r'^\d+$', part):
            ids.append({
                'type': 'numeric',
                'location': 'path',
                'param': f'path_segment_{i}',
                'value': part,
                'original_url': url,
                'path_index': i
            })
        
        # UUID format
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', part, re.I):
            ids.append({
                'type': 'uuid',
                'location': 'path',
                'param': f'path_segment_{i}',
                'value': part,
                'original_url': url,
                'path_index': i
            })
        
        # Short hex IDs (e.g., MongoDB ObjectId style)
        if re.match(r'^[0-9a-f]{24}$', part, re.I):
            ids.append({
                'type': 'objectid',
                'location': 'path',
                'param': f'path_segment_{i}',
                'value': part,
                'original_url': url,
                'path_index': i
            })
    
    # Extract from query parameters
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for param, values in qs.items():
        if not values:
            continue
        value = values[0] if isinstance(values, list) else values
        
        # Look for common ID parameter names
        id_params = ['id', 'user_id', 'userid', 'doc_id', 'document_id', 'file_id', 
                     'order_id', 'account_id', 'customer_id', 'item_id', 'post_id',
                     'message_id', 'ticket_id', 'invoice_id']
        
        param_lower = param.lower()
        is_id_param = any(id_name in param_lower for id_name in id_params)
        
        # Numeric IDs
        if re.match(r'^\d+$', str(value)):
            ids.append({
                'type': 'numeric',
                'location': 'query',
                'param': param,
                'value': str(value),
                'original_url': url,
                'is_id_param': is_id_param
            })
        
        # UUID format
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', str(value), re.I):
            ids.append({
                'type': 'uuid',
                'location': 'query',
                'param': param,
                'value': str(value),
                'original_url': url,
                'is_id_param': is_id_param
            })
        
        # ObjectId style
        if re.match(r'^[0-9a-f]{24}$', str(value), re.I):
            ids.append({
                'type': 'objectid',
                'location': 'query',
                'param': param,
                'value': str(value),
                'original_url': url,
                'is_id_param': is_id_param
            })
    
    return ids


def generate_test_ids(original_id: str, id_type: str) -> List[str]:
    """
    Generate test IDs based on the original ID type.
    Returns list of alternative IDs to test for IDOR.
    """
    test_ids = []
    
    if id_type == 'numeric':
        try:
            num = int(original_id)
            # Test nearby IDs (might be other users/objects)
            test_ids.extend([
                str(num - 1),
                str(num + 1),
                str(num - 10),
                str(num + 10),
                '1',  # First object
                '999999',  # High ID
                '0',  # Edge case
            ])
        except ValueError:
            pass
    
    elif id_type == 'uuid':
        # Generate different UUIDs
        test_ids.extend([
            str(uuid.uuid4()),
            '00000000-0000-0000-0000-000000000001',
            'ffffffff-ffff-ffff-ffff-ffffffffffff',
        ])
    
    elif id_type == 'objectid':
        # Generate similar ObjectId-style IDs
        import random
        test_ids.extend([
            ''.join(random.choices('0123456789abcdef', k=24)) for _ in range(3)
        ])
    
    # Remove duplicates and original
    test_ids = [tid for tid in test_ids if tid != original_id]
    return list(dict.fromkeys(test_ids))  # dedupe preserving order


def build_test_url(parsed_url, id_info: Dict, new_id: str) -> str:
    """
    Build a new URL with the modified ID.
    """
    if id_info['location'] == 'path':
        # Replace path segment
        path_parts = [p for p in parsed_url.path.split('/')]
        idx = id_info['path_index']
        if idx < len(path_parts):
            path_parts[idx] = new_id
        new_path = '/'.join(path_parts)
        
        return urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            new_path,
            parsed_url.params,
            parsed_url.query,
            parsed_url.fragment
        ))
    
    elif id_info['location'] == 'query':
        # Replace query parameter
        qs = parse_qs(parsed_url.query, keep_blank_values=True)
        qs[id_info['param']] = [new_id]
        new_query = urlencode(qs, doseq=True)
        
        return urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
    
    return id_info['original_url']


async def test_idor(session, original_url: str, id_info: Dict, per_host_rate: float = None) -> List[Dict]:
    """
    Test for IDOR vulnerability by trying different IDs.
    Returns list of findings.
    """
    findings = []
    parsed = urlparse(original_url)
    host = parsed.netloc.lower()
    
    try:
        # Get original response
        if per_host_rate:
            await await_host_token(host, per_host_rate)
        
        async with session.get(original_url, timeout=15, allow_redirects=False) as resp:
            original_status = resp.status
            original_text = await resp.text()
            original_length = len(original_text)
            original_headers = dict(resp.headers)
        
        # Skip if original request failed
        if original_status >= 400:
            return findings
        
        # Generate test IDs
        test_ids = generate_test_ids(id_info['value'], id_info['type'])
        
        # Test each ID
        successful_access = []
        for test_id in test_ids[:5]:  # Limit to 5 tests per ID to avoid too many requests
            test_url = build_test_url(parsed, id_info, test_id)
            
            if per_host_rate:
                await await_host_token(host, per_host_rate)
            
            try:
                async with session.get(test_url, timeout=15, allow_redirects=False) as resp:
                    test_status = resp.status
                    test_text = await resp.text()
                    test_length = len(test_text)
                    
                    # Check for successful access to different object
                    # Indicators of IDOR:
                    # 1. Same status code as original (200, 201, etc.)
                    # 2. Similar response length (not error page)
                    # 3. Different content (different object)
                    
                    if test_status == original_status and test_status < 300:
                        # Similar response length (within 20% tolerance)
                        length_diff_pct = abs(test_length - original_length) / max(original_length, 1) * 100
                        
                        if length_diff_pct < 80:  # Response is similar in size
                            # Check if content is actually different
                            content_diff = test_text != original_text
                            
                            if content_diff or length_diff_pct > 5:  # Some difference exists
                                successful_access.append({
                                    'test_id': test_id,
                                    'test_url': test_url,
                                    'status': test_status,
                                    'length': test_length,
                                    'length_diff_pct': round(length_diff_pct, 2)
                                })
                
            except Exception as e:
                logger.debug(f"IDOR test failed for {test_url}: {e}")
                continue
        
        # If we successfully accessed other objects, it's likely IDOR
        if successful_access:
            confidence = 'high' if len(successful_access) > 2 else 'medium'
            severity = 'high' if id_info.get('is_id_param') or 'user' in str(id_info.get('param', '')).lower() else 'medium'
            
            evidence = f"Original ID '{id_info['value']}' in {id_info['location']} ({id_info['param']}) "
            evidence += f"can be replaced with other IDs to access different objects. "
            evidence += f"Successfully accessed {len(successful_access)} different objects: "
            evidence += ", ".join([f"{sa['test_id']} (HTTP {sa['status']}, {sa['length']} bytes)" 
                                  for sa in successful_access[:3]])
            
            findings.append({
                'type': 'IDOR (Insecure Direct Object Reference)',
                'severity': severity,
                'confidence': confidence,
                'evidence': evidence,
                'url': original_url,
                'vulnerable_parameter': id_info['param'],
                'parameter_location': id_info['location'],
                'original_id': id_info['value'],
                'id_type': id_info['type'],
                'test_results': successful_access,
                'impact': f"Unauthorized access to other {id_info['param']} objects by manipulating ID values",
                'recommendation': 'Implement proper authorization checks to verify user has access to requested object ID'
            })
    
    except Exception as e:
        logger.debug(f"IDOR testing error for {original_url}: {e}")
    
    return findings


@register_active
async def idor_detector(session, url: str, context: Dict) -> List[Dict]:
    """
    Active IDOR detector.
    
    Detects Insecure Direct Object Reference vulnerabilities by:
    1. Identifying object IDs in URLs (path and query params)
    2. Testing access to different object IDs
    3. Detecting if unauthorized access is possible
    
    Context keys:
      - per_host_rate: float (requests per second limit)
    
    Returns: list of findings
    """
    findings = []
    
    if not url:
        return findings
    
    per_host_rate = context.get('per_host_rate', 1.0)
    
    try:
        # Extract potential IDs from URL
        id_candidates = extract_ids_from_url(url)
        
        if not id_candidates:
            return findings
        
        # Test each ID candidate
        for id_info in id_candidates:
            idor_findings = await test_idor(session, url, id_info, per_host_rate)
            findings.extend(idor_findings)
            
            # Limit findings to avoid overwhelming report
            if len(findings) >= 3:
                break
    
    except Exception as e:
        logger.error(f"IDOR detector error for {url}: {e}")
    
    return findings

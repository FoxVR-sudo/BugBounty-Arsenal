"""
Subscription tier definitions for detector access control
"""

# Basic tier detectors (free)
BASIC_DETECTORS = [
    'reflection_detector',
    'sql_pattern_detector',
    'xss_pattern_detector',
    'open_redirect_detector',
    'security_headers_detector',
    'dir_listing_detector',
]

# Advanced tier detectors
ADVANCED_DETECTORS = BASIC_DETECTORS + [
    'ssrf_detector',
    'advanced_ssrf_detector',
    'csrf_detector',
    'lfi_detector',
    'header_injection_detector',
    'secret_detector',
    'idor_detector',
    'command_injection_detector',
    'xxe_detector',
    'ssti_detector',
]

# Enterprise tier detectors (all)
ENTERPRISE_DETECTORS = ADVANCED_DETECTORS + [
    'ssrf_oob_detector',
    'graphql_detector',
    'jwt_detector',
    'file_upload_detector',
    'subdomain_takeover_detector',
    'cors_detector',
    'oauth_detector',
    'cache_poisoning_detector',
    'prototype_pollution_detector',
    'nosql_injection_detector',
    'api_security_detector',
    'auth_bypass_detector',
    'rate_limit_bypass_detector',
    'brute_force_detector',
    'jwt_vulnerability_scanner',
    'race_condition_detector',
    'graphql_injection_detector',
    'simple_file_list_detector',
    'basic_param_fuzzer',
    'fuzz_detector',
    'injector',
]

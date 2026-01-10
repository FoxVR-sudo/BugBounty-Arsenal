"""
Detector Categories and Plan-based Access Control
Maps all detectors to categories and defines which plans can access them.
"""

# Detector Categories
DETECTOR_CATEGORIES = {
    # WEB SCANNING - Basic web vulnerabilities (All plans)
    'web': {
        'name': 'Web Security',
        'icon': '🌐',
        'description': 'Basic web vulnerability scanning',
        'detectors': [
            'xss_pattern_detector',
            'sql_pattern_detector',
            'lfi_detector',
            'open_redirect_detector',
            'xxe_detector',
            'ssti_detector',
            'csrf_detector',
            'cors_detector',
            'security_headers_detector',
            'dir_listing_detector',
            'reflection_detector',
        ],
        'required_plan': 'free',  # Available to all plans
    },
    
    # INJECTION ATTACKS - Advanced injection testing (Pro+)
    'injection': {
        'name': 'Injection Attacks',
        'icon': '💉',
        'description': 'Advanced SQL, NoSQL, Command injection',
        'detectors': [
            'command_injection_detector',
            'nosql_injection_detector',
            'graphql_injection_detector',
            'header_injection_detector',
            'prototype_pollution_detector',
        ],
        'required_plan': 'pro',
    },
    
    # API SECURITY - API testing tools (Pro+)
    'api': {
        'name': 'API Security',
        'icon': '🔌',
        'description': 'REST, GraphQL, API documentation discovery',
        'detectors': [
            'api_security_detector',
            'graphql_detector',
            'api_docs_discovery',
            'jwt_detector',
            'jwt_vulnerability_scanner',
            'oauth_detector',
        ],
        'required_plan': 'pro',
    },
    
    # SSRF & OOB - Out-of-band testing (Enterprise only)
    'ssrf': {
        'name': 'SSRF & OOB',
        'icon': '🔗',
        'description': 'Server-Side Request Forgery & Out-of-Band attacks',
        'detectors': [
            'ssrf_detector',
            'advanced_ssrf_detector',
            'ssrf_oob_detector',
            'ssrf_oob_advanced_detector',
        ],
        'required_plan': 'enterprise',
    },
    
    # AUTHENTICATION - Auth testing (Pro+)
    'auth': {
        'name': 'Authentication',
        'icon': '🔐',
        'description': 'Authentication bypass, brute force, session attacks',
        'detectors': [
            'auth_bypass_detector',
            'brute_force_detector',
            'rate_limit_bypass_detector',
            'race_condition_detector',
        ],
        'required_plan': 'pro',
    },
    
    # BUSINESS LOGIC - Logic flaws (Enterprise)
    'business_logic': {
        'name': 'Business Logic',
        'icon': '💼',
        'description': 'Business logic flaws, IDOR, access control',
        'detectors': [
            'idor_detector',
            'business_logic_detector',
            'cache_poisoning_detector',
        ],
        'required_plan': 'enterprise',
    },
    
    # RECONNAISSANCE - Information gathering (All plans)
    'recon': {
        'name': 'Reconnaissance',
        'icon': '🔍',
        'description': 'Subdomain discovery, secret detection, file hunting',
        'detectors': [
            'subdomain_takeover_detector',
            'secret_detector',
            'js_file_analyzer',
            'backup_file_hunter',
            'simple_file_list_detector',
            'old_domain_hunter',
            'github_osint',
        ],
        'required_plan': 'free',
    },
    
    # FUZZING - Advanced fuzzing (Pro+)
    'fuzzing': {
        'name': 'Fuzzing',
        'icon': '⚡',
        'description': 'Parameter fuzzing, file upload, CVE scanning',
        'detectors': [
            'basic_param_fuzzer',
            'parameter_fuzzer',
            'fuzz_detector',
            'file_upload_detector',
            'cve_database_detector',
        ],
        'required_plan': 'pro',
    },
}


# Plan-based access levels
PLAN_ACCESS = {
    'free': ['web', 'recon'],
    'pro': ['web', 'recon', 'injection', 'api', 'auth', 'fuzzing'],
    'enterprise': ['web', 'recon', 'injection', 'api', 'auth', 'fuzzing', 'ssrf', 'business_logic'],
}


def get_allowed_detectors_for_plan(plan_name: str) -> list:
    """
    Get list of all detector names allowed for a specific plan.
    
    Args:
        plan_name: Plan name ('free', 'pro', 'enterprise')
        
    Returns:
        List of detector names
    """
    allowed_categories = PLAN_ACCESS.get(plan_name, [])
    detectors = []
    
    for category_key in allowed_categories:
        category = DETECTOR_CATEGORIES.get(category_key, {})
        detectors.extend(category.get('detectors', []))
    
    return detectors


def get_detector_category(detector_name: str) -> dict:
    """
    Get category information for a specific detector.
    
    Args:
        detector_name: Name of the detector
        
    Returns:
        Dict with category info or None
    """
    for category_key, category_data in DETECTOR_CATEGORIES.items():
        if detector_name in category_data['detectors']:
            return {
                'key': category_key,
                'name': category_data['name'],
                'icon': category_data['icon'],
                'required_plan': category_data['required_plan'],
            }
    return None


def is_detector_allowed_for_plan(detector_name: str, plan_name: str) -> bool:
    """
    Check if a detector is allowed for a specific plan.
    
    Args:
        detector_name: Name of the detector
        plan_name: Plan name ('free', 'pro', 'enterprise')
        
    Returns:
        bool
    """
    allowed = get_allowed_detectors_for_plan(plan_name)
    return detector_name in allowed


def get_categories_for_plan(plan_name: str) -> list:
    """
    Get all categories with their detectors for a specific plan.
    Marks each detector as locked/unlocked based on plan.
    
    Args:
        plan_name: Plan name ('free', 'pro', 'enterprise')
        
    Returns:
        List of category dicts with detector info
    """
    allowed_categories = PLAN_ACCESS.get(plan_name, [])
    result = []
    
    for category_key, category_data in DETECTOR_CATEGORIES.items():
        is_allowed = category_key in allowed_categories
        
        result.append({
            'key': category_key,
            'name': category_data['name'],
            'icon': category_data['icon'],
            'description': category_data['description'],
            'required_plan': category_data['required_plan'],
            'is_allowed': is_allowed,
            'detectors': [
                {
                    'name': detector,
                    'is_allowed': is_allowed,
                }
                for detector in category_data['detectors']
            ],
            'detector_count': len(category_data['detectors']),
        })
    
    return result

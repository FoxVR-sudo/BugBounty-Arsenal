"""
Subscription tier management for BugBounty Arsenal SaaS.
Defines feature limits and detector access per tier.
"""
from enum import Enum
from typing import List, Dict, Optional
from dataclasses import dataclass


class SubscriptionTier(str, Enum):
    """Available subscription tiers."""
    FREE = "free"
    BASIC = "basic"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass
class TierLimits:
    """Feature limits for a subscription tier."""
    # Scan limits
    max_concurrent_scans: int
    max_urls_per_scan: int
    daily_scan_limit: int  # Daily scan quota (0 = unlimited for ENTERPRISE)
    
    # Recon limits (since tools are open source)
    enable_recon_pipeline: bool
    max_subdomains_to_scan: int  # Limit discovered subdomains
    enable_subdomain_takeover: bool
    enable_cloud_metadata: bool  # AWS/Azure/GCP metadata checks
    
    # Feature flags
    enable_nuclei: bool
    enable_mobile_scanner: bool
    enable_cloudflare_solver: bool
    enable_api_access: bool
    enable_scheduled_scans: bool
    enable_team_collaboration: bool
    
    # Detector groups
    allowed_detectors: List[str]
    
    # Export options
    enable_json_export: bool
    enable_markdown_export: bool
    enable_pdf_export: bool
    
    # Rate limiting
    requests_per_host: float
    scan_timeout_minutes: int
    
    # Quality of life
    enable_custom_wordlists: bool
    enable_notifications: bool  # Slack/email/webhook


# Detector categories
BASIC_DETECTORS = [
    "xss_pattern_detector",
    "sql_pattern_detector",
    "security_headers_detector",
    "open_redirect_detector",
    "secret_detector",
]

ADVANCED_DETECTORS = [
    "idor_detector",
    "csrf_detector",
    "cors_detector",
    "lfi_detector",
    "xxe_detector",
    "ssti_detector",
    "command_injection_detector",
    "jwt_detector",
    "nosql_injection_detector",
    "graphql_detector",
    "prototype_pollution_detector",
    "race_condition_detector",
    "dir_listing_detector",
    "file_upload_detector",
]

ENTERPRISE_DETECTORS = [
    "ssrf_detector",
    "advanced_ssrf_detector",
    "ssrf_oob_detector",
    "auth_bypass_detector",
    "api_security_detector",
    "cache_poisoning_detector",
    "header_injection_detector",
    "oauth_detector",
    "rate_limit_bypass_detector",
    "brute_force_detector",
]


# Pricing in EUR (monthly)
TIER_PRICING = {
    SubscriptionTier.FREE: {"monthly": 0, "currency": "EUR"},
    SubscriptionTier.BASIC: {"monthly": 4.99, "currency": "EUR"},
    SubscriptionTier.PRO: {"monthly": 9.99, "currency": "EUR"},
    SubscriptionTier.ENTERPRISE: {"monthly": 49.99, "currency": "EUR"},
}

# Tier configurations
TIER_LIMITS: Dict[SubscriptionTier, TierLimits] = {
    SubscriptionTier.FREE: TierLimits(
        max_concurrent_scans=1,
        max_urls_per_scan=5,
        daily_scan_limit=3,  # 3 scans per day
        enable_recon_pipeline=True,  # Open source tools available
        max_subdomains_to_scan=10,  # But limit scope
        enable_subdomain_takeover=False,
        enable_cloud_metadata=False,
        enable_nuclei=False,
        enable_mobile_scanner=False,
        enable_cloudflare_solver=False,
        enable_api_access=False,
        enable_scheduled_scans=False,
        enable_team_collaboration=False,
        allowed_detectors=BASIC_DETECTORS,
        enable_json_export=False,
        enable_markdown_export=False,
        enable_pdf_export=False,
        requests_per_host=0.5,
        scan_timeout_minutes=10,
        enable_custom_wordlists=False,
        enable_notifications=False,
    ),
    
    SubscriptionTier.BASIC: TierLimits(
        max_concurrent_scans=2,
        max_urls_per_scan=20,
        daily_scan_limit=10,  # 10 scans per day
        enable_recon_pipeline=True,
        max_subdomains_to_scan=25,
        enable_subdomain_takeover=False,
        enable_cloud_metadata=False,
        enable_nuclei=False,
        enable_mobile_scanner=False,
        enable_cloudflare_solver=False,
        enable_api_access=False,
        enable_scheduled_scans=False,
        enable_team_collaboration=False,
        allowed_detectors=BASIC_DETECTORS + ADVANCED_DETECTORS[:5],  # 10 detectors total
        enable_json_export=True,
        enable_markdown_export=True,
        enable_pdf_export=False,
        requests_per_host=1.0,
        scan_timeout_minutes=30,
        enable_custom_wordlists=False,
        enable_notifications=False,
    ),
    
    SubscriptionTier.PRO: TierLimits(
        max_concurrent_scans=3,
        max_urls_per_scan=100,
        daily_scan_limit=50,  # 50 scans per day
        enable_recon_pipeline=True,
        max_subdomains_to_scan=100,  # More scope
        enable_subdomain_takeover=True,
        enable_cloud_metadata=True,
        enable_nuclei=False,  # Reserved for ENTERPRISE
        enable_mobile_scanner=False,
        enable_cloudflare_solver=True,
        enable_api_access=False,
        enable_scheduled_scans=True,
        enable_team_collaboration=True,  # Up to 3 seats
        allowed_detectors=BASIC_DETECTORS + ADVANCED_DETECTORS,
        enable_json_export=True,
        enable_markdown_export=True,
        enable_pdf_export=False,
        requests_per_host=1.5,
        scan_timeout_minutes=60,
        enable_custom_wordlists=True,
        enable_notifications=True,
    ),
    
    SubscriptionTier.ENTERPRISE: TierLimits(
        max_concurrent_scans=10,
        max_urls_per_scan=0,  # Unlimited
        daily_scan_limit=0,  # Unlimited daily scans
        enable_recon_pipeline=True,
        max_subdomains_to_scan=999999,  # Unlimited
        enable_subdomain_takeover=True,
        enable_cloud_metadata=True,
        enable_nuclei=True,
        enable_mobile_scanner=True,
        enable_cloudflare_solver=True,
        enable_api_access=True,
        enable_scheduled_scans=True,
        enable_team_collaboration=True,  # Unlimited seats
        allowed_detectors=BASIC_DETECTORS + ADVANCED_DETECTORS + ENTERPRISE_DETECTORS,
        enable_json_export=True,
        enable_markdown_export=True,
        enable_pdf_export=True,
        requests_per_host=3.0,
        scan_timeout_minutes=180,
        enable_custom_wordlists=True,
        enable_notifications=True,
    ),
}


def get_tier_limits(tier: SubscriptionTier) -> TierLimits:
    """Get feature limits for a subscription tier."""
    return TIER_LIMITS[tier]


def can_start_scan(tier: SubscriptionTier, current_active_scans: int) -> tuple[bool, Optional[str]]:
    """
    Check if user can start a new scan based on their tier.
    
    Returns:
        (allowed, error_message)
    """
    limits = get_tier_limits(tier)
    
    if current_active_scans >= limits.max_concurrent_scans:
        return False, f"Concurrent scan limit reached ({limits.max_concurrent_scans}). Upgrade for more."
    
    return True, None


def validate_scan_scope(tier: SubscriptionTier, url_count: int) -> tuple[bool, Optional[str]]:
    """
    Validate if scope size is allowed for tier.
    
    Returns:
        (allowed, error_message)
    """
    limits = get_tier_limits(tier)
    
    if url_count > limits.max_urls_per_scan:
        return False, f"URL limit exceeded ({limits.max_urls_per_scan}). Upgrade to scan more targets."
    
    return True, None


def is_detector_allowed(tier: SubscriptionTier, detector_name: str) -> bool:
    """Check if a detector is allowed for the given tier."""
    limits = get_tier_limits(tier)
    return detector_name in limits.allowed_detectors


def filter_detectors_by_tier(tier: SubscriptionTier, all_detectors: List[str]) -> List[str]:
    """Filter detector list based on tier permissions."""
    limits = get_tier_limits(tier)
    return [d for d in all_detectors if d in limits.allowed_detectors]


def get_tier_display_info(tier: SubscriptionTier) -> Dict[str, any]:
    """Get human-readable tier information for UI display."""
    limits = get_tier_limits(tier)
    
    return {
        "name": tier.value.upper(),
        "concurrent_scans": limits.max_concurrent_scans,
        "max_urls": limits.max_urls_per_scan if limits.max_urls_per_scan < 999999 else "Unlimited",
        "recon_pipeline": "✓" if limits.enable_recon_pipeline else "✗",
        "nuclei": "✓" if limits.enable_nuclei else "✗",
        "mobile_scanner": "✓" if limits.enable_mobile_scanner else "✗",
        "detectors": f"{len(limits.allowed_detectors)} detectors",
        "json_export": "✓" if limits.enable_json_export else "✗",
    }

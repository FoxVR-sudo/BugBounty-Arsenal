"""
Dynamic Subscription Management - Uses Plan model from database
Replaces hardcoded tier system with DB-driven plans
"""
import json
from typing import List, Dict, Optional
from dataclasses import dataclass
from sqlalchemy.orm import Session
from models import Plan, Subscription, User


@dataclass
class PlanLimits:
    """Feature limits parsed from Plan.limits JSON"""
    scans_per_day: int
    max_concurrent_scans: int
    max_targets_per_scan: int
    max_scan_duration_minutes: int
    api_access: bool
    advanced_detectors: bool
    mobile_scanning: bool
    recon_mode: bool
    priority_support: bool
    nuclei_templates: bool = False


def get_user_plan(user_id: int, db: Session) -> Optional[Plan]:
    """Get user's active plan from database"""
    subscription = db.query(Subscription).filter(
        Subscription.user_id == user_id
    ).first()
    
    if not subscription or not subscription.plan_id:
        # Return FREE plan by default
        return db.query(Plan).filter(Plan.name == "FREE").first()
    
    return db.query(Plan).filter(Plan.id == subscription.plan_id).first()


def parse_plan_limits(plan: Plan) -> PlanLimits:
    """Parse Plan.limits JSON into PlanLimits dataclass"""
    if not plan or not plan.limits:
        # Default FREE limits
        return PlanLimits(
            scans_per_day=5,
            max_concurrent_scans=1,
            max_targets_per_scan=10,
            max_scan_duration_minutes=30,
            api_access=False,
            advanced_detectors=False,
            mobile_scanning=False,
            recon_mode=False,
            priority_support=False,
            nuclei_templates=False
        )
    
    try:
        limits_data = json.loads(plan.limits) if isinstance(plan.limits, str) else plan.limits
        return PlanLimits(
            scans_per_day=limits_data.get("scans_per_day", 5),
            max_concurrent_scans=limits_data.get("max_concurrent_scans", 1),
            max_targets_per_scan=limits_data.get("max_targets_per_scan", 10),
            max_scan_duration_minutes=limits_data.get("max_scan_duration_minutes", 30),
            api_access=limits_data.get("api_access", False),
            advanced_detectors=limits_data.get("advanced_detectors", False),
            mobile_scanning=limits_data.get("mobile_scanning", False),
            recon_mode=limits_data.get("recon_mode", False),
            priority_support=limits_data.get("priority_support", False),
            nuclei_templates=limits_data.get("nuclei_templates", False)
        )
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"Error parsing plan limits: {e}")
        # Return safe defaults
        return parse_plan_limits(None)


def can_user_scan(user: User, db: Session, current_active_scans: int = 0) -> tuple[bool, Optional[str]]:
    """
    Check if user can start a new scan
    
    Returns:
        (allowed, error_message)
    """
    plan = get_user_plan(user.id, db)
    if not plan:
        return False, "No plan found. Please contact support."
    
    limits = parse_plan_limits(plan)
    
    # Check concurrent scans
    if current_active_scans >= limits.max_concurrent_scans:
        return False, f"Concurrent scan limit reached ({limits.max_concurrent_scans}). Upgrade for more."
    
    # Check daily limit
    if limits.scans_per_day != -1:  # -1 means unlimited
        # TODO: Check daily scan count from Subscription.daily_scans_count
        pass
    
    return True, None


def validate_scan_scope(user: User, db: Session, target_count: int) -> tuple[bool, Optional[str]]:
    """
    Validate if scan scope is allowed
    
    Returns:
        (allowed, error_message)
    """
    plan = get_user_plan(user.id, db)
    if not plan:
        return False, "No plan found"
    
    limits = parse_plan_limits(plan)
    
    if limits.max_targets_per_scan != -1:  # -1 means unlimited
        if target_count > limits.max_targets_per_scan:
            return False, f"Target limit exceeded ({limits.max_targets_per_scan}). Upgrade to scan more."
    
    return True, None


def get_allowed_detectors(user: User, db: Session) -> List[str]:
    """Get list of allowed detectors based on user's plan"""
    plan = get_user_plan(user.id, db)
    if not plan:
        return BASIC_DETECTORS
    
    limits = parse_plan_limits(plan)
    
    # Free plan: basic detectors only
    if not limits.advanced_detectors:
        return BASIC_DETECTORS
    
    # Pro plan: all detectors
    return BASIC_DETECTORS + ADVANCED_DETECTORS + ENTERPRISE_DETECTORS


def get_plan_display_info(plan: Plan) -> Dict[str, any]:
    """Get human-readable plan information for UI"""
    if not plan:
        return {
            "name": "FREE",
            "price": "$0/mo",
            "features": ["5 scans/day", "Basic detectors"]
        }
    
    limits = parse_plan_limits(plan)
    features = json.loads(plan.features) if plan.features else []
    
    return {
        "id": plan.id,
        "name": plan.name,
        "display_name": plan.display_name,
        "price_monthly": f"${plan.price_monthly}/mo",
        "price_yearly": f"${plan.price_yearly}/yr",
        "scans_per_day": limits.scans_per_day if limits.scans_per_day != -1 else "Unlimited",
        "concurrent_scans": limits.max_concurrent_scans,
        "features": features,
        "is_active": plan.is_active
    }


# Detector categories (kept for backward compatibility)
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


# Legacy functions for backward compatibility
def get_tier_limits(tier):
    """Legacy function - use get_user_plan() instead"""
    print("⚠️ Warning: get_tier_limits() is deprecated. Use get_user_plan() instead.")
    # Return default limits
    return PlanLimits(
        scans_per_day=5,
        max_concurrent_scans=1,
        max_targets_per_scan=10,
        max_scan_duration_minutes=30,
        api_access=False,
        advanced_detectors=False,
        mobile_scanning=False,
        recon_mode=False,
        priority_support=False
    )


def get_tier_display_info(tier):
    """Legacy function - use get_plan_display_info() instead"""
    print("⚠️ Warning: get_tier_display_info() is deprecated. Use get_plan_display_info() instead.")
    return {
        "name": str(tier).upper(),
        "features": []
    }

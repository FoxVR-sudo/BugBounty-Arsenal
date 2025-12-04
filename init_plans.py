"""
Initialize plans table with FREE and PRO tiers
Run this after database migration
"""
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Plan

# Database setup
DATABASE_URL = "sqlite:///./bugbounty_arsenal.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)


def init_plans():
    """Create FREE and PRO plans in database"""
    db = SessionLocal()
    
    try:
        # Check if plans already exist
        existing = db.query(Plan).count()
        if existing > 0:
            print(f"✓ Plans already initialized ({existing} plans found)")
            return
        
        # FREE Plan
        free_plan = Plan(
            name="FREE",
            display_name="Free Plan",
            price_monthly=0.0,
            price_yearly=0.0,
            limits=json.dumps({
                "scans_per_day": 5,
                "max_concurrent_scans": 1,
                "max_targets_per_scan": 10,
                "max_scan_duration_minutes": 30,
                "api_access": False,
                "advanced_detectors": False,
                "mobile_scanning": False,
                "priority_support": False
            }),
            features=json.dumps([
                "5 scans per day",
                "Basic web security checks",
                "XSS detection",
                "SQL injection detection",
                "Security headers check",
                "Email support"
            ]),
            is_active=True,
            is_visible=True
        )
        
        # PRO Plan
        pro_plan = Plan(
            name="PRO",
            display_name="Pro Plan",
            price_monthly=49.99,
            price_yearly=499.99,
            limits=json.dumps({
                "scans_per_day": -1,  # Unlimited
                "max_concurrent_scans": 5,
                "max_targets_per_scan": 1000,
                "max_scan_duration_minutes": -1,  # Unlimited
                "api_access": True,
                "advanced_detectors": True,
                "mobile_scanning": True,
                "priority_support": True,
                "recon_mode": True,
                "nuclei_templates": True
            }),
            features=json.dumps([
                "Unlimited scans",
                "Full reconnaissance mode",
                "All 22+ detectors enabled",
                "API security testing",
                "Mobile app scanning",
                "GraphQL & REST API tests",
                "JWT vulnerability detection",
                "SSRF & XXE detection",
                "Nuclei CVE templates",
                "Priority email support",
                "Custom scan scheduling",
                "Detailed PDF reports"
            ]),
            is_active=True,
            is_visible=True,
            stripe_price_id_monthly="price_pro_monthly",  # Replace with real Stripe ID
            stripe_price_id_yearly="price_pro_yearly"     # Replace with real Stripe ID
        )
        
        db.add(free_plan)
        db.add(pro_plan)
        db.commit()
        
        print("✓ Plans initialized successfully")
        print(f"  - FREE Plan (ID: {free_plan.id})")
        print(f"  - PRO Plan (ID: {pro_plan.id})")
        
    except Exception as e:
        db.rollback()
        print(f"✗ Error initializing plans: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    print("Initializing plans...")
    init_plans()

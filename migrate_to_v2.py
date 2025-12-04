"""
Database Migration Script - V2.0 Upgrade
Migrates from old tier system to new Plan-based system
"""
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from models import Base, User, Subscription, Plan, SubscriptionTierEnum, SubscriptionStatus
import json
from datetime import datetime

DATABASE_URL = "sqlite:///./bugbounty_arsenal.db"


def migrate_to_v2():
    """Migrate database to V2.0 schema"""
    print("🔄 Starting BugBounty Arsenal V2.0 migration...")
    
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    
    try:
        # Step 1: Add new columns to existing tables
        print("\n📊 Step 1: Adding new columns...")
        
        with engine.connect() as conn:
            # Add is_admin to users table if doesn't exist
            try:
                conn.execute(text("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
                conn.commit()
                print("  ✓ Added is_admin to users")
            except Exception as e:
                if "duplicate column" not in str(e).lower():
                    print(f"  ⚠️ Could not add is_admin: {e}")
            
            # Add plan_id to subscriptions table if doesn't exist
            try:
                conn.execute(text("ALTER TABLE subscriptions ADD COLUMN plan_id INTEGER"))
                conn.commit()
                print("  ✓ Added plan_id to subscriptions")
            except Exception as e:
                if "duplicate column" not in str(e).lower():
                    print(f"  ⚠️ Could not add plan_id: {e}")
        
        # Step 2: Create plans table
        print("\n📊 Step 2: Creating plans table...")
        Base.metadata.create_all(engine)
        print("  ✓ Plans table created")
        
        # Step 3: Initialize plans
        print("\n📊 Step 3: Initializing plans...")
        
        free_plan = db.query(Plan).filter(Plan.name == "FREE").first()
        if not free_plan:
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
                    "recon_mode": False,
                    "priority_support": False
                }),
                features=json.dumps([
                    "5 scans per day",
                    "Basic web security checks",
                    "XSS detection",
                    "SQL injection detection",
                    "Security headers check"
                ]),
                is_active=True,
                is_visible=True
            )
            db.add(free_plan)
            db.commit()
            print("  ✓ FREE plan created")
        else:
            print("  ✓ FREE plan exists")
        
        pro_plan = db.query(Plan).filter(Plan.name == "PRO").first()
        if not pro_plan:
            pro_plan = Plan(
                name="PRO",
                display_name="Pro Plan",
                price_monthly=49.99,
                price_yearly=499.99,
                limits=json.dumps({
                    "scans_per_day": -1,  # Unlimited
                    "max_concurrent_scans": 5,
                    "max_targets_per_scan": 1000,
                    "max_scan_duration_minutes": -1,
                    "api_access": True,
                    "advanced_detectors": True,
                    "mobile_scanning": True,
                    "recon_mode": True,
                    "nuclei_templates": True,
                    "priority_support": True
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
                is_visible=True
            )
            db.add(pro_plan)
            db.commit()
            print("  ✓ PRO plan created")
        else:
            print("  ✓ PRO plan exists")
        
        # Step 4: Migrate existing subscriptions
        print("\n📊 Step 4: Migrating existing subscriptions...")
        
        subscriptions = db.query(Subscription).all()
        migrated = 0
        
        for sub in subscriptions:
            if sub.plan_id is None:
                # Map old tier to new plan
                if sub.tier in [SubscriptionTierEnum.FREE]:
                    sub.plan_id = free_plan.id
                elif sub.tier in [SubscriptionTierEnum.BASIC, SubscriptionTierEnum.PRO, SubscriptionTierEnum.ENTERPRISE]:
                    # Upgrade all paid users to PRO
                    sub.plan_id = pro_plan.id
                    sub.tier = SubscriptionTierEnum.PRO
                migrated += 1
        
        db.commit()
        print(f"  ✓ Migrated {migrated} subscriptions")
        
        # Step 5: Create first admin user if needed
        print("\n📊 Step 5: Checking for admin user...")
        
        admin_count = db.query(User).filter(User.is_admin == True).count()
        if admin_count == 0:
            # Make first user admin
            first_user = db.query(User).order_by(User.id).first()
            if first_user:
                first_user.is_admin = True
                db.commit()
                print(f"  ✓ Made {first_user.email} an admin")
            else:
                print("  ⚠️ No users found. Create your first user and set is_admin=True manually.")
        else:
            print(f"  ✓ {admin_count} admin(s) already exist")
        
        print("\n✅ Migration completed successfully!")
        print("\n📋 Next steps:")
        print("  1. Restart the application")
        print("  2. Log in as admin to access /admin panel")
        print("  3. Review and customize plans in admin panel")
        print("  4. Test scans with both FREE and PRO plans")
        print("\n🐳 Docker deployment:")
        print("  docker-compose up --build")
        
    except Exception as e:
        db.rollback()
        print(f"\n❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    migrate_to_v2()

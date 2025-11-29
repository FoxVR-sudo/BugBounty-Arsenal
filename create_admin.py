"""
Create superuser admin account.
Run this script once to create the admin user.
"""
from database import get_db_session
from models import User, Subscription, SubscriptionTierEnum
from auth import hash_password

def create_superuser():
    """Create admin superuser account"""
    with get_db_session() as db:
        # Check if admin already exists
        existing = db.query(User).filter(User.email == "admin@bugbountyarsenal.com").first()
        if existing:
            print("❌ Admin user already exists!")
            print(f"   Email: {existing.email}")
            print(f"   Superuser: {existing.is_superuser}")
            return
        
        # Create admin user
        admin = User(
            email="admin@bugbountyarsenal.com",
            full_name="System Administrator",
            password_hash=hash_password("admin123"),  # Simple password for testing
            is_active=True,
            is_verified=True,
            is_superuser=True
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        
        # Create ENTERPRISE subscription for admin
        subscription = Subscription(
            user_id=admin.id,
            tier=SubscriptionTierEnum.ENTERPRISE
        )
        db.add(subscription)
        db.commit()
        
        print("✓ Superuser created successfully!")
        print(f"   Email: admin@bugbountyarsenal.com")
        print(f"   Password: admin123")
        print(f"   Tier: ENTERPRISE")
        print(f"   Superuser: True")
        print("\n⚠️  IMPORTANT: Change the password after first login!")

if __name__ == "__main__":
    create_superuser()

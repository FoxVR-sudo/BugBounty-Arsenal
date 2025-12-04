#!/usr/bin/env python3
"""Quick admin account setup"""
import sys
from database import SessionLocal
from models import User
from auth import hash_password

def setup_admin():
    db = SessionLocal()
    try:
        # Find admin user
        admin = db.query(User).filter(User.email == "admin@bugbountyarsenal.com").first()
        
        if not admin:
            print("❌ Admin user not found. Creating new admin...")
            admin = User(
                email="admin@bugbountyarsenal.com",
                username="admin",
                hashed_password=hash_password("admin123"),
                is_admin=True
            )
            db.add(admin)
        else:
            print("✓ Admin user found. Resetting password...")
            admin.hashed_password = hash_password("admin123")
            admin.is_admin = True
        
        db.commit()
        
        print("\n✅ Admin account ready!")
        print("━" * 50)
        print("📧 Email:    admin@bugbountyarsenal.com")
        print("🔑 Password: admin123")
        print("━" * 50)
        print("\n🌐 Login at: http://localhost:5000/login")
        print("👑 Admin panel: http://localhost:5000/admin")
        print("\n⚠️  IMPORTANT: Change this password in production!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    setup_admin()

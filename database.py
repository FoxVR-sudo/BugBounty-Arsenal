"""
Database connection and session management.
Supports both PostgreSQL (production) and SQLite (development).
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from typing import Generator

from models import Base

# Database URL from environment or default to SQLite
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./bugbounty_arsenal.db"  # Default to SQLite for development
)

# Convert postgres:// to postgresql:// for SQLAlchemy
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Create engine
engine = create_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL query logging
    pool_pre_ping=True,  # Verify connections before using
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize database (create all tables)"""
    Base.metadata.create_all(bind=engine)
    print(f"✓ Database initialized at {DATABASE_URL}")


def get_db() -> Generator[Session, None, None]:
    """
    Dependency for FastAPI routes.
    
    Usage:
        @app.get("/users")
        def get_users(db: Session = Depends(get_db)):
            return db.query(User).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Context manager for manual database operations.
    
    Usage:
        with get_db_session() as db:
            user = db.query(User).first()
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def reset_db():
    """Drop all tables and recreate (USE WITH CAUTION!)"""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("✓ Database reset complete")


if __name__ == "__main__":
    # Initialize database when run directly
    init_db()

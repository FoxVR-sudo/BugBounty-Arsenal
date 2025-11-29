"""
Database models for BugBounty Arsenal.
Uses SQLAlchemy ORM with PostgreSQL/SQLite support.
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Float, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session
import enum

Base = declarative_base()


class SubscriptionTierEnum(str, enum.Enum):
    """Subscription tier enum matching subscription.py"""
    FREE = "free"
    BASIC = "basic"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class SubscriptionStatus(str, enum.Enum):
    """Subscription payment status"""
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    TRIALING = "trialing"


class ScanStatus(str, enum.Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class User(Base):
    """User account model"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    
    # Profile
    full_name = Column(String(255), nullable=True)
    company = Column(String(255), nullable=True)
    
    # Auth
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)  # Admin access
    verification_token = Column(String(255), nullable=True)
    reset_token = Column(String(255), nullable=True)
    reset_token_expires = Column(DateTime, nullable=True)
    
    # OAuth
    oauth_provider = Column(String(50), nullable=True)  # google, github
    oauth_id = Column(String(255), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    subscription = relationship("Subscription", back_populates="user", uselist=False)
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User {self.email}>"


class Subscription(Base):
    """User subscription model"""
    __tablename__ = "subscriptions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    
    # Tier & Status
    tier = Column(SQLEnum(SubscriptionTierEnum), default=SubscriptionTierEnum.FREE, nullable=False)
    status = Column(SQLEnum(SubscriptionStatus), default=SubscriptionStatus.ACTIVE, nullable=False)
    
    # Billing
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)
    
    # Dates
    started_at = Column(DateTime, default=datetime.utcnow)
    current_period_start = Column(DateTime, nullable=True)
    current_period_end = Column(DateTime, nullable=True)
    trial_ends_at = Column(DateTime, nullable=True)
    canceled_at = Column(DateTime, nullable=True)
    
    # Usage tracking
    scans_this_month = Column(Integer, default=0)
    api_calls_this_month = Column(Integer, default=0)
    last_reset_at = Column(DateTime, default=datetime.utcnow)
    
    # Daily limits (for FREE/BASIC/PRO tiers)
    daily_scans_count = Column(Integer, default=0)
    last_daily_reset = Column(DateTime, default=datetime.utcnow)
    
    # Extra scans (purchasable add-ons)
    extra_scans_purchased = Column(Integer, default=0)
    extra_scans_used = Column(Integer, default=0)
    
    # Relationship
    user = relationship("User", back_populates="subscription")
    
    def __repr__(self):
        return f"<Subscription user={self.user_id} tier={self.tier.value}>"


class Scan(Base):
    """Scan history model"""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Scan info
    job_id = Column(String(50), unique=True, index=True, nullable=False)
    mode = Column(String(20), nullable=False)  # recon, standard
    target = Column(String(500), nullable=False)  # domain or scope file
    intensity = Column(String(20), nullable=True)  # safe, normal, brute
    
    # Execution
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    pid = Column(Integer, nullable=True)
    log_path = Column(String(500), nullable=True)
    report_path = Column(String(500), nullable=True)
    
    # Results
    vulnerabilities_found = Column(Integer, default=0)
    urls_scanned = Column(Integer, default=0)
    detectors_triggered = Column(Text, nullable=True)  # JSON array of detector names
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Errors
    error_message = Column(Text, nullable=True)
    
    # Relationship
    user = relationship("User", back_populates="scans")
    
    def __repr__(self):
        return f"<Scan {self.job_id} status={self.status.value}>"
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate scan duration in seconds"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class ApiKey(Base):
    """API key for programmatic access (ENTERPRISE tier)"""
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Key info
    key = Column(String(64), unique=True, index=True, nullable=False)  # SHA256 hash
    name = Column(String(100), nullable=False)  # User-friendly name
    prefix = Column(String(8), nullable=False)  # First 8 chars for display
    
    # Usage
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime, nullable=True)
    requests_count = Column(Integer, default=0)
    
    # Limits
    rate_limit_per_minute = Column(Integer, default=60)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    
    # Relationship
    user = relationship("User", back_populates="api_keys")
    
    def __repr__(self):
        return f"<ApiKey {self.prefix}... user={self.user_id}>"


class AuditLog(Base):
    """Audit log for security events"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Event
    event_type = Column(String(50), nullable=False)  # login, scan_started, tier_changed, etc.
    description = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    
    # Metadata
    extra_data = Column(Text, nullable=True)  # JSON blob (renamed from metadata)
    
    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<AuditLog {self.event_type} user={self.user_id}>"

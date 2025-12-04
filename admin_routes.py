"""
Admin Panel API Routes
Full platform control: users, plans, scans, database, settings, audit logs
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from datetime import datetime, timedelta
from typing import List, Optional
import json
import os
import shutil
from pathlib import Path

from models import (
    User, Plan, Subscription, Scan, AuditLog, ApiKey,
    SubscriptionTierEnum, SubscriptionStatus, ScanStatus
)
from database import get_db

router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory="templates")


# ===== AUTHENTICATION =====

def require_admin(request: Request, db: Session = Depends(get_db)):
    """Require admin authentication"""
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return user


# ===== DASHBOARD =====

@router.get("", response_class=HTMLResponse)
async def admin_panel(request: Request, admin: User = Depends(require_admin)):
    """Admin panel UI"""
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "admin": admin
    })


@router.get("/api/stats")
async def get_dashboard_stats(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics"""
    # Total users
    total_users = db.query(func.count(User.id)).scalar()
    
    # Active subscriptions (PRO tier)
    active_subs = db.query(func.count(Subscription.id)).filter(
        and_(
            Subscription.status == SubscriptionStatus.ACTIVE,
            Subscription.tier != SubscriptionTierEnum.FREE
        )
    ).scalar()
    
    # Scans today
    today = datetime.now().date()
    scans_today = db.query(func.count(Scan.id)).filter(
        func.date(Scan.created_at) == today
    ).scalar()
    
    # Monthly revenue (mock - integrate with Stripe)
    monthly_revenue = 0.0
    pro_subs = db.query(Subscription).filter(
        Subscription.status == SubscriptionStatus.ACTIVE
    ).all()
    
    for sub in pro_subs:
        if sub.plan_id:
            plan = db.query(Plan).filter(Plan.id == sub.plan_id).first()
            if plan:
                monthly_revenue += plan.price_monthly
    
    return {
        "total_users": total_users,
        "active_subscriptions": active_subs,
        "scans_today": scans_today,
        "monthly_revenue": round(monthly_revenue, 2)
    }


@router.get("/api/activity")
async def get_recent_activity(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
    limit: int = 20
):
    """Get recent audit log activity"""
    logs = db.query(AuditLog).order_by(
        AuditLog.created_at.desc()
    ).limit(limit).all()
    
    return [{
        "id": log.id,
        "event_type": log.event_type,
        "description": log.description,
        "user_id": log.user_id,
        "ip_address": log.ip_address,
        "created_at": log.created_at.isoformat() if log.created_at else None
    } for log in logs]


# ===== USER MANAGEMENT =====

@router.get("/api/users")
async def get_all_users(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
    page: int = 1,
    limit: int = 50
):
    """Get all users with pagination"""
    offset = (page - 1) * limit
    users = db.query(User).offset(offset).limit(limit).all()
    total = db.query(func.count(User.id)).scalar()
    
    return {
        "users": [{
            "id": u.id,
            "email": u.email,
            "username": u.username,
            "full_name": u.full_name,
            "company": u.company,
            "is_active": u.is_active,
            "is_admin": u.is_admin,
            "is_verified": u.is_verified,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "last_login": u.last_login.isoformat() if u.last_login else None,
            "subscription": {
                "tier": u.subscription.tier.value if u.subscription else "none",
                "status": u.subscription.status.value if u.subscription else "none"
            } if u.subscription else None
        } for u in users],
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }


@router.get("/api/users/{user_id}")
async def get_user_details(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get detailed user information"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get user's scans
    scans = db.query(Scan).filter(Scan.user_id == user_id).order_by(
        Scan.created_at.desc()
    ).limit(10).all()
    
    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "full_name": user.full_name,
        "company": user.company,
        "is_active": user.is_active,
        "is_admin": user.is_admin,
        "is_verified": user.is_verified,
        "oauth_provider": user.oauth_provider,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "subscription": {
            "tier": user.subscription.tier.value,
            "status": user.subscription.status.value,
            "started_at": user.subscription.started_at.isoformat() if user.subscription.started_at else None,
            "scans_this_month": user.subscription.scans_this_month
        } if user.subscription else None,
        "recent_scans": [{
            "job_id": s.job_id,
            "target": s.target,
            "status": s.status.value,
            "created_at": s.created_at.isoformat() if s.created_at else None
        } for s in scans]
    }


@router.post("/api/users")
async def create_user(
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create new user"""
    data = await request.json()
    
    # Check if user exists
    existing = db.query(User).filter(User.email == data["email"]).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create user
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    user = User(
        email=data["email"],
        username=data.get("username", data["email"].split("@")[0]),
        password_hash=pwd_context.hash(data["password"]),
        full_name=data.get("full_name"),
        company=data.get("company"),
        is_active=data.get("is_active", True),
        is_admin=data.get("is_admin", False),
        is_verified=True
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Create subscription
    plan_name = data.get("plan", "FREE")
    plan = db.query(Plan).filter(Plan.name == plan_name).first()
    
    if plan:
        subscription = Subscription(
            user_id=user.id,
            plan_id=plan.id,
            tier=SubscriptionTierEnum.FREE if plan_name == "FREE" else SubscriptionTierEnum.PRO
        )
        db.add(subscription)
        db.commit()
    
    # Audit log
    audit = AuditLog(
        user_id=admin.id,
        event_type="user_created",
        description=f"Admin created user {user.email}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    db.commit()
    
    return {"id": user.id, "email": user.email}


@router.put("/api/users/{user_id}")
async def update_user(
    user_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update user"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    data = await request.json()
    
    # Update fields
    if "email" in data:
        user.email = data["email"]
    if "username" in data:
        user.username = data["username"]
    if "full_name" in data:
        user.full_name = data["full_name"]
    if "company" in data:
        user.company = data["company"]
    if "is_active" in data:
        user.is_active = data["is_active"]
    if "is_admin" in data:
        user.is_admin = data["is_admin"]
    if "is_verified" in data:
        user.is_verified = data["is_verified"]
    
    db.commit()
    
    # Audit log
    audit = AuditLog(
        user_id=admin.id,
        event_type="user_updated",
        description=f"Admin updated user {user.email}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    db.commit()
    
    return {"success": True}


@router.delete("/api/users/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete user (cascade: subscription, scans, api keys)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.is_admin and user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    email = user.email
    
    # Audit log before deletion
    audit = AuditLog(
        user_id=admin.id,
        event_type="user_deleted",
        description=f"Admin deleted user {email}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    
    db.delete(user)
    db.commit()
    
    return {"success": True}


# ===== PLAN MANAGEMENT =====

@router.get("/api/plans")
async def get_all_plans(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get all subscription plans"""
    plans = db.query(Plan).order_by(Plan.price_monthly.asc()).all()
    
    return [{
        "id": p.id,
        "name": p.name,
        "display_name": p.display_name,
        "price_monthly": p.price_monthly,
        "price_yearly": p.price_yearly,
        "limits": json.loads(p.limits) if p.limits else {},
        "features": json.loads(p.features) if p.features else [],
        "is_active": p.is_active,
        "is_visible": p.is_visible,
        "stripe_price_id_monthly": p.stripe_price_id_monthly,
        "stripe_price_id_yearly": p.stripe_price_id_yearly,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "subscribers": db.query(func.count(Subscription.id)).filter(
            Subscription.plan_id == p.id
        ).scalar()
    } for p in plans]


@router.post("/api/plans")
async def create_plan(
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create new plan"""
    data = await request.json()
    
    # Validate JSON fields
    try:
        limits = json.loads(data["limits"]) if isinstance(data["limits"], str) else data["limits"]
        features = json.loads(data["features"]) if isinstance(data["features"], str) else data["features"]
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in limits or features")
    
    plan = Plan(
        name=data["name"],
        display_name=data["display_name"],
        price_monthly=data["price_monthly"],
        price_yearly=data.get("price_yearly", data["price_monthly"] * 10),
        limits=json.dumps(limits),
        features=json.dumps(features),
        is_active=data.get("is_active", True),
        is_visible=data.get("is_visible", True),
        stripe_price_id_monthly=data.get("stripe_price_id_monthly"),
        stripe_price_id_yearly=data.get("stripe_price_id_yearly")
    )
    
    db.add(plan)
    db.commit()
    db.refresh(plan)
    
    # Audit log
    audit = AuditLog(
        user_id=admin.id,
        event_type="plan_created",
        description=f"Admin created plan {plan.name}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    db.commit()
    
    return {"id": plan.id, "name": plan.name}


@router.put("/api/plans/{plan_id}")
async def update_plan(
    plan_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update plan"""
    plan = db.query(Plan).filter(Plan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    
    data = await request.json()
    
    # Update fields
    if "display_name" in data:
        plan.display_name = data["display_name"]
    if "price_monthly" in data:
        plan.price_monthly = data["price_monthly"]
    if "price_yearly" in data:
        plan.price_yearly = data["price_yearly"]
    if "limits" in data:
        plan.limits = json.dumps(data["limits"]) if isinstance(data["limits"], dict) else data["limits"]
    if "features" in data:
        plan.features = json.dumps(data["features"]) if isinstance(data["features"], list) else data["features"]
    if "is_active" in data:
        plan.is_active = data["is_active"]
    if "is_visible" in data:
        plan.is_visible = data["is_visible"]
    if "stripe_price_id_monthly" in data:
        plan.stripe_price_id_monthly = data["stripe_price_id_monthly"]
    if "stripe_price_id_yearly" in data:
        plan.stripe_price_id_yearly = data["stripe_price_id_yearly"]
    
    plan.updated_at = datetime.now()
    db.commit()
    
    # Audit log
    audit = AuditLog(
        user_id=admin.id,
        event_type="plan_updated",
        description=f"Admin updated plan {plan.name}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    db.commit()
    
    return {"success": True}


@router.delete("/api/plans/{plan_id}")
async def delete_plan(
    plan_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete plan (check for subscribers first)"""
    plan = db.query(Plan).filter(Plan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    
    # Check for subscribers
    subscribers = db.query(func.count(Subscription.id)).filter(
        Subscription.plan_id == plan_id
    ).scalar()
    
    if subscribers > 0:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete plan with {subscribers} active subscribers"
        )
    
    plan_name = plan.name
    
    # Audit log
    audit = AuditLog(
        user_id=admin.id,
        event_type="plan_deleted",
        description=f"Admin deleted plan {plan_name}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    
    db.delete(plan)
    db.commit()
    
    return {"success": True}


# ===== SCAN MANAGEMENT =====

@router.get("/api/scans")
async def get_all_scans(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
    page: int = 1,
    limit: int = 50,
    status: Optional[str] = None
):
    """Get all scans with pagination"""
    offset = (page - 1) * limit
    
    query = db.query(Scan)
    if status:
        query = query.filter(Scan.status == status)
    
    scans = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    total = query.count()
    
    return {
        "scans": [{
            "id": s.id,
            "job_id": s.job_id,
            "user_id": s.user_id,
            "user_email": s.user.email if s.user else None,
            "target": s.target,
            "mode": s.mode,
            "status": s.status.value,
            "vulnerabilities_found": s.vulnerabilities_found,
            "urls_scanned": s.urls_scanned,
            "progress_percentage": s.progress_percentage,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "duration": s.duration_seconds
        } for s in scans],
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }


@router.delete("/api/scans/{scan_id}")
async def delete_scan(
    scan_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete scan and associated files"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Delete associated files
    if scan.report_path and os.path.exists(scan.report_path):
        try:
            os.remove(scan.report_path)
        except Exception as e:
            print(f"Error deleting report: {e}")
    
    if scan.log_path and os.path.exists(scan.log_path):
        try:
            os.remove(scan.log_path)
        except Exception as e:
            print(f"Error deleting log: {e}")
    
    # Audit log
    audit = AuditLog(
        user_id=admin.id,
        event_type="scan_deleted",
        description=f"Admin deleted scan {scan.job_id}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    
    db.delete(scan)
    db.commit()
    
    return {"success": True}


# ===== DATABASE TOOLS =====

@router.get("/api/database/info")
async def get_database_info(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get database information"""
    db_path = Path("bugbounty_arsenal.db")
    
    return {
        "size_bytes": db_path.stat().st_size if db_path.exists() else 0,
        "size_mb": round(db_path.stat().st_size / (1024 * 1024), 2) if db_path.exists() else 0,
        "total_users": db.query(func.count(User.id)).scalar(),
        "total_scans": db.query(func.count(Scan.id)).scalar(),
        "total_plans": db.query(func.count(Plan.id)).scalar(),
        "total_audit_logs": db.query(func.count(AuditLog.id)).scalar()
    }


@router.post("/api/database/backup")
async def backup_database(
    request: Request,
    admin: User = Depends(require_admin)
):
    """Create database backup"""
    db_path = Path("bugbounty_arsenal.db")
    if not db_path.exists():
        raise HTTPException(status_code=404, detail="Database not found")
    
    # Create backups directory
    backup_dir = Path("backups")
    backup_dir.mkdir(exist_ok=True)
    
    # Create backup with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"bugbounty_arsenal_{timestamp}.db"
    
    shutil.copy2(db_path, backup_path)
    
    # Audit log
    from database import SessionLocal
    db = SessionLocal()
    audit = AuditLog(
        user_id=admin.id,
        event_type="database_backup",
        description=f"Admin created database backup: {backup_path.name}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    db.commit()
    db.close()
    
    return {
        "success": True,
        "backup_file": str(backup_path),
        "size_mb": round(backup_path.stat().st_size / (1024 * 1024), 2)
    }


@router.get("/api/database/backups")
async def list_backups(admin: User = Depends(require_admin)):
    """List all database backups"""
    backup_dir = Path("backups")
    if not backup_dir.exists():
        return {"backups": []}
    
    backups = []
    for backup in backup_dir.glob("*.db"):
        backups.append({
            "filename": backup.name,
            "size_mb": round(backup.stat().st_size / (1024 * 1024), 2),
            "created_at": datetime.fromtimestamp(backup.stat().st_mtime).isoformat()
        })
    
    return {"backups": sorted(backups, key=lambda x: x["created_at"], reverse=True)}


# ===== AUDIT LOGS =====

@router.get("/api/audit-logs")
async def get_audit_logs(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
    page: int = 1,
    limit: int = 100
):
    """Get audit logs with pagination"""
    offset = (page - 1) * limit
    
    logs = db.query(AuditLog).order_by(
        AuditLog.created_at.desc()
    ).offset(offset).limit(limit).all()
    
    total = db.query(func.count(AuditLog.id)).scalar()
    
    return {
        "logs": [{
            "id": log.id,
            "event_type": log.event_type,
            "description": log.description,
            "user_id": log.user_id,
            "user_email": log.user.email if log.user_id and hasattr(log, 'user') else None,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "extra_data": log.extra_data,
            "created_at": log.created_at.isoformat() if log.created_at else None
        } for log in logs],
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }


# ===== PLATFORM SETTINGS =====

@router.get("/api/settings")
async def get_platform_settings(admin: User = Depends(require_admin)):
    """Get platform-wide settings"""
    # TODO: Store settings in database or config file
    return {
        "platform_name": "BugBounty Arsenal",
        "contact_email": "support@bugbounty-arsenal.com",
        "maintenance_mode": False,
        "max_concurrent_scans_global": 10,
        "registration_enabled": True
    }


@router.put("/api/settings")
async def update_platform_settings(
    request: Request,
    admin: User = Depends(require_admin)
):
    """Update platform-wide settings"""
    data = await request.json()
    
    # TODO: Store settings in database or config file
    # For now, just audit the change
    from database import SessionLocal
    db = SessionLocal()
    audit = AuditLog(
        user_id=admin.id,
        event_type="settings_updated",
        description="Admin updated platform settings",
        ip_address=request.client.host if request.client else None,
        extra_data=json.dumps(data)
    )
    db.add(audit)
    db.commit()
    db.close()
    
    return {"success": True}


# ===== DATABASE MANAGEMENT =====

@router.get("/api/database/tables")
async def get_database_tables(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get all database tables with row counts"""
    from sqlalchemy import inspect, text
    
    inspector = inspect(db.bind)
    tables = []
    
    for table_name in inspector.get_table_names():
        # Get row count
        try:
            result = db.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
            row_count = result.scalar()
        except:
            row_count = 0
        
        # Get columns
        columns = []
        for col in inspector.get_columns(table_name):
            columns.append({
                "name": col["name"],
                "type": str(col["type"]),
                "nullable": col["nullable"],
                "default": str(col["default"]) if col["default"] else None
            })
        
        tables.append({
            "name": table_name,
            "row_count": row_count,
            "columns": columns
        })
    
    return {"tables": tables}


@router.post("/api/database/query")
async def execute_database_query(
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Execute SQL query (READ-ONLY for safety)"""
    from sqlalchemy import text
    
    data = await request.json()
    query = data.get("query", "").strip()
    
    if not query:
        raise HTTPException(status_code=400, detail="Query is required")
    
    # Safety check - only allow SELECT queries
    query_lower = query.lower()
    if not query_lower.startswith("select"):
        raise HTTPException(
            status_code=403, 
            detail="Only SELECT queries are allowed for safety. Use the specific API endpoints to modify data."
        )
    
    try:
        result = db.execute(text(query))
        
        # Get column names
        columns = list(result.keys()) if result.returns_rows else []
        
        # Get rows
        rows = []
        if result.returns_rows:
            for row in result:
                rows.append([str(val) for val in row])
        
        # Audit log
        audit = AuditLog(
            user_id=admin.id,
            event_type="database_query",
            description=f"Admin executed SQL query",
            ip_address=request.client.host if request.client else None,
            extra_data=json.dumps({"query": query})
        )
        db.add(audit)
        db.commit()
        
        return {
            "success": True,
            "columns": columns,
            "rows": rows,
            "row_count": len(rows)
        }
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Query error: {str(e)}")


@router.get("/api/database/table/{table_name}")
async def get_table_data(
    table_name: str,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
    page: int = 1,
    limit: int = 50
):
    """Get data from a specific table with pagination"""
    from sqlalchemy import text
    
    offset = (page - 1) * limit
    
    try:
        # Get total count
        count_result = db.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
        total = count_result.scalar()
        
        # Get data
        query = text(f"SELECT * FROM {table_name} LIMIT :limit OFFSET :offset")
        result = db.execute(query, {"limit": limit, "offset": offset})
        
        columns = list(result.keys())
        rows = []
        for row in result:
            rows.append({col: str(val) for col, val in zip(columns, row)})
        
        return {
            "table_name": table_name,
            "columns": columns,
            "rows": rows,
            "total": total,
            "page": page,
            "pages": (total + limit - 1) // limit if total > 0 else 0
        }
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")

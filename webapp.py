import os
import uuid
import subprocess
import sys
import psutil
from datetime import datetime
from typing import List, Optional, Dict

from fastapi import FastAPI, Request, Form, HTTPException, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from subscription import (
    SubscriptionTier,
    get_tier_limits,
    can_start_scan,
    validate_scan_scope,
    get_tier_display_info,
)
from database import init_db, get_db
from models import User, Subscription, Scan, ScanStatus, SubscriptionTierEnum, SubscriptionStatus, AuditLog
from auth import hash_password, verify_password, create_access_token, decode_access_token
from stripe_integration import (
    create_checkout_session,
    create_customer_portal_session,
    verify_webhook_signature,
    get_tier_price,
)
from background_tasks import monitor_scan_status, parse_vulnerability_count
from report_exporter import export_to_json, export_to_markdown, count_vulnerabilities_from_report
from email_service import email_service

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR = os.path.join(BASE_DIR, "scan_logs")
os.makedirs(LOGS_DIR, exist_ok=True)

app = FastAPI(title="BugBounty Arsenal UI")

# Favicon endpoint to prevent 404 errors
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Return empty favicon to prevent 404 errors"""
    from fastapi.responses import FileResponse
    # Return empty response with proper content type
    return Response(
        content=b'\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x18\x00(\x00\x00\x00\x16\x00\x00\x00',
        media_type="image/x-icon"
    )

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    init_db()
    print("✓ Database initialized")

# Mount /reports as static, so we can link to HTML reports directly
if os.path.isdir(REPORTS_DIR):
    app.mount("/reports", StaticFiles(directory=REPORTS_DIR), name="reports")

# Templates directory (already exists in the repo)
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


# Active scan tracking: {job_id: {"pid": int, "log_path": str, "started": datetime, "status": "running"|"completed"}}
ACTIVE_SCANS: Dict[str, dict] = {}

# For MVP: simulate a logged-in user with a tier
# In production, this would come from session/JWT token
CURRENT_USER_TIER = SubscriptionTier.FREE  # Change to PRO or ENTERPRISE for testing


def get_current_user(access_token: Optional[str] = Cookie(None), db: Session = Depends(get_db)) -> Optional[User]:
    """
    Get current user from JWT token cookie.
    Returns None if not authenticated (for MVP, allows anonymous access).
    """
    if not access_token:
        return None
    
    payload = decode_access_token(access_token)
    if not payload:
        return None
    
    email = payload.get("sub")
    if not email:
        return None
    
    user = db.query(User).filter(User.email == email).first()
    return user


def get_user_tier(user: Optional[User], db: Session) -> SubscriptionTier:
    """Get user's subscription tier or default to FREE"""
    if not user:
        return CURRENT_USER_TIER  # MVP fallback
    
    if not user.subscription:
        # Create default FREE subscription
        subscription = Subscription(
            user_id=user.id,
            tier=SubscriptionTierEnum.FREE
        )
        db.add(subscription)
        db.commit()
        return SubscriptionTier.FREE
    
    return SubscriptionTier(user.subscription.tier.value)


def require_superuser(user: Optional[User] = Depends(get_current_user)) -> User:
    """
    Dependency to require superuser access.
    Raises 403 if user is not a superuser.
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    if not user.is_superuser:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return user


def _list_reports() -> List[dict]:
    """Scan the reports directory and list available HTML reports."""
    items: List[dict] = []
    if not os.path.isdir(REPORTS_DIR):
        return items

    for root, dirs, files in os.walk(REPORTS_DIR):
        for filename in files:
            if not filename.lower().endswith(".html"):
                continue
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, REPORTS_DIR)
            # Guess created time from filesystem
            try:
                created_ts = datetime.fromtimestamp(os.path.getmtime(full_path))
            except Exception:
                created_ts = None
            items.append(
                {
                    "name": filename,
                    "rel_path": rel_path.replace(os.sep, "/"),
                    "created": created_ts,
                }
            )
    # Newest first
    items.sort(key=lambda x: x["created"] or datetime.min, reverse=True)
    return items


@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    """Render landing page."""
    return templates.TemplateResponse("landing.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Render dashboard with scan form + list of reports."""
    # Get user's tier
    user_tier = get_user_tier(user, db)
    tier_info = get_tier_display_info(user_tier)
    tier_limits = get_tier_limits(user_tier)
    
    # Get scan history from database if user is logged in
    scan_history = []
    reports = []
    scan_stats = None
    if user:
        scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.created_at.desc()).limit(20).all()
        scan_history = [
            {
                "job_id": scan.job_id,
                "target": scan.target,
                "status": scan.status.value,
                "created_at": scan.created_at,
                "completed_at": scan.completed_at,
                "vulnerabilities": scan.vulnerabilities_found,
                "report_path": scan.report_path,
            }
            for scan in scans
        ]
        
        # Generate reports list from scans with completed reports
        for scan in scans:
            if scan.report_path and os.path.exists(os.path.join(REPORTS_DIR, scan.report_path)):
                reports.append({
                    "name": f"{scan.target} - {scan.created_at.strftime('%Y-%m-%d %H:%M')}",
                    "rel_path": scan.report_path,
                    "created": scan.completed_at or scan.created_at,
                })
        
        # Get scan statistics
        subscription = db.query(Subscription).filter(Subscription.user_id == user.id).first()
        if subscription:
            extra_scans_available = subscription.extra_scans_purchased - subscription.extra_scans_used
            scan_stats = {
                "daily_used": subscription.daily_scans_count,
                "daily_limit": tier_limits.daily_scan_limit,
                "extra_scans_available": extra_scans_available,
                "extra_scans_purchased": subscription.extra_scans_purchased,
                "extra_scans_used": subscription.extra_scans_used,
            }
    else:
        # For non-logged in users, show all reports from filesystem
        reports = _list_reports()
    
    # Check active scans status
    _update_scan_statuses(db)
    
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "reports": reports,
            "active_scans": ACTIVE_SCANS,
            "scan_history": scan_history,
            "tier": user_tier.value,
            "tier_info": tier_info,
            "tier_limits": tier_limits,
            "user": user,
            "is_superuser": user.is_superuser if user else False,
            "scan_stats": scan_stats,
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render login page."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    """Render signup page."""
    return templates.TemplateResponse("signup.html", {"request": request})


@app.post("/api/signup")
async def signup(
    email: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Create new user account"""
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Generate verification token
    verification_token = email_service.generate_verification_token()
    
    # Create user
    user = User(
        email=email,
        full_name=full_name,
        password_hash=hash_password(password),
        is_active=True,
        is_verified=False,  # Require email verification
        verification_token=verification_token
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Create FREE subscription
    subscription = Subscription(
        user_id=user.id,
        tier=SubscriptionTierEnum.FREE
    )
    db.add(subscription)
    db.commit()
    
    # Create audit log
    audit = AuditLog(
        user_id=user.id,
        event_type="user_registered",
        description=f"User {email} registered"
    )
    db.add(audit)
    db.commit()
    
    # Send verification email
    email_sent = email_service.send_verification_email(email, verification_token)
    
    return JSONResponse(content={
        "message": "Account created! Please check your email to verify your account.",
        "email_sent": email_sent,
        "user": {"email": user.email, "full_name": user.full_name}
    })


@app.post("/api/login")
async def login(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Authenticate user and create session"""
    # Find user
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email address before logging in")
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Create audit log
    audit = AuditLog(
        user_id=user.id,
        event_type="user_login",
        description=f"User {email} logged in"
    )
    db.add(audit)
    db.commit()
    
    # Create JWT token
    # Create access token with user_id
    access_token = create_access_token(data={"sub": user.email, "user_id": user.id})
    
    response = JSONResponse(content={
        "message": "Login successful",
        "user": {"email": user.email, "full_name": user.full_name}
    })
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=False,  # Allow JavaScript to read for EventSource
        max_age=60 * 60 * 24 * 7,  # 7 days
        samesite="lax"
    )
    
    return response


@app.post("/api/logout")
async def logout():
    """Logout user by clearing cookie"""
    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie(key="access_token")
    return response


@app.get("/verify-email", response_class=HTMLResponse)
async def verify_email_page(
    token: str,
    db: Session = Depends(get_db)
):
    """Verify user email with token"""
    user = db.query(User).filter(User.verification_token == token).first()
    
    if not user:
        return HTMLResponse(content="""
        <html>
            <head><title>Invalid Token</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h2 style="color: #dc2626;">Invalid Verification Token</h2>
                <p>This link is invalid or has already been used.</p>
                <a href="/login" style="color: #2563eb;">Return to Login</a>
            </body>
        </html>
        """, status_code=400)
    
    # Mark user as verified
    user.is_verified = True
    user.verification_token = None
    db.commit()
    
    # Create audit log
    audit = AuditLog(
        user_id=user.id,
        event_type="email_verified",
        description=f"User {user.email} verified email"
    )
    db.add(audit)
    db.commit()
    
    return HTMLResponse(content=f"""
    <html>
        <head>
            <title>Email Verified</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                .success {{ color: #16a34a; }}
                .btn {{ background-color: #2563eb; color: white; padding: 12px 30px;
                        text-decoration: none; border-radius: 5px; display: inline-block;
                        margin-top: 20px; }}
            </style>
        </head>
        <body>
            <h2 class="success">✓ Email Verified Successfully!</h2>
            <p>Your account <strong>{user.email}</strong> has been verified.</p>
            <p>You can now log in and start scanning.</p>
            <a href="/login" class="btn">Go to Login</a>
        </body>
    </html>
    """)


# ============================================================================
# ADMIN PANEL ROUTES
# ============================================================================

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(
    request: Request,
    user: User = Depends(require_superuser),
    db: Session = Depends(get_db)
):
    """Admin panel - superuser only"""
    from sqlalchemy import func
    
    # Calculate stats
    total_users = db.query(func.count(User.id)).scalar()
    active_subs = db.query(func.count(Subscription.id)).filter(
        Subscription.tier != SubscriptionTierEnum.FREE
    ).scalar()
    total_scans = db.query(func.count(Scan.id)).scalar()
    
    # Calculate monthly revenue (mock for now)
    pro_count = db.query(func.count(Subscription.id)).filter(
        Subscription.tier == SubscriptionTierEnum.PRO
    ).scalar()
    ent_count = db.query(func.count(Subscription.id)).filter(
        Subscription.tier == SubscriptionTierEnum.ENTERPRISE
    ).scalar()
    monthly_revenue = (pro_count * 39) + (ent_count * 119)
    
    stats = {
        "total_users": total_users,
        "active_subscriptions": active_subs,
        "total_scans": total_scans,
        "monthly_revenue": monthly_revenue
    }
    
    # Get recent data
    users = db.query(User).order_by(User.created_at.desc()).limit(50).all()
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(50).all()
    audit_logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
    
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "stats": stats,
            "users": users,
            "scans": scans,
            "audit_logs": audit_logs,
        }
    )


@app.post("/admin/users/{user_id}/tier")
async def admin_change_tier(
    user_id: int,
    tier: str = Form(...),
    admin: User = Depends(require_superuser),
    db: Session = Depends(get_db)
):
    """Change user's subscription tier (admin only)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate tier
    try:
        new_tier = SubscriptionTierEnum(tier)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid tier")
    
    # Update or create subscription
    if user.subscription:
        user.subscription.tier = new_tier
    else:
        subscription = Subscription(user_id=user.id, tier=new_tier)
        db.add(subscription)
    
    # Audit log
    audit = AuditLog(
        user_id=admin.id,
        event_type="tier_changed",
        description=f"Admin changed user {user.email} tier to {tier}"
    )
    db.add(audit)
    db.commit()
    
    return JSONResponse({"message": "Tier updated successfully"})


@app.post("/admin/users/{user_id}/toggle")
async def admin_toggle_user(
    user_id: int,
    is_active: bool = Form(...),
    admin: User = Depends(require_superuser),
    db: Session = Depends(get_db)
):
    """Enable/disable user account (admin only)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_active = is_active
    
    # Audit log
    audit = AuditLog(
        user_id=admin.id,
        event_type="user_status_changed",
        description=f"Admin {'enabled' if is_active else 'disabled'} user {user.email}"
    )
    db.add(audit)
    db.commit()
    
    return JSONResponse({"message": "User status updated"})


@app.post("/admin/users/create")
async def admin_create_user(
    email: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(...),
    tier: str = Form("FREE"),
    is_superuser: bool = Form(False),
    admin: User = Depends(require_superuser),
    db: Session = Depends(get_db)
):
    """Create new user (admin only)"""
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Validate tier (handle both uppercase and lowercase)
    try:
        user_tier = SubscriptionTierEnum(tier.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid tier: {tier}. Must be one of: free, basic, pro, enterprise")
    
    # Create user
    user = User(
        email=email,
        full_name=full_name,
        password_hash=hash_password(password),
        is_active=True,
        is_verified=True,  # Admin-created users are pre-verified
        is_superuser=is_superuser
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Create subscription
    subscription = Subscription(
        user_id=user.id,
        tier=user_tier
    )
    db.add(subscription)
    db.commit()
    
    # Create audit log
    audit = AuditLog(
        user_id=admin.id,
        event_type="user_created",
        description=f"Admin created user {email} with tier {tier}"
    )
    db.add(audit)
    db.commit()
    
    return JSONResponse({"message": "User created successfully", "user_id": user.id})


@app.post("/api/validate-scope")
async def validate_scope(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Validate scope file and return in-scope/out-of-scope counts."""
    # Check tier
    subscription = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    user_tier = subscription.tier if subscription else SubscriptionTierEnum.FREE
    
    if user_tier not in [SubscriptionTierEnum.PRO, SubscriptionTierEnum.ENTERPRISE]:
        raise HTTPException(status_code=403, detail="Scope file validation requires PRO or ENTERPRISE tier")
    
    data = await request.json()
    scope_file = data.get("scope_file", "targets.csv")
    scope_path = os.path.join(BASE_DIR, scope_file)
    
    if not os.path.exists(scope_path):
        raise HTTPException(status_code=404, detail=f"Scope file not found: {scope_file}")
    
    try:
        from scope_parser import parse_scope
        in_scope_list, out_scope_list = parse_scope(scope_path)
        
        return JSONResponse({
            "in_scope_count": len(in_scope_list),
            "out_of_scope_count": len(out_scope_list)
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse scope file: {str(e)}")


@app.post("/scan", response_class=RedirectResponse)
async def start_scan(
    request: Request,
    scope_file: Optional[str] = Form(default="targets.csv"),
    recon_domain: Optional[str] = Form(default=""),
    mode: str = Form(default="standard"),  # "standard" or "recon"
    scan_intensity: str = Form(default="normal"),  # safe/normal/brute
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start a scan via subprocess using existing main.py CLI."""
    
    # Check tier for scope file usage
    if user:
        subscription = db.query(Subscription).filter(Subscription.user_id == user.id).first()
        user_tier = subscription.tier if subscription else SubscriptionTierEnum.FREE
        
        if mode == "standard" and user_tier not in [SubscriptionTierEnum.PRO, SubscriptionTierEnum.ENTERPRISE]:
            raise HTTPException(
                status_code=403,
                detail="Scope file scanning requires PRO or ENTERPRISE tier. Upgrade to access."
            )
    
    # Get user tier
    user_tier = get_user_tier(user, db)
    
    # Check daily scan limit (for non-ENTERPRISE tiers)
    if user:
        subscription = db.query(Subscription).filter(Subscription.user_id == user.id).first()
        if subscription:
            tier_limits = get_tier_limits(user_tier)
            
            # Reset daily counter if it's a new day
            if subscription.last_daily_reset:
                days_since_reset = (datetime.utcnow() - subscription.last_daily_reset).days
                if days_since_reset >= 1:
                    subscription.daily_scans_count = 0
                    subscription.last_daily_reset = datetime.utcnow()
                    db.commit()
            
            # Check daily limit (0 = unlimited for ENTERPRISE)
            if tier_limits.daily_scan_limit > 0:
                # Check if user has extra scans available
                extra_scans_available = subscription.extra_scans_purchased - subscription.extra_scans_used
                
                if subscription.daily_scans_count >= tier_limits.daily_scan_limit:
                    # Daily limit reached, check if extra scans available
                    if extra_scans_available > 0:
                        # Allow scan but use extra scan
                        pass  # Will be handled after scan creation
                    else:
                        raise HTTPException(
                            status_code=403,
                            detail=f"Daily scan limit reached ({tier_limits.daily_scan_limit} scans/day). Purchase extra scans or upgrade your plan."
                        )
    
    # Check tier limits - concurrent scans
    active_running = sum(1 for s in ACTIVE_SCANS.values() if s["status"] == "running")
    allowed, error_msg = can_start_scan(user_tier, active_running)
    if not allowed:
        raise HTTPException(status_code=403, detail=error_msg)
    
    # Check tier limits - recon pipeline
    tier_limits = get_tier_limits(user_tier)
    if mode == "recon" and not tier_limits.enable_recon_pipeline:
        raise HTTPException(
            status_code=403, 
            detail="Recon pipeline not available in your tier. Upgrade to access."
        )
    
    # Generate job_id early so we can use it for filtered files
    job_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(LOGS_DIR, f"scan_{job_id}.log")
    
    # Validate scope file for standard mode (PRO/ENTERPRISE only)
    if mode == "standard" and scope_file:
        scope_path = os.path.join(BASE_DIR, scope_file)
        if os.path.exists(scope_path):
            try:
                from scope_parser import parse_scope
                in_scope_list, out_scope_list = parse_scope(scope_path)
                
                # Filter out out-of-scope domains by creating a temporary filtered file
                if out_scope_list:
                    filtered_file = f"filtered_{job_id}.csv"
                    filtered_path = os.path.join(BASE_DIR, filtered_file)
                    
                    # Write only in-scope domains to filtered file
                    with open(filtered_path, 'w') as f:
                        for domain in in_scope_list:
                            f.write(f"{domain}\n")
                    
                    # Use filtered file for scan
                    scope_file = filtered_file
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to validate scope file: {str(e)}"
                )
    
    base_cmd = [
        sys.executable,
        "main.py",
        "--consent",
        "--tier", user_tier.lower(),
    ]

    if mode == "recon" and recon_domain:
        base_cmd.extend(["--recon", recon_domain])
        scan_label = f"Recon: {recon_domain}"
        target = recon_domain
    else:
        # Standard mode: use a scope CSV file
        if scope_file:
            base_cmd.extend(["--scope", scope_file])
        scan_label = f"Standard: {scope_file}"
        target = scope_file
        # Map intensity to existing --scan-mode
        if scan_intensity in {"safe", "normal", "brute"}:
            base_cmd.extend(["--scan-mode", scan_intensity])

    # Create scan record in database
    if user:
        scan_record = Scan(
            user_id=user.id,
            job_id=job_id,
            mode=mode,
            target=target,
            intensity=scan_intensity if mode == "standard" else None,
            status=ScanStatus.RUNNING,
            log_path=log_path,
            started_at=datetime.utcnow()
        )
        db.add(scan_record)
        
        # Increment daily scan counter or use extra scan
        subscription = db.query(Subscription).filter(Subscription.user_id == user.id).first()
        if subscription:
            tier_limits = get_tier_limits(user_tier)
            
            # Check if we're over daily limit and should use extra scan
            if tier_limits.daily_scan_limit > 0 and subscription.daily_scans_count >= tier_limits.daily_scan_limit:
                # Use extra scan
                extra_scans_available = subscription.extra_scans_purchased - subscription.extra_scans_used
                if extra_scans_available > 0:
                    subscription.extra_scans_used += 1
            else:
                # Use regular daily scan
                subscription.daily_scans_count += 1
        
        db.commit()
        db.refresh(scan_record)
    
    # Start process with output to log file
    log_file = open(log_path, "w")
    process = subprocess.Popen(
        base_cmd,
        cwd=BASE_DIR,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    ACTIVE_SCANS[job_id] = {
        "pid": process.pid,
        "log_path": log_path,
        "started": datetime.now(),
        "status": "running",
        "label": scan_label,
        "log_file_handle": log_file,
        "user_id": user.id if user else None,
    }
    
    # Update scan record with PID
    if user:
        scan_record.pid = process.pid
        db.commit()
        
        # Start background monitoring
        monitor_scan_status(job_id, process.pid)

    # After starting, redirect back to dashboard
    return RedirectResponse(url="/dashboard", status_code=303)


def _update_scan_statuses(db: Optional[Session] = None):
    """Check all active scans and update their status based on process state."""
    for job_id, info in list(ACTIVE_SCANS.items()):
        if info["status"] == "running":
            try:
                proc = psutil.Process(info["pid"])
                if not proc.is_running():
                    info["status"] = "completed"
                    info["completed"] = datetime.now()
                    # Close log file handle
                    if "log_file_handle" in info:
                        info["log_file_handle"].close()
                        del info["log_file_handle"]
                    
                    # Update in database
                    if db:
                        scan = db.query(Scan).filter(Scan.job_id == job_id).first()
                        if scan:
                            scan.status = ScanStatus.COMPLETED
                            scan.completed_at = datetime.now()
                            db.commit()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info["status"] = "completed"
                info["completed"] = datetime.now()
                if "log_file_handle" in info:
                    info["log_file_handle"].close()
                    del info["log_file_handle"]
                
                # Update in database
                if db:
                    scan = db.query(Scan).filter(Scan.job_id == job_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.completed_at = datetime.now()
                        db.commit()


@app.get("/scan-status", response_class=JSONResponse)
async def scan_status(db: Session = Depends(get_db)):
    """Return real-time status of all active scans."""
    _update_scan_statuses(db)
    
    running_count = sum(1 for s in ACTIVE_SCANS.values() if s["status"] == "running")
    
    return {
        "in_progress": running_count > 0,
        "active_count": running_count,
        "scans": [
            {
                "job_id": jid,
                "status": info["status"],
                "label": info.get("label", ""),
                "started": info["started"].isoformat(),
            }
            for jid, info in ACTIVE_SCANS.items()
        ]
    }


@app.get("/scan-log/{job_id}")
async def get_scan_log(job_id: str):
    """Stream the live log for a specific scan job."""
    if job_id not in ACTIVE_SCANS:
        return JSONResponse({"error": "Job not found"}, status_code=404)
    
    log_path = ACTIVE_SCANS[job_id]["log_path"]
    
    async def log_stream():
        """Tail the log file and stream new lines."""
        if not os.path.exists(log_path):
            yield "data: [Waiting for log file...]\n\n"
            return
        
        with open(log_path, "r") as f:
            # Send existing content
            content = f.read()
            if content:
                for line in content.splitlines():
                    yield f"data: {line}\n\n"
            
            # For now, just send what exists (not true tailing)
            # True tailing would require asyncio + file monitoring
            yield "data: [End of current log]\n\n"
    
    return StreamingResponse(log_stream(), media_type="text/event-stream")


@app.get("/api/scan/{job_id}/stream-log")
async def stream_scan_log(
    job_id: str,
    request: Request,
    token: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Stream scan logs in real-time using Server-Sent Events."""
    # Get token from query parameter or cookie
    if not token:
        token = request.cookies.get("access_token")
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        payload = decode_access_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Try to get user_id from payload, fallback to email lookup
        user_id = payload.get("user_id")
        if user_id:
            user = db.query(User).filter(User.id == user_id).first()
        else:
            # Fallback for old tokens without user_id
            email = payload.get("sub")
            if not email:
                raise HTTPException(status_code=401, detail="Invalid token payload")
            user = db.query(User).filter(User.email == email).first()
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")
    
    # Get scan from database
    scan = db.query(Scan).filter(Scan.job_id == job_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Determine log path
    log_path = scan.log_path
    if not log_path:
        # Construct default log path if not set
        log_path = os.path.join(LOGS_DIR, f"scan_{job_id}.log")
    
    async def log_stream():
        """Stream log file content with live updates."""
        import asyncio
        
        # Send initial connection message
        yield "data: [Connected to scan log stream]\n\n"
        
        # Wait for log file if it doesn't exist yet
        if not os.path.exists(log_path):
            yield "data: [Waiting for scan to start...]\n\n"
            # Wait up to 30 seconds for log file
            for _ in range(60):
                await asyncio.sleep(0.5)
                if os.path.exists(log_path):
                    yield "data: [Log file found, streaming started...]\n\n"
                    break
            else:
                # If no log file after 30 seconds, keep connection alive with status updates
                yield "data: [Still waiting for scan output...]\n\n"
        
        last_position = 0
        idle_count = 0
        max_idle = 300  # 150 seconds with no activity (5 minutes max)
        keepalive_count = 0
        
        try:
            while idle_count < max_idle:
                try:
                    if os.path.exists(log_path):
                        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                            f.seek(last_position)
                            new_content = f.read()
                            
                            if new_content:
                                for line in new_content.splitlines():
                                    if line.strip():  # Skip empty lines
                                        # Escape special characters for SSE
                                        safe_line = line.replace('\n', ' ').replace('\r', '')
                                        yield f"data: {safe_line}\n\n"
                                last_position = f.tell()
                                idle_count = 0  # Reset idle count when we get data
                                keepalive_count = 0
                            else:
                                # No new data - send keepalive comment every 15 seconds
                                await asyncio.sleep(0.5)
                                idle_count += 1
                                keepalive_count += 1
                                
                                # Send keepalive comment (not visible to client)
                                if keepalive_count >= 30:  # Every 15 seconds
                                    yield ": keepalive\n\n"
                                    keepalive_count = 0
                    else:
                        # Log file doesn't exist yet
                        await asyncio.sleep(0.5)
                        idle_count += 1
                            
                    # Check if scan is completed
                    db.refresh(scan)
                    if scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.STOPPED]:
                        # Give it a few more seconds to catch final logs
                        if idle_count > 10:
                            yield "data: [✓ Scan completed - stream ending]\n\n"
                            break
                                
                except FileNotFoundError:
                    await asyncio.sleep(0.5)
                    idle_count += 1
                except Exception as e:
                    yield f"data: [Error reading file: {str(e)}]\n\n"
                    await asyncio.sleep(1)
                    idle_count += 1
                    
        except asyncio.CancelledError:
            # Client disconnected - this is normal
            pass
        except Exception as e:
            yield f"data: [Stream error: {str(e)}]\n\n"
    
    return StreamingResponse(
        log_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )


@app.post("/scan-stop/{job_id}")
async def stop_scan(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Stop a running scan by terminating its process."""
    if job_id not in ACTIVE_SCANS:
        return JSONResponse({"error": "Job not found"}, status_code=404)
    
    scan_info = ACTIVE_SCANS[job_id]
    
    if scan_info["status"] != "running":
        return JSONResponse({"error": "Scan not running"}, status_code=400)
    
    try:
        proc = psutil.Process(scan_info["pid"])
        proc.terminate()  # SIGTERM
        proc.wait(timeout=5)  # Wait up to 5 seconds
    except psutil.TimeoutExpired:
        proc.kill()  # Force kill if doesn't terminate
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    
    scan_info["status"] = "stopped"
    scan_info["completed"] = datetime.now()
    
    # Update scan in database
    scan = db.query(Scan).filter(Scan.job_id == job_id).first()
    if scan:
        scan.status = "stopped"
        scan.completed_at = datetime.now()
        db.commit()
    
    if "log_file_handle" in scan_info:
        scan_info["log_file_handle"].close()
        del scan_info["log_file_handle"]
    
    return JSONResponse({"success": True, "message": f"Scan {job_id} stopped"})


@app.post("/change-tier")
async def change_tier(tier: str = Form(...)):
    """Change user tier (for MVP testing only - in production this would be managed by billing)."""
    global CURRENT_USER_TIER
    
    try:
        CURRENT_USER_TIER = SubscriptionTier(tier.lower())
        return JSONResponse({
            "success": True, 
            "tier": CURRENT_USER_TIER.value,
            "message": f"Tier changed to {CURRENT_USER_TIER.value.upper()}"
        })
    except ValueError:
        return JSONResponse(
            {"error": f"Invalid tier: {tier}. Must be one of: free, pro, enterprise"},
            status_code=400
        )


# ========================================
# Stripe Billing Endpoints
# ========================================

@app.post("/api/create-checkout-session")
async def create_stripe_checkout(
    tier: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create Stripe Checkout session for subscription upgrade.
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Validate tier
    try:
        target_tier = SubscriptionTierEnum(tier.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid tier")
    
    if target_tier == SubscriptionTierEnum.FREE:
        raise HTTPException(status_code=400, detail="Cannot purchase FREE tier")
    
    # Get or create subscription
    subscription = user.subscription
    if not subscription:
        subscription = Subscription(user_id=user.id, tier=SubscriptionTierEnum.FREE)
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
    
    # Check if already on this tier
    if subscription.tier == target_tier and subscription.status == SubscriptionStatus.ACTIVE:
        raise HTTPException(status_code=400, detail=f"Already subscribed to {tier}")
    
    # Create Stripe checkout session
    try:
        session_data = create_checkout_session(
            user_email=user.email,
            tier=target_tier,
            success_url=f"{os.getenv('APP_URL', 'http://localhost:8000')}/dashboard?checkout=success",
            cancel_url=f"{os.getenv('APP_URL', 'http://localhost:8000')}/dashboard?checkout=canceled",
            customer_id=subscription.stripe_customer_id
        )
        
        # Update subscription with checkout session
        subscription.stripe_customer_id = session_data["customer_id"]
        db.commit()
        
        return JSONResponse({
            "session_id": session_data["session_id"],
            "url": session_data["url"]
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stripe error: {str(e)}")


@app.post("/api/billing/buy-extra-scans")
async def buy_extra_scans(
    package: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create Stripe Checkout session for purchasing extra scans.
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Only paid tiers can purchase extra scans
    subscription = user.subscription
    if not subscription or subscription.tier == SubscriptionTierEnum.FREE:
        raise HTTPException(status_code=403, detail="Extra scans only available for paid plans")
    
    # ENTERPRISE has unlimited scans, no need for extras
    if subscription.tier == SubscriptionTierEnum.ENTERPRISE:
        raise HTTPException(status_code=400, detail="ENTERPRISE tier has unlimited scans")
    
    try:
        from stripe_integration import create_extra_scans_checkout
        
        checkout_data = create_extra_scans_checkout(
            user_email=user.email,
            package=package,
            success_url=f"{os.getenv('APP_URL', 'http://localhost:8000')}/dashboard?extra_scans_success=true",
            cancel_url=f"{os.getenv('APP_URL', 'http://localhost:8000')}/dashboard?extra_scans_cancel=true",
            customer_id=subscription.stripe_customer_id
        )
        
        # Update customer ID if new customer was created
        if checkout_data.get("customer_id") and not subscription.stripe_customer_id:
            subscription.stripe_customer_id = checkout_data["customer_id"]
            db.commit()
        
        return JSONResponse(content={
            "session_id": checkout_data["session_id"],
            "url": checkout_data["url"]
        })
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stripe error: {str(e)}")


@app.get("/api/billing/portal")
async def billing_portal(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create Stripe Customer Portal session for subscription management.
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    subscription = user.subscription
    if not subscription:
        # Create a subscription if it doesn't exist
        subscription = Subscription(user_id=user.id, tier=SubscriptionTierEnum.FREE)
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
    
    # If no Stripe customer exists, redirect to checkout instead
    if not subscription.stripe_customer_id:
        # Free users should upgrade to get portal access
        raise HTTPException(
            status_code=400, 
            detail="No payment method on file. Please upgrade to a paid plan first."
        )
    
    try:
        portal_data = create_customer_portal_session(
            customer_id=subscription.stripe_customer_id,
            return_url=f"{os.getenv('APP_URL', 'http://localhost:8000')}/dashboard"
        )
        
        return RedirectResponse(url=portal_data["url"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stripe error: {str(e)}")


@app.post("/api/stripe-webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Handle Stripe webhook events.
    """
    payload = await request.body()
    signature = request.headers.get("stripe-signature")
    
    # Verify webhook signature
    event = verify_webhook_signature(payload, signature)
    if not event:
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    event_type = event["type"]
    event_data = event["data"]["object"]
    
    # Handle different event types
    if event_type == "checkout.session.completed":
        # Check if this is a subscription or extra scans purchase
        metadata = event_data.get("metadata", {})
        purchase_type = metadata.get("type", "subscription")
        
        customer_id = event_data.get("customer")
        
        # Find subscription by customer ID
        subscription = db.query(Subscription).filter(
            Subscription.stripe_customer_id == customer_id
        ).first()
        
        if purchase_type == "extra_scans":
            # Handle extra scans purchase
            scans = int(metadata.get("scans", 0))
            package = metadata.get("package", "unknown")
            
            if subscription:
                subscription.extra_scans_purchased += scans
                db.commit()
                
                # Create audit log
                audit = AuditLog(
                    user_id=subscription.user_id,
                    event_type="extra_scans_purchased",
                    description=f"Purchased {scans} extra scans ({package})",
                    extra_data={"package": package, "scans": scans}
                )
                db.add(audit)
                db.commit()
        else:
            # Handle subscription creation
            subscription_id = event_data.get("subscription")
            tier = metadata.get("tier", "PRO")
            
            if subscription:
                subscription.stripe_subscription_id = subscription_id
                subscription.tier = SubscriptionTierEnum(tier.upper())
                subscription.status = SubscriptionStatus.TRIALING
                db.commit()
                
                # Create audit log
                audit = AuditLog(
                    user_id=subscription.user_id,
                    event_type="subscription_created",
                    description=f"Stripe subscription created: {tier}",
                    extra_data={"subscription_id": subscription_id}
                )
                db.add(audit)
                db.commit()
    
    elif event_type == "customer.subscription.updated":
        # Subscription changed (tier upgrade/downgrade or status change)
        subscription_id = event_data.get("id")
        status = event_data.get("status")
        
        subscription = db.query(Subscription).filter(
            Subscription.stripe_subscription_id == subscription_id
        ).first()
        
        if subscription:
            # Map Stripe status to our enum
            status_map = {
                "active": SubscriptionStatus.ACTIVE,
                "trialing": SubscriptionStatus.TRIALING,
                "past_due": SubscriptionStatus.PAST_DUE,
                "canceled": SubscriptionStatus.CANCELED,
                "incomplete": SubscriptionStatus.PAST_DUE,
                "incomplete_expired": SubscriptionStatus.CANCELED,
                "unpaid": SubscriptionStatus.PAST_DUE,
            }
            subscription.status = status_map.get(status, SubscriptionStatus.ACTIVE)
            
            # Update period dates
            subscription.current_period_start = datetime.fromtimestamp(event_data.get("current_period_start"))
            subscription.current_period_end = datetime.fromtimestamp(event_data.get("current_period_end"))
            db.commit()
            
            # Create audit log
            audit = AuditLog(
                user_id=subscription.user_id,
                event_type="subscription_updated",
                description=f"Subscription status: {status}",
                extra_data={"subscription_id": subscription_id}
            )
            db.add(audit)
            db.commit()
    
    elif event_type == "customer.subscription.deleted":
        # Subscription canceled, downgrade to FREE
        subscription_id = event_data.get("id")
        
        subscription = db.query(Subscription).filter(
            Subscription.stripe_subscription_id == subscription_id
        ).first()
        
        if subscription:
            subscription.tier = SubscriptionTierEnum.FREE
            subscription.status = SubscriptionStatus.CANCELED
            db.commit()
            
            # Create audit log
            audit = AuditLog(
                user_id=subscription.user_id,
                event_type="subscription_canceled",
                description="Subscription canceled, downgraded to FREE",
                extra_data={"subscription_id": subscription_id}
            )
            db.add(audit)
            db.commit()
    
    elif event_type == "invoice.payment_succeeded":
        # Payment succeeded, update period dates
        subscription_id = event_data.get("subscription")
        
        subscription = db.query(Subscription).filter(
            Subscription.stripe_subscription_id == subscription_id
        ).first()
        
        if subscription:
            subscription.status = SubscriptionStatus.ACTIVE
            subscription.current_period_start = datetime.fromtimestamp(event_data.get("period_start"))
            subscription.current_period_end = datetime.fromtimestamp(event_data.get("period_end"))
            db.commit()
    
    elif event_type == "invoice.payment_failed":
        # Payment failed, mark as past_due
        subscription_id = event_data.get("subscription")
        
        subscription = db.query(Subscription).filter(
            Subscription.stripe_subscription_id == subscription_id
        ).first()
        
        if subscription:
            subscription.status = SubscriptionStatus.PAST_DUE
            db.commit()
            
            # Create audit log
            audit = AuditLog(
                user_id=subscription.user_id,
                event_type="payment_failed",
                description="Payment failed, subscription past due",
                extra_data={"subscription_id": subscription_id}
            )
            db.add(audit)
            db.commit()
    
    return JSONResponse({"status": "success"})


# ========================================
# Export Endpoints
# ========================================

@app.get("/api/scan/{job_id}/export/json")
async def export_scan_json(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Export scan results as JSON (PRO+ only).
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Check tier (PRO or ENTERPRISE)
    user_tier = get_user_tier(user, db)
    tier_limits = get_tier_limits(user_tier)
    if not tier_limits.enable_json_export:
        raise HTTPException(
            status_code=403,
            detail="JSON export is available in PRO and ENTERPRISE tiers only"
        )
    
    # Get scan from database
    scan = db.query(Scan).filter(
        Scan.job_id == job_id,
        Scan.user_id == user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get report path
    report_path = scan.report_path
    if not report_path or not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Export to JSON
    json_content = export_to_json(report_path)
    
    return Response(
        content=json_content,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=scan_{job_id}.json"
        }
    )


@app.get("/api/scan/{job_id}/export/markdown")
async def export_scan_markdown(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Export scan results as Markdown (PRO+ only).
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Check tier (PRO or ENTERPRISE)
    user_tier = get_user_tier(user, db)
    tier_limits = get_tier_limits(user_tier)
    if not tier_limits.enable_markdown_export:
        raise HTTPException(
            status_code=403,
            detail="Markdown export is available in PRO and ENTERPRISE tiers only"
        )
    
    # Get scan from database
    scan = db.query(Scan).filter(
        Scan.job_id == job_id,
        Scan.user_id == user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get report path
    report_path = scan.report_path
    if not report_path or not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Export to Markdown
    markdown_content = export_to_markdown(report_path)
    
    return Response(
        content=markdown_content,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f"attachment; filename=scan_{job_id}.md"
        }
    )


@app.get("/api/scan/{job_id}/details")
async def scan_details(
    job_id: str,
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a scan.
    """
    # Build query
    query = db.query(Scan).filter(Scan.job_id == job_id)
    
    # Filter by user if authenticated
    if user:
        query = query.filter(Scan.user_id == user.id)
    
    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Count vulnerabilities if report exists
    vuln_count = 0
    if scan.report_path and os.path.exists(scan.report_path):
        vuln_count = count_vulnerabilities_from_report(scan.report_path)
    
    return JSONResponse({
        "job_id": scan.job_id,
        "mode": scan.mode,
        "target": scan.target,
        "status": scan.status.value,
        "vulnerabilities_found": vuln_count,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "report_path": scan.report_path,
        "log_path": scan.log_path,
    })


@app.delete("/api/scan/{job_id}")
async def delete_scan(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a scan and all associated files.
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Get scan from database
    scan = db.query(Scan).filter(
        Scan.job_id == job_id,
        Scan.user_id == user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Delete associated files
    try:
        if scan.report_path and os.path.exists(scan.report_path):
            os.remove(scan.report_path)
        if scan.log_path and os.path.exists(scan.log_path):
            os.remove(scan.log_path)
    except Exception as e:
        print(f"Error deleting scan files: {e}")
    
    # Delete from database
    db.delete(scan)
    db.commit()
    
    return JSONResponse({"success": True, "message": f"Scan {job_id} deleted"})


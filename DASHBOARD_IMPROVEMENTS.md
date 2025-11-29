# Dashboard Improvements & Next Steps

## ✅ Completed (Just Now)

1. **BASIC Tier Added**
   - €4.99/month pricing
   - 2 concurrent scans
   - 20 URLs per scan
   - 25 subdomains limit
   - 10 detectors (basic + 5 advanced)
   - JSON/Markdown export enabled

2. **EUR Pricing**
   - FREE: €0
   - BASIC: €4.99
   - PRO: €9.99
   - ENTERPRISE: €49.99

3. **Delete Scan Endpoint**
   - `DELETE /api/scan/{job_id}`
   - Deletes scan from DB + files
   - User-specific (own scans only)

4. **Updated Files**
   - `subscription.py` - BASIC tier + EUR pricing
   - `models.py` - BASIC enum
   - `stripe_integration.py` - BASIC price ID + EUR
   - `templates/landing.html` - 4 tier pricing cards
   - `webapp.py` - DELETE scan endpoint

## 🔨 Remaining Tasks (To Implement)

### 1. Dashboard UI Improvements

**Current State**: Functional but needs better organization

**Improvements Needed**:
- Reorganize layout into clear sections
- Better scan history table with action buttons
- Scan status cards at the top
- Improved tier info display

**Add to dashboard.html**:
```html
<!-- Scan Actions Column in History Table -->
<td>
    <button onclick="viewScanDetails('{{ scan.job_id }}')" class="btn-sm btn-info">
        📊 Details
    </button>
    {% if user_tier in ['PRO', 'ENTERPRISE', 'BASIC'] %}
    <button onclick="exportScan('{{ scan.job_id }}', 'json')" class="btn-sm btn-secondary">
        📥 JSON
    </button>
    <button onclick="exportScan('{{ scan.job_id }}', 'markdown')" class="btn-sm btn-secondary">
        📥 MD
    </button>
    {% endif %}
    <button onclick="deleteScan('{{ scan.job_id }}')" class="btn-sm btn-danger">
        🗑️ Delete
    </button>
</td>
```

**JavaScript Functions**:
```javascript
async function viewScanDetails(jobId) {
    const response = await fetch(`/api/scan/${jobId}/details`);
    const data = await response.json();
    // Show modal with detailed info
    showScanModal(data);
}

async function exportScan(jobId, format) {
    window.location.href = `/api/scan/${jobId}/export/${format}`;
}

async function deleteScan(jobId) {
    if (!confirm('Delete this scan permanently?')) return;
    
    const response = await fetch(`/api/scan/${jobId}`, { method: 'DELETE' });
    if (response.ok) {
        alert('Scan deleted!');
        location.reload();
    }
}
```

### 2. Scan Details Modal

**Add to dashboard.html**:
```html
<!-- Modal HTML -->
<div id="scanModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeScanModal()">&times;</span>
        <h2>Scan Details</h2>
        <div id="scanModalBody">
            <!-- Populated by JavaScript -->
        </div>
    </div>
</div>

<style>
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.8);
}
.modal-content {
    background-color: #0b1120;
    margin: 5% auto;
    padding: 2rem;
    border: 1px solid #1f2937;
    border-radius: 1rem;
    width: 80%;
    max-width: 800px;
}
</style>
```

**JavaScript for Modal**:
```javascript
function showScanModal(data) {
    const modal = document.getElementById('scanModal');
    const body = document.getElementById('scanModalBody');
    
    body.innerHTML = `
        <p><strong>Job ID:</strong> ${data.job_id}</p>
        <p><strong>Target:</strong> ${data.target}</p>
        <p><strong>Mode:</strong> ${data.mode}</p>
        <p><strong>Status:</strong> ${data.status}</p>
        <p><strong>Vulnerabilities Found:</strong> ${data.vulnerabilities_found}</p>
        <p><strong>Started:</strong> ${new Date(data.started_at).toLocaleString()}</p>
        <p><strong>Completed:</strong> ${data.completed_at ? new Date(data.completed_at).toLocaleString() : 'In progress'}</p>
        
        ${data.report_path ? `<a href="${data.report_path}" target="_blank" class="btn btn-primary">📄 View Full Report</a>` : ''}
    `;
    
    modal.style.display = 'block';
}

function closeScanModal() {
    document.getElementById('scanModal').style.display = 'none';
}
```

### 3. Email Verification System

**Create new file**: `email_service.py`
```python
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
FROM_EMAIL = os.getenv("FROM_EMAIL", "noreply@bugbountyarsenal.com")

def send_verification_email(to_email: str, verification_token: str, base_url: str):
    """Send email verification link"""
    verification_url = f"{base_url}/verify-email?token={verification_token}"
    
    html = f"""
    <html>
        <body>
            <h2>Welcome to BugBounty Arsenal!</h2>
            <p>Please verify your email address to activate your account:</p>
            <p><a href="{verification_url}">Verify Email Address</a></p>
            <p>Or copy this link: {verification_url}</p>
            <p>This link expires in 24 hours.</p>
        </body>
    </html>
    """
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Verify your BugBounty Arsenal account"
    msg['From'] = FROM_EMAIL
    msg['To'] = to_email
    
    msg.attach(MIMEText(html, 'html'))
    
    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(FROM_EMAIL, [to_email], msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False
```

**Update webapp.py signup endpoint**:
```python
from email_service import send_verification_email

@app.post("/api/signup")
async def signup(...):
    # ... existing code ...
    
    # Generate verification token
    verification_token = generate_verification_token()
    user.verification_token = verification_token
    user.is_verified = False  # Don't auto-verify
    
    db.commit()
    
    # Send verification email
    base_url = os.getenv("APP_URL", "http://localhost:8000")
    send_verification_email(user.email, verification_token, base_url)
    
    return JSONResponse({
        "message": "Account created! Please check your email to verify.",
        "email": user.email
    })

@app.get("/verify-email")
async def verify_email(token: str, db: Session = Depends(get_db)):
    """Verify email with token"""
    user = db.query(User).filter(User.verification_token == token).first()
    
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification token")
    
    user.is_verified = True
    user.verification_token = None
    db.commit()
    
    return RedirectResponse(url="/login?verified=true")
```

**Update login to check verification**:
```python
@app.post("/api/login")
async def login(...):
    # ... after password check ...
    
    if not user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="Email not verified. Please check your inbox."
        )
    
    # ... rest of login logic ...
```

### 4. Admin Button for Superuser

**Update dashboard.html header**:
```html
<header>
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h1>BugBounty Arsenal v2.0</h1>
        </div>
        <div style="text-align: right;">
            <span class="tag">{{ tier_info.name }} PLAN</span>
            
            {% if user.is_superuser %}
            <a href="/admin" class="btn-admin" style="display: inline-block; margin: 0.5rem;">
                🛡️ Admin Panel
            </a>
            {% endif %}
            
            <button onclick="window.location.href='/api/logout'" class="btn-secondary">
                Logout
            </button>
        </div>
    </div>
</header>

<style>
.btn-admin {
    padding: 0.4rem 0.8rem;
    background: linear-gradient(135deg, #ef4444, #dc2626);
    color: white;
    border-radius: 0.4rem;
    text-decoration: none;
    font-size: 0.85rem;
    font-weight: 600;
}
.btn-admin:hover {
    background: linear-gradient(135deg, #dc2626, #b91c1c);
}
</style>
```

### 5. Update .env.example

```env
# Application
APP_URL=http://localhost:8000
DATABASE_URL=sqlite:///./bugbounty_arsenal.db
JWT_SECRET_KEY=your-secret-key-change-in-production

# Stripe (EUR Pricing)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_BASIC=price_1Basic...
STRIPE_PRICE_PRO=price_1Pro...
STRIPE_PRICE_ENT=price_1Enterprise...

# Email (for verification)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=noreply@bugbountyarsenal.com
```

### 6. Create Stripe Products (in Dashboard)

1. Go to https://dashboard.stripe.com/test/products
2. Create 3 products:
   - **BASIC**: €4.99/month → Copy Price ID
   - **PRO**: €9.99/month → Copy Price ID
   - **ENTERPRISE**: €49.99/month → Copy Price ID
3. Add Price IDs to `.env`

### 7. Test Email with Gmail

**Gmail App Password Setup**:
1. Go to Google Account → Security
2. Enable 2-Step Verification
3. Generate App Password
4. Use in `.env` as `SMTP_PASSWORD`

## 📝 Implementation Order

1. ✅ **BASIC Tier** - Done
2. ✅ **EUR Pricing** - Done
3. ✅ **DELETE Endpoint** - Done
4. ⏳ **Dashboard UI** - Add action buttons to table
5. ⏳ **Scan Modal** - Add modal HTML + JS
6. ⏳ **Admin Button** - Add to header with conditional
7. ⏳ **Email Service** - Create email_service.py
8. ⏳ **Email Verification** - Update signup/login
9. ⏳ **Test Everything** - End-to-end testing

## 🧪 Testing Checklist

- [ ] Sign up with new email
- [ ] Receive verification email
- [ ] Click verification link
- [ ] Login successfully
- [ ] See correct tier pricing (EUR)
- [ ] Start a scan
- [ ] View scan details in modal
- [ ] Export scan as JSON
- [ ] Export scan as Markdown
- [ ] Delete a scan
- [ ] Upgrade to BASIC tier
- [ ] Test admin panel (superuser only)
- [ ] Admin button visible only for superuser

## 🎯 Quick Implementation Script

Due to context limitations, here's a prioritized approach:

**Priority 1 (Critical)**:
- Email verification (security)
- Admin button visibility
- Scan action buttons (export/delete)

**Priority 2 (Important)**:
- Scan details modal
- Dashboard UI cleanup

**Priority 3 (Nice to have)**:
- Enhanced styling
- More statistics

---

**Status**: BASIC tier + EUR pricing + DELETE endpoint complete  
**Next**: Implement email verification system  
**Server**: Running on port 8000 with all changes

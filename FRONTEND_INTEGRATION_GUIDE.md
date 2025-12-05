# Frontend API Integration - Testing Guide

## ✅ Completed Integration

### API Client (`api-client.js`)
- Centralized JavaScript API client with JWT authentication
- Automatic token refresh on 401 responses
- LocalStorage for token persistence
- Automatic redirect to login for protected pages

### Integrated Pages

1. **Login Page** (`/login/`)
   - JWT authentication with access/refresh tokens
   - Error handling and validation
   - Auto-redirect to dashboard on success

2. **Signup Page** (`/signup/`)
   - User registration with JWT tokens
   - Password validation (min 8 chars)
   - Confirm password matching
   - Auto-redirect to dashboard after signup

3. **Dashboard** (`/dashboard/`)
   - Scan status polling every 10 seconds
   - Start new scans with API
   - Stop running scans
   - Buy extra scans (Stripe integration)
   - Change subscription tier
   - Open billing portal
   - All operations with JWT authentication

4. **Admin Panel** (`/admin-panel/`)
   - Admin statistics dashboard
   - User management list
   - Scan overview list
   - System health monitoring
   - Protected by admin-only authentication

## 🧪 Testing the Integration

### 1. Test Login Flow
```bash
# Access login page
curl http://localhost:8000/login/

# Test login API directly
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@example.com","password":"TestPass123!"}'

# Expected response:
# {
#   "access": "eyJhbGci...",
#   "refresh": "eyJhbGci...",
#   "user": {"email":"testuser@example.com"}
# }
```

### 2. Test Signup Flow
```bash
# Test signup API
curl -X POST http://localhost:8000/api/auth/signup/ \
  -H "Content-Type: application/json" \
  -d '{
    "email":"newuser@example.com",
    "password":"SecurePass123!",
    "full_name":"New User"
  }'
```

### 3. Test Dashboard API Calls
```bash
# Get JWT token first
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@example.com","password":"TestPass123!"}' \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['access'])")

# Test scan status
curl -X GET http://localhost:8000/api/scans/status/ \
  -H "Authorization: Bearer $TOKEN"

# Test start scan
curl -X POST http://localhost:8000/api/scans/start/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","scan_type":"web_security"}'

# Test billing portal
curl -X GET http://localhost:8000/api/billing/portal/ \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Test Admin Panel
```bash
# Login as admin
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"AdminPass123!"}' \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['access'])")

# Test admin stats
curl -X GET http://localhost:8000/api/admin/stats/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool

# Test admin users list
curl -X GET http://localhost:8000/api/admin/users/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool

# Test system health
curl -X GET http://localhost:8000/api/admin/system-health/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool
```

## 🌐 Browser Testing

### Manual Flow Testing

1. **Registration and Login**
   - Open http://localhost:8000/signup/
   - Create a new account
   - Verify JWT tokens in browser console: `localStorage.getItem('access_token')`
   - Should auto-redirect to dashboard

2. **Dashboard Operations**
   - Open http://localhost:8000/dashboard/
   - Try starting a new scan
   - Monitor scan status updates (auto-refresh every 10 seconds)
   - Test "Buy Extra Scans" button (opens modal)
   - Test "Manage Subscription" button (in test mode)

3. **Admin Panel** (requires superuser)
   - Open http://localhost:8000/admin-panel/
   - View dashboard statistics
   - Navigate between tabs (Dashboard, Users, Scans)
   - Verify data loads correctly

### Browser Console Testing
```javascript
// Check if API client is loaded
window.api

// Test authentication status
window.api.isAuthenticated()

// Check stored tokens
localStorage.getItem('access_token')
localStorage.getItem('refresh_token')

// Test API call
await window.api.getScanStatus()

// Test admin call (if admin)
await window.api.getAdminStats()
```

## 🔒 Authentication Features

### JWT Token Management
- **Access Token**: Short-lived (7 days default), used for API requests
- **Refresh Token**: Long-lived, used to get new access tokens
- **Auto-Refresh**: Automatically refreshes expired access tokens
- **Logout**: Clears all tokens and redirects to login

### Protected Routes
- Dashboard requires authentication
- Admin panel requires staff/superuser status
- All API endpoints validate JWT tokens
- Automatic redirect to `/login/` if not authenticated

## 🎨 UI Features

### Error Handling
- Login errors: Display inline error messages
- Signup validation: Password strength, matching passwords
- API errors: User-friendly error messages in alerts or error divs
- Network errors: Clear feedback to user

### Loading States
- Button text changes during operations ("Sign In" → "Signing in...")
- Buttons disabled during API calls
- Auto-refresh indicators for scan status

## 📝 API Client Methods

### Authentication
```javascript
await window.api.login(email, password)
await window.api.signup(email, password, fullName)
window.api.logout()
window.api.isAuthenticated()
```

### Scan Operations
```javascript
await window.api.getScanStatus()
await window.api.startScan(target, scanType, options)
await window.api.stopScan(scanId)
await window.api.validateScope(target)
```

### Billing
```javascript
await window.api.createCheckoutSession(planId, successUrl, cancelUrl)
await window.api.getBillingPortal()
await window.api.buyExtraScans(quantity)
await window.api.changeTier(newPlanId)
```

### Admin
```javascript
await window.api.getAdminStats()
await window.api.getAdminUsers(params)
await window.api.activateUser(userId)
await window.api.deactivateUser(userId)
await window.api.getAdminScans(params)
await window.api.getSystemHealth()
await window.api.clearCache()
```

## 🐛 Troubleshooting

### Tokens Not Saving
- Check browser console for errors
- Verify localStorage is enabled
- Check for CORS issues

### API Calls Failing
- Verify Docker containers are running: `docker compose ps`
- Check container logs: `docker compose logs web`
- Verify JWT token in localStorage
- Check browser network tab for request details

### 401 Unauthorized Errors
- Token may be expired or invalid
- Try logging out and logging in again
- Check token refresh logic in browser console

### Admin Panel Not Loading
- Verify user has `is_staff=True` or `is_superuser=True`
- Check admin API endpoints are working: `curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/admin/stats/`

## ✨ Next Steps

1. **Production Deployment**
   - Configure HTTPS/SSL
   - Set proper CORS headers
   - Use production Stripe keys
   - Configure PostgreSQL

2. **Additional Features**
   - OAuth login integration (Google, GitHub)
   - Real-time scan progress with WebSockets
   - Advanced admin features (user deactivation UI)
   - Email notifications

3. **Testing**
   - Unit tests for API client
   - Integration tests for complete flows
   - E2E tests with Selenium/Playwright

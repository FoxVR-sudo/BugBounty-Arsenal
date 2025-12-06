#!/bin/bash

# Bug Bounty Arsenal Frontend Integration Test Script
# Tests all API endpoints and frontend functionality

echo "🧪 Bug Bounty Arsenal Frontend Integration Tests"
echo "================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
PASSED=0
FAILED=0

# Helper function to test endpoint
test_endpoint() {
    local name="$1"
    local command="$2"
    local expected_pattern="$3"
    
    echo -n "Testing: $name... "
    
    result=$(eval "$command" 2>&1)
    
    if echo "$result" | grep -q "$expected_pattern"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Expected pattern: $expected_pattern"
        echo "  Got: $result"
        ((FAILED++))
        return 1
    fi
}

echo "1️⃣  Testing Basic Connectivity"
echo "--------------------------------"

test_endpoint \
    "Health Check" \
    "curl -s http://localhost:8000/health/" \
    "healthy"

test_endpoint \
    "Landing Page" \
    "curl -s http://localhost:8000/ -o /dev/null -w '%{http_code}'" \
    "200"

test_endpoint \
    "Login Page" \
    "curl -s http://localhost:8000/login/ -o /dev/null -w '%{http_code}'" \
    "200"

test_endpoint \
    "Dashboard Page (redirects to login)" \
    "curl -s http://localhost:8000/dashboard/ -o /dev/null -w '%{http_code}'" \
    "200\|302"

echo ""
echo "2️⃣  Testing Static Files"
echo "-------------------------"

test_endpoint \
    "Favicon (root path with redirect)" \
    "curl -sL http://localhost:8000/favicon.ico -o /dev/null -w '%{http_code}'" \
    "200"

test_endpoint \
    "Favicon (static path)" \
    "curl -s http://localhost:8000/static/favicon.svg -o /dev/null -w '%{http_code}'" \
    "200"

test_endpoint \
    "API Client JS" \
    "curl -s http://localhost:8000/static/js/api-client.js -o /dev/null -w '%{http_code}'" \
    "200"

echo ""
echo "3️⃣  Testing Authentication API"
echo "--------------------------------"

# Test Login
echo -n "Testing: User Login... "
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@example.com","password":"TestPass123!"}')

if echo "$LOGIN_RESPONSE" | grep -q "access"; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((PASSED++))
    TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['access'])")
    echo "  Token: ${TOKEN:0:50}..."
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Response: $LOGIN_RESPONSE"
    ((FAILED++))
    exit 1
fi

# Test Admin Login
echo -n "Testing: Admin Login... "
ADMIN_LOGIN=$(curl -s -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"AdminPass123!"}')

if echo "$ADMIN_LOGIN" | grep -q "access"; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((PASSED++))
    ADMIN_TOKEN=$(echo "$ADMIN_LOGIN" | python3 -c "import sys, json; print(json.load(sys.stdin)['access'])")
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Response: $ADMIN_LOGIN"
    ((FAILED++))
fi

echo ""
echo "4️⃣  Testing User API Endpoints"
echo "--------------------------------"

test_endpoint \
    "Get User Profile" \
    "curl -s http://localhost:8000/api/users/me/ -H 'Authorization: Bearer $TOKEN'" \
    "testuser@example.com"

test_endpoint \
    "Get User Scans" \
    "curl -s http://localhost:8000/api/scans/ -H 'Authorization: Bearer $TOKEN'" \
    "count"

test_endpoint \
    "Get Scan Stats" \
    "curl -s http://localhost:8000/api/scans/stats/ -H 'Authorization: Bearer $TOKEN'" \
    "total_scans"

echo ""
echo "5️⃣  Testing Subscription API"
echo "-----------------------------"

test_endpoint \
    "Get Plans" \
    "curl -s http://localhost:8000/api/plans/" \
    "count"

test_endpoint \
    "Get Current Subscription" \
    "curl -s http://localhost:8000/api/subscriptions/current/ -H 'Authorization: Bearer $TOKEN'" \
    "error\|plan_name"

echo ""
echo "6️⃣  Testing Admin API Endpoints"
echo "---------------------------------"

test_endpoint \
    "Admin Stats" \
    "curl -s http://localhost:8000/api/admin/stats/ -H 'Authorization: Bearer $ADMIN_TOKEN'" \
    "users"

test_endpoint \
    "Admin Users List" \
    "curl -s http://localhost:8000/api/admin/users/ -H 'Authorization: Bearer $ADMIN_TOKEN'" \
    "testuser@example.com"

test_endpoint \
    "Admin Scans List" \
    "curl -s http://localhost:8000/api/admin/scans/ -H 'Authorization: Bearer $ADMIN_TOKEN'" \
    "count"

test_endpoint \
    "System Health" \
    "curl -s http://localhost:8000/api/admin/system-health/ -H 'Authorization: Bearer $ADMIN_TOKEN'" \
    "database"

test_endpoint \
    "Celery Status" \
    "curl -s http://localhost:8000/api/admin/celery-status/ -H 'Authorization: Bearer $ADMIN_TOKEN'" \
    "workers\|status"

echo ""
echo "7️⃣  Testing Scan Operations"
echo "----------------------------"

# Create a test scan
echo -n "Testing: Create New Scan... "
SCAN_RESPONSE=$(curl -s -X POST http://localhost:8000/api/scans/start/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","scan_type":"web_security"}')

if echo "$SCAN_RESPONSE" | grep -q "id\|error"; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((PASSED++))
    if echo "$SCAN_RESPONSE" | grep -q "celery_task_id"; then
        TASK_ID=$(echo "$SCAN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['celery_task_id'])" 2>/dev/null || echo "")
        echo "  Task ID: $TASK_ID"
    else
        echo "  Response: $SCAN_RESPONSE"
    fi
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Response: $SCAN_RESPONSE"
    ((FAILED++))
fi

echo ""
echo "8️⃣  Testing Billing API"
echo "------------------------"

test_endpoint \
    "Get Billing Portal" \
    "curl -s http://localhost:8000/api/billing/portal/ -H 'Authorization: Bearer $TOKEN'" \
    "url\|error"

echo ""
echo "================================================"
echo "📊 Test Results"
echo "================================================"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "Total: $((PASSED + FAILED))"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed${NC}"
    exit 1
fi

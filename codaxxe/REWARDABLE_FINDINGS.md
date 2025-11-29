# Rewardable Vulnerabilities - Grammarly API

## [HIGH] XXE - Error-Based Detection
- **URL:** https://codacontent.io
- **Описание:** XXE error detected with payload "invalid_entity". Server error message indicates XML external entity processing.
- **Payload:** `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]><root><data>&xxe;</data></root>`
- **Детектор:** xxe_detector
- **Доказателство:** Error excerpt in response

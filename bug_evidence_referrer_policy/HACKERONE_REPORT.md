# Missing Referrer-Policy Header on www.syfe.com

## Summary
The Syfe website (`https://www.syfe.com`) does not implement the `Referrer-Policy` HTTP security header. This may result in sensitive information being leaked through the Referer header when users navigate to external sites from Syfe pages.

## Severity
**Low** (CVSS 3.7 - AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

## CWE
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## Description
The `Referrer-Policy` header controls how much referrer information (sent via the `Referer` header) should be included with requests. When this header is missing, browsers use their default policy, which typically sends the full URL including query parameters.

This is particularly concerning for financial applications like Syfe where URLs might contain:
- Session identifiers
- User account numbers
- Transaction IDs
- Portfolio values
- Other sensitive parameters

## Impact
Without a proper Referrer-Policy:

1. **Privacy Leak**: When users click external links from Syfe (social media, support articles, partner sites), the full URL including any query parameters is sent in the Referer header
2. **Session Token Exposure**: If session tokens are in URLs (even temporarily), they could be leaked to third parties
3. **Information Disclosure**: Internal application structure and parameter names are exposed to third parties
4. **Compliance Risk**: May violate data protection regulations (GDPR, PDPA) regarding user privacy

## Steps to Reproduce

### Method 1: Using cURL
```bash
curl -I https://www.syfe.com
```

**Expected**: Response headers should include `Referrer-Policy`  
**Actual**: No `Referrer-Policy` header present

### Method 2: Using Browser DevTools
1. Open https://www.syfe.com in browser
2. Press F12 to open DevTools
3. Go to Network tab
4. Refresh the page
5. Click on the main document request
6. Check Response Headers
7. Observe: No `Referrer-Policy` header

### Method 3: Using online scanner
- Test at https://securityheaders.com/?q=https://www.syfe.com
- Result shows missing Referrer-Policy

## Proof of Concept

```bash
# Check all security headers
curl -I https://www.syfe.com 2>&1 | grep -i referrer

# Output: (empty - header not present)
```

## Recommended Fix

Add the `Referrer-Policy` header to all HTTP responses:

### Nginx Configuration:
```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### Apache Configuration:
```apache
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

### Recommended Policy Values (in order of preference):
1. **`strict-origin-when-cross-origin`** (Recommended) - Sends full URL for same-origin, only origin for cross-origin HTTPS, nothing for HTTP
2. **`no-referrer-when-downgrade`** - Sends full URL for same-level or higher security (HTTPS→HTTPS), nothing for downgrades (HTTPS→HTTP)
3. **`same-origin`** - Only sends referrer for same-origin requests
4. **`no-referrer`** (Most restrictive) - Never sends referrer (may break analytics)

## References
- MDN Web Docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
- OWASP Secure Headers: https://owasp.org/www-project-secure-headers/#referrer-policy
- Scott Helme's Guide: https://scotthelme.co.uk/a-new-security-header-referrer-policy/
- CWE-200: https://cwe.mitre.org/data/definitions/200.html

## Additional Notes
- This finding was discovered during passive reconnaissance
- No exploitation attempts were made
- All testing was done using standard HTTP clients
- This is a defense-in-depth security measure

---

**Discovered**: November 04, 2025  
**Target**: https://www.syfe.com  
**Tool**: Safe Reconnaissance Scanner  

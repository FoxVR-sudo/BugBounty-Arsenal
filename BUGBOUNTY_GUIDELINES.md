# Bug Bounty Submission Guidelines

## What Bug Bounty Programs Accept

### ✅ ACCEPTED Vulnerabilities

#### 1. **SSRF with Real Impact**
HackerOne, Bugcrowd, and most programs require **proof of exploitation**:

**Acceptable SSRF proofs:**
- ✅ AWS IAM credentials extraction (`AccessKeyId`, `SecretAccessKey`)
- ✅ GCP service account token extraction
- ✅ Azure managed identity token access
- ✅ Internal service interaction (Redis, Elasticsearch, databases)
- ✅ Local file reading (`/etc/passwd`, config files)
- ✅ Internal port scanning showing open ports with service banners
- ✅ SMTP interaction to send emails
- ✅ Server-side code execution via internal APIs

**NOT acceptable SSRF proofs:**
- ❌ DNS pingback alone (Burp Collaborator, interact.sh)
- ❌ HTTP pingback without data extraction
- ❌ Simple 200 OK response from internal endpoint
- ❌ Timeout differences (timing attacks)

**Example from HackerOne:**
> "DNS interactions and HTTP pingbacks on their own are not a vulnerability, and cannot be exploited in any known way."

#### 2. **XSS with Real Impact**
- ✅ Stored XSS (persists across sessions)
- ✅ DOM-based XSS with user interaction
- ✅ Reflected XSS in critical functionality (admin panels, payment pages)
- ✅ Bypassing CSP/WAF protections
- ❌ Self-XSS (requires victim to paste malicious code)
- ❌ XSS in error messages without reflected payload

#### 3. **SQL Injection**
- ✅ Blind SQLi with time-based confirmation
- ✅ Boolean-based SQLi with clear difference in responses
- ✅ Error-based SQLi showing database errors
- ✅ Union-based SQLi extracting data
- ❌ Generic error messages without confirmation
- ❌ Syntax errors without exploitability

#### 4. **Authentication/Authorization**
- ✅ Account takeover via password reset
- ✅ IDOR accessing other users' data
- ✅ Privilege escalation (user → admin)
- ✅ JWT vulnerabilities with proof of token forgery
- ❌ Username enumeration (usually informational)
- ❌ Verbose error messages (usually low severity)

#### 5. **Business Logic Flaws**
- ✅ Payment bypass (paying $0 for items)
- ✅ Race conditions leading to double spending
- ✅ Mass assignment changing restricted fields
- ✅ CAPTCHA bypass
- ❌ Missing rate limiting (unless exploitable)
- ❌ Information disclosure without impact

---

## How to Provide Strong Evidence

### 1. **Screenshots/Videos**
- Show the full attack flow
- Include timestamps
- Highlight sensitive data (blur if needed)
- Show URL in browser

### 2. **HTTP Request/Response**
```http
POST /api/transfer HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{"amount": -100, "to": "attacker"}

HTTP/1.1 200 OK
{"success": true, "new_balance": 1000100}
```

### 3. **Proof of Concept (PoC)**
```python
# Working exploit code
import requests

# Step 1: Get CSRF token
s = requests.Session()
s.get("https://target.com/login")

# Step 2: Exploit vulnerability
response = s.post("https://target.com/api/ssrf", 
    data={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})

# Step 3: Show extracted credentials
print(response.text)  # Shows AccessKeyId, SecretAccessKey
```

### 4. **Impact Statement**
```
IMPACT:
- Attacker can extract AWS IAM credentials
- Credentials grant full access to EC2 instances
- Can lead to:
  * Data breach (access to S3 buckets)
  * Lateral movement in AWS infrastructure
  * Cost amplification attacks
  
BUSINESS IMPACT:
- Estimated $50,000+ in potential data breach costs
- Regulatory compliance violations (GDPR, CCPA)
- Reputational damage
```

---

## Severity Guidelines

### Critical ($5,000 - $30,000)
- Remote Code Execution (RCE)
- SSRF with cloud metadata access
- SQL Injection in production database
- Authentication bypass in critical systems
- Payment/financial logic flaws

### High ($1,000 - $10,000)
- Stored XSS in main application
- IDOR in sensitive data
- Privilege escalation
- SSRF accessing internal services
- Account takeover

### Medium ($500 - $3,000)
- Reflected XSS with user interaction
- CSRF in state-changing operations
- Information disclosure (PII)
- Security misconfigurations with impact

### Low ($100 - $500)
- Missing security headers (CSP, HSTS)
- Verbose error messages
- Weak password policy
- Information disclosure (non-sensitive)

### Informational (No bounty)
- SSL/TLS issues (outdated but not exploitable)
- Missing best practices
- UI/UX issues
- Out of scope findings

---

## Program-Specific Requirements

### HackerOne
- Proof of exploitation required
- No duplicate reports
- Must follow disclosure timeline
- Provide remediation suggestions

### Bugcrowd
- Proof of Concept (PoC) required
- Clear impact statement
- Test on staging if available
- No automated scanning without permission

### YesWeHack
- Detailed technical write-up
- French/English language support
- CVSS score calculation helpful
- Video proof preferred for complex issues

### Intigriti
- Proof of vulnerability required
- Impact assessment mandatory
- No social engineering
- European GDPR compliance important

---

## Red Flags (Will Get Report Rejected)

❌ **No proof of exploitation**
```
"I think this endpoint might be vulnerable to SSRF because it accepts URLs"
```

❌ **Out of scope targets**
```
"Found vulnerability on old.company.com (marked as out of scope in program)"
```

❌ **Known issues**
```
"Missing HSTS header" (often marked as known/accepted risk)
```

❌ **Automated scanner results without validation**
```
"Nessus reported SQL injection here" (without manual confirmation)
```

❌ **Vague descriptions**
```
"I found a security issue on your website"
```

✅ **Good example:**
```
TITLE: SSRF in /api/preview allows AWS IAM credential extraction

DESCRIPTION:
The /api/preview endpoint accepts a 'url' parameter without proper validation,
allowing Server-Side Request Forgery attacks.

STEPS TO REPRODUCE:
1. Send POST request to /api/preview with url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
2. Observe IAM role name in response
3. Send second request with full path to role
4. Extract AccessKeyId and SecretAccessKey

IMPACT:
- Attacker can extract AWS IAM credentials
- Full EC2 instance access
- Potential data breach in connected S3 buckets

REMEDIATION:
- Implement URL whitelist for allowed domains
- Block access to 169.254.169.254
- Use IMDSv2 with token requirement
```

---

## Testing Tips

### Before Submitting:
1. ✅ Verify finding is **in scope**
2. ✅ Confirm it's not a **known issue** (check program updates)
3. ✅ Test with **proof of exploitation** (not just theory)
4. ✅ Check for **duplicates** (search existing reports)
5. ✅ Provide **clear reproduction steps**
6. ✅ Include **remediation advice**
7. ✅ Calculate **accurate severity** (use CVSS if required)

### During Testing:
- Use responsible disclosure
- Don't access more data than needed for PoC
- Don't perform DoS attacks
- Don't test on production without permission
- Keep detailed logs of your testing
- Blur/redact sensitive data in reports

---

## Our Scanner Configuration

### To test with real exploitation (like HackerOne requires):
```bash
# Enable destructive/advanced tests
python main.py --recon target.com --consent --destructive

# This will:
# - Test AWS/GCP/Azure metadata endpoints
# - Attempt local file reading
# - Probe internal services
# - Extract cloud credentials if vulnerable
```

### To test conservatively (reconnaissance only):
```bash
# Safe scanning (no exploitation attempts)
python main.py --recon target.com --consent

# This will:
# - Enumerate subdomains
# - Detect patterns and indicators
# - Flag potential issues for manual testing
```

---

## Resources

- [HackerOne Disclosure Guidelines](https://www.hackerone.com/disclosure-guidelines)
- [Bugcrowd VRT (Vulnerability Rating Taxonomy)](https://bugcrowd.com/vulnerability-rating-taxonomy)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PentesterLab SSRF Exercises](https://pentesterlab.com/exercises/ssrf)

---

**Remember:** Quality > Quantity. One well-documented, high-impact finding is worth more than 100 low-quality reports.

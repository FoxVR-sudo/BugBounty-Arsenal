# 🎯 Under Armour - Priority Findings for Bugcrowd

**Scan Date:** November 2, 2025  
**Total Findings:** 12,047  
**Target:** underarmour.com  
**Scan Time:** 45 minutes  

---

## 🔥 CRITICAL - SSRF (12 findings)

### 1. SSRF on DEV Environment (HIGHEST PRIORITY)
- **URL:** https://jss-dev.underarmour.com
- **Parameter:** `input`
- **Confidence:** High
- **Impact:** Dev environment SSRF = potential AWS metadata access
- **Estimated Bounty:** $5,000 - $15,000

**Why High Value:**
- Dev environments often have relaxed security
- Direct AWS metadata access possible
- Can leak internal architecture/credentials

**Repro:**
```bash
curl -i "https://jss-dev.underarmour.com?input=http://169.254.169.254/latest/meta-data/"
```

---

### 2. SSRF on Careers Portal (x2)
- **URL:** https://careers.underarmour.com
- **Parameters:** `input`
- **Confidence:** High
- **Estimated Bounty:** $2,000 - $8,000

**Tests Confirmed:**
- ✅ External URL fetch: `http://example.com/ping`
- ✅ Internal network access: `http://127.0.0.1`

---

### 3. SSRF on Frontend Docs
- **URL:** https://frontenddocs.ecm.underarmour.com
- **Parameter:** `input`
- **Confidence:** High
- **Estimated Bounty:** $2,000 - $8,000

---

## 🔑 HIGH - SECRETS (77 findings)

### AWS Credentials Exposed
- **URL:** https://apphouse.underarmour.com
- **Type:** AWS Secret Keys (heuristic detection)
- **Confidence:** Medium (needs manual verification)
- **Estimated Bounty:** $500 - $5,000 (if valid)

**Action Required:**
- Manual verification of exposed keys
- Check if they're test/production credentials
- Test access scope

---

## ⚡ HIGH - XXE (73 findings)

### XXE Error-Based Detection
**Top Targets:**
1. `https://armouru2.underarmour.com` - XML processing errors
2. `https://about.underarmour.com` - DOCTYPE errors detected
3. `https://cms2.ecm.underarmour.com` - CMS with XML parsing

**Confidence:** Medium (error-based detection)  
**Estimated Bounty:** $1,000 - $5,000 per confirmed XXE  

**Next Step:** Manual exploitation with XXE payloads to confirm file read/SSRF

---

## 📁 HIGH - LFI (170 findings)

### API Gateway LFI
- **URL:** https://api-gw.underarmour.com (5 LFI parameters)
- **Confidence:** Low-Medium (pattern-based)
- **Estimated Bounty:** $500 - $3,000 if confirmed

**High-Value LFI Targets:**
- `api-gw.underarmour.com` - Main API gateway
- `shop-api.underarmour.com` - E-commerce API
- `shop-api-staging.underarmour.com` - Staging environment

---

## �� HIGH-VALUE API ENDPOINTS (10+ found)

**E-Commerce APIs:**
- `shop-api.underarmour.com`
- `shop-api-staging.underarmour.com`

**Development APIs:**
- `api-dev-emea.ecm.underarmour.com`
- `api-integration.ecm.underarmour.com`
- `api-load.ecm.underarmour.com`

**Third-Party Integrations:**
- `api-connect.underarmour.com`
- `api-notredamenil.underarmour.com`

---

## 💰 RECOMMENDED REPORTING STRATEGY

### Priority 1 - Submit Immediately (Est. $7K-$20K)
1. **SSRF on jss-dev.underarmour.com**  
   - Manual test for AWS metadata access
   - Confirm internal network reach
   - Document impact clearly

2. **SSRF on careers.underarmour.com**  
   - Confirm both HTTP/HTTPS work
   - Test cloud metadata endpoints
   - Show internal service access

### Priority 2 - Verify Then Submit (Est. $2K-$10K)
1. **AWS Secrets on apphouse.underarmour.com**  
   - Verify keys are valid (safe checks only)
   - Determine scope (read-only vs full access)
   - Screenshot evidence

2. **XXE on CMS endpoints**  
   - Manual XXE exploitation
   - Try file read: `/etc/passwd`
   - Test SSRF via XXE

### Priority 3 - Bulk Submission (Est. $500-$3K)
- LFI patterns on API endpoints
- Prototype Pollution findings
- Security header issues

---

## 🚀 NEXT STEPS

1. **Manual Verification** (1-2 hours)
   - Test SSRF for AWS metadata access
   - Verify secret keys validity
   - Exploit XXE manually

2. **Documentation** (30 min)
   - Screenshot evidence
   - Impact descriptions
   - Remediation advice

3. **Bugcrowd Submission** (same day)
   - Start with SSRF (highest bounty)
   - Follow with secrets if valid
   - Batch submit lower severity

**Expected Timeline:**
- Verification: 1-2 hours
- First reports: Today
- Response time: 1-7 days
- Potential payout: $10,000-$30,000

---

## 📊 SCAN STATISTICS

- **Subdomains Found:** 806
- **Live Hosts:** 212
- **Total Findings:** 12,047
- **Critical:** 12 (SSRF)
- **High:** 352 (Secrets, XXE, LFI)
- **Medium:** 10,904
- **Low:** 779

**Scanner Features Used:**
- ✅ Cloudflare bypass (delays 2-4s)
- ✅ Destructive tests enabled
- ✅ Advanced SSRF detection
- ✅ Secret pattern matching
- ✅ 23 active detectors

**Scan completed successfully on November 2, 2025**

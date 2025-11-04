# CVE Exploit Scanner

Automated vulnerability scanner that detects known CVEs using multiple sources without requiring local Exploit-DB installation.

## Features

### 🔍 Technology Detection
- Web server fingerprinting (Apache, nginx, IIS)
- Programming language detection (PHP, Python, Node.js)
- CMS identification (WordPress, Joomla, Drupal)
- JavaScript library detection (jQuery, React, Angular)
- Framework detection (Bootstrap, etc.)

### 🎯 CVE Discovery Methods

1. **Built-in Vulnerability Database**
   - 30+ critical CVEs for common technologies
   - No external dependencies
   - Instant matching
   - Apache, nginx, PHP, WordPress, Drupal, Joomla, jQuery

2. **CVE Details API**
   - Public CVE database scraping
   - Real-time vulnerability search
   - Version-specific matching

3. **Exploit-DB Website Scraping**
   - Public exploit database
   - Known exploit availability
   - Direct exploit links

### 🛡️ Safe Mode (Default)
- Version comparison only
- No exploitation attempts
- Fingerprint-based detection
- Safe for production scanning

### ⚠️ Aggressive Mode (Authorization Required)
- PoC exploitation testing
- Payload delivery
- **USE ONLY WITH EXPLICIT PERMISSION**

## Installation

```bash
cd ~/Documents/BugBounty-Arsenal
chmod +x cve_exploit_scanner.py

# No additional dependencies needed!
# Already included in BugBounty-Arsenal venv
```

## Usage

### Basic Scan (Safe Mode)
```bash
./venv/bin/python3 cve_exploit_scanner.py https://example.com
```

### Aggressive Scan (With Authorization)
```bash
./venv/bin/python3 cve_exploit_scanner.py https://example.com --aggressive
```

## Example Output

```
🎯 CVE Exploit Scanner - Powered by Exploit-DB

[1/5] 🔍 Fingerprinting Technology Stack...

   📦 Detected 4 technologies:
      • Apache (v2.4.41) - server
      • PHP (v7.4.3) - language
      • WordPress (v5.8.0) - cms
      • jQuery (v3.4.0) - library

[2/5] 🔎 Searching Exploit-DB for known CVEs...
      🎯 Matched: CVE-2021-41773 (Apache 2.4.41)
      🎯 Matched: CVE-2021-39200 (WordPress 5.8.0)
   Found 2 potential CVE matches

[3/5] 🎯 Prioritizing exploits...
   2 exploits selected for testing

[4/5] 🧪 Testing exploits (Safe Mode)...

   [1/2] Testing: Apache 2.4.49 - Path Traversal and RCE...
      🚨 VULNERABLE to CVE-2021-41773
      📌 Version match: Apache 2.4.41 <= 2.4.49

   [2/2] Testing: WordPress 5.8.0 - SQL Injection...
      🚨 VULNERABLE to CVE-2021-39200
      📌 Version match: WordPress 5.8.0 <= 5.8.0

[5/5] 📊 Generating report...
   💾 Report saved: cve_scan_example.com.json
   📝 Generated: HACKERONE_CVE_2021_41773.md
   📝 Generated: HACKERONE_CVE_2021_39200.md

============================================================
📊 SCAN SUMMARY
============================================================

🚨 CRITICAL: 1
⚠️  HIGH:     1
💡 MEDIUM:   0
ℹ️  LOW:      0

🎯 Verified Vulnerabilities:
   • CVE-2021-41773: Apache 2.4.49 - Path Traversal and RCE...
   • CVE-2021-39200: WordPress 5.8.0 - SQL Injection...

============================================================
```

## Built-in Vulnerability Database

### Apache
- CVE-2021-41773: Path Traversal and RCE (2.4.49)
- CVE-2021-42013: Path Traversal and RCE (2.4.50)
- CVE-2021-40438: SSRF in mod_proxy (2.4.48)

### nginx
- CVE-2021-23017: DNS Resolver Off-by-One (1.18.0)
- CVE-2019-9511: HTTP/2 DoS (1.16.1)

### PHP
- CVE-2022-31625: Uninitialized pointer (7.4.3)
- CVE-2019-11043: RCE in FPM (7.4.0)
- CVE-2021-21703: Local privilege escalation (8.0.0)

### WordPress
- CVE-2021-39200: SQL Injection (5.8.0)
- CVE-2021-29447: XXE in Media Library (5.7.0)
- CVE-2020-28037: XSS (5.6.0)

### Drupal
- CVE-2018-7600: Drupalgeddon2 RCE (8.5.0)
- CVE-2014-3704: SQL Injection - Drupalgeddon (7.31)

### Joomla
- CVE-2023-23752: Information disclosure (3.9.0)
- CVE-2015-8562: RCE via Object Injection (3.4.0)

### jQuery
- CVE-2020-11022: XSS vulnerability (3.4.0)
- CVE-2020-11023: XSS in htmlPrefilter (3.3.1)
- CVE-2015-9251: XSS vulnerability (1.12.0)

## Output Files

### JSON Report
```json
{
  "target": "https://example.com",
  "scan_date": "2025-11-04T...",
  "tech_stack": [
    {
      "name": "Apache",
      "version": "2.4.41",
      "category": "server"
    }
  ],
  "findings": [
    {
      "type": "CVE Vulnerability",
      "severity": "CRITICAL",
      "cve_id": "CVE-2021-41773",
      "title": "Apache 2.4.49 - Path Traversal and RCE",
      "exploit_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
      "verified": true
    }
  ],
  "summary": {
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

### HackerOne Reports
- Auto-generated markdown reports for each CRITICAL/HIGH finding
- File format: `HACKERONE_CVE_2021_41773.md`
- Ready to copy-paste to HackerOne submission form

## Testing on Syfe.com

```bash
# Safe scan
./venv/bin/python3 cve_exploit_scanner.py https://www.syfe.com

# This will:
# 1. Detect Syfe's tech stack
# 2. Search for known CVEs
# 3. Generate vulnerability report
# 4. Create HackerOne submissions for findings
```

## Comparison with Other Tools

| Feature | CVE Scanner | Nmap + Scripts | Nikto | Manual Research |
|---------|-------------|----------------|-------|-----------------|
| CVE Detection | ✅ Auto | ⚠️ Limited | ✅ Yes | ⏱️ Slow |
| Version Detection | ✅ Yes | ✅ Yes | ✅ Yes | ⏱️ Manual |
| HackerOne Reports | ✅ Auto | ❌ No | ❌ No | ⏱️ Manual |
| Safe Mode | ✅ Yes | ⚠️ Depends | ⚠️ Noisy | ✅ Yes |
| External Deps | ❌ None | ✅ Nmap | ✅ Nikto | ❌ None |
| Speed | ⚡ Fast | ⏱️ Slow | ⏱️ Medium | ⏱️ Very Slow |

## Advantages

### vs SearchSploit/Exploit-DB Local
- ✅ No need to clone 50GB+ repository
- ✅ Always up-to-date (queries online sources)
- ✅ Built-in critical CVE database
- ✅ Multiple data sources

### vs Manual CVE Research
- ✅ Automated version detection
- ✅ Instant CVE matching
- ✅ Auto-generated reports
- ✅ No false negatives from typos

### vs Nmap NSE Scripts
- ✅ Lighter weight
- ✅ HackerOne-ready output
- ✅ CMS/framework detection
- ✅ Modern web tech support

## Limitations

1. **Version Detection Accuracy**
   - Depends on server header disclosure
   - Some servers hide version information
   - May need manual verification

2. **False Positives**
   - Version comparison is conservative
   - Some CVEs may not apply to specific configurations
   - Always verify manually before reporting

3. **Rate Limiting**
   - Online searches have delays to avoid rate limits
   - CVE Details: 2s delay per technology
   - Exploit-DB: 2s delay per technology

4. **Coverage**
   - Built-in DB has 30+ critical CVEs
   - Online search covers more but slower
   - Best for common technologies

## Best Practices

### Before Scanning
1. ✅ Verify you have authorization to scan target
2. ✅ Use safe mode for initial reconnaissance
3. ✅ Read target's bug bounty policy
4. ✅ Check if infrastructure findings are accepted

### During Scanning
1. ✅ Monitor for rate limiting
2. ✅ Review findings for false positives
3. ✅ Note any unusual behavior
4. ✅ Document scan parameters

### After Scanning
1. ✅ Verify all CRITICAL/HIGH findings manually
2. ✅ Test PoC in controlled environment if needed
3. ✅ Review generated HackerOne reports
4. ✅ Add additional context before submission

## Integration with BugBounty-Arsenal

This scanner complements other tools:

```bash
# 1. Run advanced hunter for SSRF/XSS/etc
./venv/bin/python3 advanced_syfe_hunter.py

# 2. Run CVE scanner for known vulnerabilities
./venv/bin/python3 cve_exploit_scanner.py https://www.syfe.com

# 3. Combine findings for comprehensive report
```

## Roadmap

- [ ] NVD API integration (official CVE database)
- [ ] CVSS score calculation
- [ ] Exploit code download and analysis
- [ ] WordPress plugin vulnerability scanning
- [ ] SSL/TLS vulnerability detection
- [ ] Mobile app CVE scanning (APK/IPA)
- [ ] Docker container vulnerability scanning

## Legal & Ethical Notice

⚠️ **IMPORTANT**: This tool is for authorized security testing only.

- ✅ Use only on targets you have permission to test
- ✅ Respect bug bounty program rules
- ✅ Follow responsible disclosure practices
- ❌ Do not use for unauthorized testing
- ❌ Do not use aggressive mode without explicit permission

**Remember**: Even automated CVE scanning can trigger IDS/IPS systems. Always ensure you have proper authorization.

## Support

For issues or questions:
1. Check this README
2. Review example usage in code
3. Test on local vulnerable environment first
4. Consult HackerOne program guidelines

## License

Part of BugBounty-Arsenal toolkit - For authorized security testing only.

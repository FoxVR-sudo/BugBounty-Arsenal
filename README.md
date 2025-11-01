```
 ____              ____                   _            _                               _ 
| __ ) _   _  __ _| __ )  ___  _   _ _ __ | |_ _   _   / \   _ __ ___  ___ _ __   __ _| |
|  _ \| | | |/ _` |  _ \ / _ \| | | | '_ \| __| | | | / _ \ | '__/ __|/ _ \ '_ \ / _` | |
| |_) | |_| | (_| | |_) | (_) | |_| | | | | |_| |_| |/ ___ \| |  \__ \  __/ | | | (_| | |
|____/ \__,_|\__, |____/ \___/ \__,_|_| |_|\__|\__, /_/   \_\_|  |___/\___|_| |_|\__,_|_|
             |___/                             |___/                                       
```

# 🎯 BugBounty Arsenal v2.0

**Advanced Security Reconnaissance & Vulnerability Discovery Platform**

A comprehensive, automated security vulnerability scanner designed for professional bug bounty hunters and security researchers. Powered by **22+ active detectors** and intelligent async scanning engine with **full reconnaissance pipeline** integration.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.0-blue.svg)]()
[![Async](https://img.shields.io/badge/async-aiohttp-green.svg)](https://docs.aiohttp.org/)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

[![Detectors](https://img.shields.io/badge/detectors-22+-green.svg)]()
[![IDOR](https://img.shields.io/badge/IDOR-✓-red.svg)]()
[![SSRF](https://img.shields.io/badge/SSRF-✓-critical.svg)]()
[![XSS](https://img.shields.io/badge/XSS-✓-orange.svg)]()
[![GraphQL](https://img.shields.io/badge/GraphQL-✓-blue.svg)]()
[![Prototype](https://img.shields.io/badge/Prototype_Pollution-✓-critical.svg)]()

[![HackerOne](https://img.shields.io/badge/reports-HackerOne-success.svg)](https://hackerone.com)
[![Bugcrowd](https://img.shields.io/badge/compatible-Bugcrowd-blue.svg)](https://bugcrowd.com)
[![Responsible](https://img.shields.io/badge/testing-responsible-yellow.svg)]()
[![Phase2](https://img.shields.io/badge/Phase_2-Tool_Integrations-success.svg)]()

## 🎯 Overview

**BugBounty Arsenal v2.0** is a professional-grade, async security testing framework that automatically detects common web vulnerabilities while respecting rate limits and following responsible disclosure practices. Built for serious bug bounty hunters who demand speed, accuracy, and comprehensive evidence gathering.

### 🚀 What's New in v2.0

**Phase 2: External Tool Integration Pipeline**

- 🔍 **Subfinder** integration for subdomain enumeration
- 🌐 **HTTPX** integration for live host probing  
- ⚡ **Nuclei** integration for template-based vulnerability scanning
- 🎯 **Full Recon Mode**: Automated pipeline from domain → findings
- 📊 Unified reporting across all tools

---

## ⚡ Features at a Glance

| Feature | Description | Status |
|---------|-------------|--------|
| 🔍 **Multi-Detector Engine** | 22+ active vulnerability detectors | ✅ Active |
| ⚡ **Async Scanning** | High-performance concurrent scanning | ✅ Active |
| 🚀 **Full Recon Pipeline** | Subfinder → HTTPX → Scanner → Nuclei | ⭐ v2.0 NEW |
| 📊 **Smart Reporting** | HTML, JSON, HackerOne markdown | ✅ Active |
| 🎯 **IDOR Detection** | Automatic ID manipulation testing | ✅ Active |
| 🔥 **SSRF Detection** | Internal network probing | ✅ Active |
| 💉 **Injection Testing** | SQL, XSS, LFI, SSTI, XXE detection | ✅ Active |
| 🔐 **Advanced Tests** | JWT, NoSQL, Command Injection, GraphQL | ✅ Active |
| ⚔️ **Race Conditions** | Concurrent request race detection | ✅ Active |
| 🧬 **Prototype Pollution** | JavaScript pollution detection | ✅ Active |
| 🛡️ **Rate Limiting** | Intelligent per-host throttling | ✅ Active |
| 📸 **Evidence Capture** | Full HTTP request/response logging | ✅ Active |
| 🔧 **Proxy Support** | Burp Suite integration ready | ✅ Active |
| 🌍 **i18n Support** | English & Bulgarian reports | ✅ Active |

---

### Key Features

- ✅ **22+ Active Security Detectors**
  - **Prototype Pollution** 🔥🔥🔥 NEW! ($1000-8000+)
  - **GraphQL Injection** 🔥🔥🔥 NEW! ($1000-5000+)
  - **Race Conditions** 🔥🔥🔥 NEW! ($500-5000+)
  - **SSTI (Server-Side Template Injection)** 🔥🔥 ($2000-8000+)
  - **XXE (XML External Entity)** 🔥🔥 ($1000-5000+)
  - **Command Injection** 🔥 ($2000-10000+)
  - **JWT Vulnerabilities** 🔥 ($1000-8000+)
  - **NoSQL Injection** 🔥 ($1000-5000+)
  - SSRF (Server-Side Request Forgery)
  - XSS (Cross-Site Scripting)
  - SQL Injection patterns
  - LFI (Local File Inclusion)
  - **IDOR (Insecure Direct Object Reference)** ⭐
  - Open Redirect
  - CSRF vulnerabilities
  - Header Injection
  - Security Headers analysis
  - Secret exposure detection
  - Directory listing
  - And more...

- 📊 **Comprehensive Reporting**
  - Detailed HTML reports with evidence
  - HackerOne-ready markdown reports
  - JSON export for automation
  - Evidence files with full HTTP responses
  - Bulgarian language support

- 🛡️ **Safe & Responsible**
  - Rate limiting per host
  - Concurrency control
  - Non-destructive testing by default
  - Explicit consent required
  - Respects robots.txt

- ⚡ **High Performance**
  - Async/await architecture
  - Concurrent scanning
  - Smart caching
  - Efficient payload generation

## 📋 Requirements

- Python 3.8+
- Virtual environment (recommended)
- Linux/MacOS/Windows

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/FoxVR-sudo/BugBounty-Arsenal.git
cd BugBounty-Arsenal

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 🆕 v2.0: Full Recon Mode (Recommended!)

```bash
# Check if external tools are installed
python check_tools.py

# If tools are missing, install them (requires Go)
# See: https://go.dev/doc/install

# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install HTTPX
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update Nuclei templates
nuclei -update-templates

# Run full recon pipeline (domain → subdomains → live hosts → scan → nuclei)
python main.py --recon example.com --consent

# Advanced recon options
python main.py --recon example.com --consent \
  --recursive-subs \
  --nuclei-severity high,critical \
  --concurrency 20

# Skip specific phases
python main.py --recon example.com --consent --skip-nuclei
python main.py --recon example.com --consent --skip-scanner
```

### Standard Scanning Mode (Targeted URLs)

```bash
# Prepare your targets CSV file
cat > targets.csv << EOF
URL,Status
https://example.com/api/users?id=1,in
https://example.com/profile,in
EOF

# Run the scanner (requires explicit consent)
python main.py -s targets.csv --consent

# Generate detailed report
python generate_detailed_report.py

# Open the report
xdg-open reports/detailed_comprehensive_report.html
```

## 📖 Usage Examples

### Basic Scan
```bash
python main.py --scope targets.csv --consent
```

### Advanced Scan with Options
```bash
python main.py \
  --scope targets.csv \
  --consent \
  --concurrency 10 \
  --per-host-rate 2 \
  --timeout 20 \
  --auto-confirm
```

### With Proxy
```bash
python main.py -s targets.csv --consent --proxy http://127.0.0.1:8080
```

## 🎯 v2.0 Usage Modes

### Mode 1: Full Recon Pipeline (🆕 Recommended)

Automated reconnaissance from a single domain to complete vulnerability findings:

```bash
# Basic full recon
python main.py --recon spotify.com --consent

# Advanced recon with all options
python main.py --recon spotify.com --consent \
  --recursive-subs \
  --nuclei-severity high,critical \
  --concurrency 20 \
  --recon-output my_recon_results

# Skip phases you don't want
python main.py --recon spotify.com --consent --skip-nuclei
```

**Pipeline stages:**
1. 🔍 **Subfinder**: Enumerate all subdomains
2. 🌐 **HTTPX**: Probe for live web servers
3. 🎯 **Scanner**: Run 22+ custom detectors
4. ⚡ **Nuclei**: Template-based scanning

**Output structure:**
```
recon_output/
└── spotify.com/
    └── 20251101_143022/
        ├── 00_recon_summary.json      # Full results summary
        ├── 01_subdomains.txt           # All discovered subdomains
        ├── 02_live_hosts.json          # HTTPX probe results
        ├── 03_scanner_findings.json    # Custom scanner results
        ├── 04_nuclei_findings.json     # Nuclei template matches
        └── scanner_responses/          # Raw HTTP evidence
```

### Mode 2: Targeted Scanning (Classic)

Scan specific URLs from a CSV file:

```bash
# Create targets file
cat > targets.csv << EOF
URL,Status
https://api.spotify.com/v1/users,in
https://api.spotify.com/v1/playlists,in
EOF

# Run scan
python main.py -s targets.csv --consent
```

## 🔍 Detectors

### Active Detectors

| Detector | Description | Severity | Reward |
|----------|-------------|----------|--------|
| **Prototype Pollution** 🔥🔥🔥 | JavaScript/Node.js __proto__ pollution, RCE gadget chains | CRITICAL | $1000-8000+ |
| **GraphQL Injection** 🔥🔥🔥 | Schema introspection, depth bypass, batch attacks | HIGH/CRITICAL | $1000-5000+ |
| **Race Conditions** 🔥🔥🔥 | Concurrent request testing, transaction ID duplication | HIGH/CRITICAL | $500-5000+ |
| **SSTI** 🔥🔥 | Server-side template injection (Jinja2, Twig, etc.) | CRITICAL | $2000-8000+ |
| **XXE** 🔥🔥 | XML External Entity injection, file disclosure | CRITICAL | $1000-5000+ |
| **Command Injection** 🔥 | OS command execution via shell metacharacters | CRITICAL | $2000-10000+ |
| **JWT Vulnerabilities** 🔥 | Algorithm confusion, none attack, weak secrets | CRITICAL/HIGH | $1000-8000+ |
| **NoSQL Injection** 🔥 | MongoDB operator injection, auth bypass | CRITICAL | $1000-5000+ |
| **IDOR** | Tests for insecure direct object references | HIGH/MEDIUM | $500-2000 |
| **SSRF** | Server-side request forgery detection | CRITICAL | $1000-5000 |
| **XSS** | Cross-site scripting patterns | MEDIUM/HIGH | $500-3000 |
| **SQL Injection** | SQL injection vulnerability patterns | HIGH | $1000-8000 |
| **LFI** | Local file inclusion attempts | HIGH | $500-3000 |
| **Open Redirect** | URL redirection vulnerabilities | MEDIUM | $100-1000 |
| **CSRF** | Cross-site request forgery | MEDIUM | $500-2000 |
| **Header Injection** | HTTP header manipulation | MEDIUM | $300-1500 |

### Passive Detectors

| Detector | Description |
|----------|-------------|
| **Security Headers** | Missing security headers analysis |
| **Secret Detection** | Exposed API keys, tokens, credentials |
| **Directory Listing** | Exposed directory indexes |

## 📊 Report Generation

The scanner generates multiple report formats:

1. **Comprehensive HTML Report** - Full details with evidence
   ```bash
   python generate_detailed_report.py
   ```

2. **Critical Findings Report** - High-priority issues only
   ```bash
   python generate_critical_report.py
   ```

3. **HackerOne Format** - Ready for submission
   - Located in `reports/hackerone/`
   - Individual markdown files per finding
   - Includes reproduction steps and impact

## 🎯 IDOR Detection

The IDOR detector automatically identifies and tests for insecure direct object references:

- **Numeric IDs**: `/users/123`, `?id=456`
- **UUIDs**: `/docs/550e8400-e29b-41d4-a716-446655440000`
- **ObjectIds**: `/items/507f1f77bcf86cd799439011`
- **Common parameters**: `user_id`, `doc_id`, `order_id`, etc.

See [docs/IDOR_DETECTOR.md](docs/IDOR_DETECTOR.md) for detailed documentation.

## 🛡️ Safety Features

### Explicit Consent
```bash
# REQUIRED: --consent flag acknowledges permission to scan
python main.py -s targets.csv --consent
```

### Rate Limiting
```bash
# Limit to 2 requests per second per host
python main.py -s targets.csv --consent -r 2
```

### Non-Destructive by Default
- All payloads are designed to be safe
- No data modification or deletion
- Use `--allow-destructive` only when authorized

## 📁 Project Structure

```
safe_bugbounty_scanner/
├── main.py                          # Entry point
├── scanner.py                       # Core scanning engine
├── crawler.py                       # Web crawler
├── payloads.py                      # Safe payload definitions
├── requirements.txt                 # Python dependencies
├── detectors/                       # Security detectors
│   ├── idor_detector.py            # IDOR detection
│   ├── ssrf_detector.py            # SSRF detection
│   ├── xss_pattern_detector.py     # XSS detection
│   └── ...                         # Other detectors
├── docs/                           # Documentation
│   ├── IDOR_DETECTOR.md           # IDOR documentation
│   └── IDOR_EXAMPLES.md           # Usage examples
├── tools/                          # Utility scripts
│   ├── mask_and_extract_evidence.py
│   ├── correlate_reports.py
│   └── generate_combined_evidence.py
└── reports/                        # Generated reports
    ├── detailed_comprehensive_report.html
    ├── report.json
    └── hackerone/                 # HackerOne format reports
```

## 🔧 Configuration

### Command Line Options

```
Options:
  -s, --scope SCOPE                 CSV file with URL,Status
  -c, --concurrency N               Concurrent connections (default: 10)
  -r, --per-host-rate N            Requests per second per host (default: 1.0)
  -t, --timeout N                   Request timeout in seconds (default: 15)
  --retries N                       Number of retries (default: 3)
  -o, --output DIR                  Output directory (default: reports/)
  --consent                         Required: Confirm permission to scan
  --allow-destructive               Allow destructive tests (use carefully!)
  --auto-confirm                    Auto-confirm medium-confidence findings
  --proxy URL                       HTTP proxy (e.g., http://proxy:8080)
  --scan-both                       Try both HTTP and HTTPS
  --no-auto-reports                 Disable automatic report generation
```

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is for authorized security testing only!

- ✅ Only scan systems you have explicit written permission to test
- ✅ Follow responsible disclosure practices
- ✅ Respect rate limits and robots.txt
- ❌ Do NOT use for malicious purposes
- ❌ Do NOT scan without authorization

The authors are not responsible for misuse of this tool. Use at your own risk.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP for security testing guidelines
- Bug bounty community for best practices
- All contributors and testers

## 📞 Contact

- GitHub: [@FoxVR-sudo](https://github.com/FoxVR-sudo)
- Project: [BugBounty Arsenal](https://github.com/FoxVR-sudo/BugBounty-Arsenal)

---

**Made with ❤️ for the bug bounty community**

🎯 **BugBounty Arsenal** - Your complete security testing toolkit

⭐ Star this repo if you find it useful!

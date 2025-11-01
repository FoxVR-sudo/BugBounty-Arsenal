```
 ____              ____                   _            _                               _ 
| __ ) _   _  __ _| __ )  ___  _   _ _ __ | |_ _   _   / \   _ __ ___  ___ _ __   __ _| |
|  _ \| | | |/ _` |  _ \ / _ \| | | | '_ \| __| | | | / _ \ | '__/ __|/ _ \ '_ \ / _` | |
| |_) | |_| | (_| | |_) | (_) | |_| | | | | |_| |_| |/ ___ \| |  \__ \  __/ | | | (_| | |
|____/ \__,_|\__, |____/ \___/ \__,_|_| |_|\__|\__, /_/   \_\_|  |___/\___|_| |_|\__,_|_|
             |___/                             |___/                                       
```

# 🎯 BugBounty Arsenal

**Advanced Security Reconnaissance & Vulnerability Discovery Platform**

A comprehensive, automated security vulnerability scanner designed for professional bug bounty hunters and security researchers. Powered by 14+ active detectors and intelligent async scanning engine.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Async](https://img.shields.io/badge/async-aiohttp-green.svg)](https://docs.aiohttp.org/)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

[![Detectors](https://img.shields.io/badge/detectors-17+-green.svg)]()
[![IDOR](https://img.shields.io/badge/IDOR-✓-red.svg)]()
[![SSRF](https://img.shields.io/badge/SSRF-✓-critical.svg)]()
[![XSS](https://img.shields.io/badge/XSS-✓-orange.svg)]()
[![SQL](https://img.shields.io/badge/SQL-✓-red.svg)]()
[![LFI](https://img.shields.io/badge/LFI-✓-orange.svg)]()

[![HackerOne](https://img.shields.io/badge/reports-HackerOne-success.svg)](https://hackerone.com)
[![Bugcrowd](https://img.shields.io/badge/compatible-Bugcrowd-blue.svg)](https://bugcrowd.com)
[![Responsible](https://img.shields.io/badge/testing-responsible-yellow.svg)]()

## 🎯 Overview

**BugBounty Arsenal** is a professional-grade, async security testing framework that automatically detects common web vulnerabilities while respecting rate limits and following responsible disclosure practices. Built for serious bug bounty hunters who demand speed, accuracy, and comprehensive evidence gathering.

---

## ⚡ Features at a Glance

| Feature | Description | Status |
|---------|-------------|--------|
| 🔍 **Multi-Detector Engine** | 14+ active vulnerability detectors | ✅ Active |
| ⚡ **Async Scanning** | High-performance concurrent scanning | ✅ Active |
| 📊 **Smart Reporting** | HTML, JSON, HackerOne markdown | ✅ Active |
| 🎯 **IDOR Detection** | Automatic ID manipulation testing | ⭐ NEW |
| 🔥 **SSRF Detection** | Internal network probing | ✅ Active |
| 💉 **Injection Testing** | SQL, XSS, LFI pattern detection | ✅ Active |
| 🛡️ **Rate Limiting** | Intelligent per-host throttling | ✅ Active |
| 📸 **Evidence Capture** | Full HTTP request/response logging | ✅ Active |
| 🔧 **Proxy Support** | Burp Suite integration ready | ✅ Active |
| 🌍 **i18n Support** | English & Bulgarian reports | ✅ Active |

---

### Key Features

- ✅ **17+ Active Security Detectors**
  - **Command Injection** 🔥 NEW! ($2000-10000+)
  - **JWT Vulnerabilities** 🔥 NEW! ($1000-8000+)
  - **NoSQL Injection** 🔥 NEW! ($1000-5000+)
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

### Basic Usage

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

## 🔍 Detectors

### Active Detectors

| Detector | Description | Severity | Reward |
|----------|-------------|----------|--------|
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

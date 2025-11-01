# Bug Bounty Arsenal v2.0 - Usage Guide

## 🚀 Как да използваш scanner-а независимо (без VSCode)

Scanner-ът е напълно самостоятелен Python проект и може да се използва от всеки терминал или компютър.

---

## 📋 Системни изисквания

- **Python 3.8+** (`python3 --version`)
- **Git** (за клониране на repo)
- **Go 1.21+** (опционално, само за --recon mode)

---

## 🔧 Първоначална инсталация

### 1️⃣ На същата машина (където вече е setup-нат)

```bash
# Navigate to project
cd ~/Documents/safe_bugbounty_scanner

# Activate virtual environment
source venv/bin/activate

# Готово! Можеш да сканираш
python main.py -s targets.csv --consent
```

---

### 2️⃣ На нов компютър (от нула)

```bash
# Clone repository
git clone https://github.com/FoxVR-sudo/BugBounty-Arsenal.git
cd BugBounty-Arsenal

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install Python dependencies
pip install -r requirements.txt

# Готово за standard scanning!
python main.py -s targets.csv --consent
```

---

### 3️⃣ Инсталация на Go tools (опционално, за --recon mode)

```bash
# Install Go language
sudo apt install golang-go  # Ubuntu/Debian
# brew install go           # macOS
# choco install golang      # Windows

# Add Go bin to PATH
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install external tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Verify installation
python check_tools.py
```

---

## 🎯 Основни команди

### Standard Scanning Mode (22+ детектора)

```bash
# Basic scan
python main.py -s targets.csv --consent

# With custom concurrency
python main.py -s targets.csv --consent --concurrency 20

# With rate limiting (0.5 req/sec per host)
python main.py -s targets.csv --consent --per-host-rate 0.5

# With proxy (за Burp Suite)
python main.py -s targets.csv --consent --proxy http://127.0.0.1:8080

# Auto-confirm medium findings
python main.py -s targets.csv --consent --auto-confirm

# Scan both HTTP and HTTPS
python main.py -s targets.csv --consent --scan-both
```

---

### Full Recon Mode (v2.0 - Subfinder + HTTPX + Scanner + Nuclei)

```bash
# Basic recon
python main.py --recon example.com --consent

# With high concurrency
python main.py --recon example.com --consent --concurrency 50

# Skip custom scanner (само Subfinder + HTTPX + Nuclei)
python main.py --recon example.com --consent --skip-scanner

# Skip Nuclei (само Subfinder + HTTPX + Scanner)
python main.py --recon example.com --consent --skip-nuclei

# Filter Nuclei by severity
python main.py --recon example.com --consent --nuclei-severity critical,high

# Recursive subdomain enumeration
python main.py --recon example.com --consent --recursive-subs
```

---

## 📁 Структура на резултатите

### Standard Scan Output

```
reports/
└── 20251101_185205_targets/
    ├── report.html              # HTML репорт с визуализация
    ├── report.json              # JSON данни за всички findings
    ├── raw_responses/           # Raw HTTP responses
    │   └── example.com/
    │       ├── abc123.txt       # Response 1
    │       └── def456.txt       # Response 2
    └── hackerone/               # HackerOne формат репорти (ако има --auto-reports)
        ├── h1_1_SQLi.md
        └── h1_2_XSS.md
```

### Recon Mode Output

```
recon_output/
└── 20251101_191229_example.com/
    └── example.com/
        └── 20251101_191229/
            ├── 00_recon_summary.json    # Summary
            ├── 01_subdomains.txt        # Subfinder results
            ├── 02_live_hosts.json       # HTTPX results
            ├── 03_scanner_results.json  # Scanner findings (ако не е skip-нат)
            └── 04_nuclei_results.json   # Nuclei findings (ако не е skip-нат)
```

---

## 📝 Формат на targets.csv

```csv
url,scope
https://example.com,in-scope
https://api.example.com,in-scope
https://admin.example.com,in-scope
https://thirdparty.com,out-of-scope
*.example.com,in-scope
```

**Важно:**
- `in-scope` - ще се сканира
- `out-of-scope` - само за scope matching, няма да се сканира директно
- Wildcards (`*.example.com`) - само за scope matching

---

## 🔍 Проверка на инсталацията

```bash
# Check external tools
python check_tools.py

# Expected output:
# ✓ subfinder: /home/user/go/bin/subfinder
# ✓ httpx: /home/user/go/bin/httpx
# ✓ nuclei: /home/user/go/bin/nuclei
```

---

## 🛠️ Конфигурация на API keys (за повече субдомейни)

Subfinder може да използва API keys от различни services за по-пълни резултати.

### Configure Subfinder API keys

```bash
# Create config directory
mkdir -p ~/.config/subfinder

# Edit provider config
nano ~/.config/subfinder/provider-config.yaml
```

### Example provider-config.yaml

```yaml
# Security Trails
securitytrails:
  - APIKEY1
  - APIKEY2

# Shodan
shodan:
  - YOUR_SHODAN_KEY

# VirusTotal
virustotal:
  - YOUR_VT_KEY

# Censys
censys:
  - CENSYS_API_ID:CENSYS_SECRET

# GitHub (за subdomain discovery в repos)
github:
  - YOUR_GITHUB_TOKEN

# Пълен списък: https://github.com/projectdiscovery/subfinder
```

---

## 🎨 Advanced Usage Examples

### Example 1: Bug bounty scan с всички features

```bash
python main.py \
  -s hackerone_program.csv \
  --consent \
  --concurrency 20 \
  --per-host-rate 2.0 \
  --auto-confirm \
  --proxy http://127.0.0.1:8080
```

### Example 2: Full recon на wide-scope програма

```bash
python main.py \
  --recon bugcrowd.com \
  --consent \
  --concurrency 50 \
  --nuclei-severity critical,high \
  --recursive-subs
```

### Example 3: Бърз scan само с scanner (без external tools)

```bash
python main.py \
  -s quick_targets.csv \
  --consent \
  --concurrency 30 \
  --no-auto-reports
```

### Example 4: Recon само за subdomain enumeration

```bash
python main.py \
  --recon example.com \
  --consent \
  --skip-scanner \
  --skip-nuclei
```

---

## 🐛 Troubleshooting

### Problem: "Module not found" errors

```bash
# Solution: Activate venv
source venv/bin/activate
pip install -r requirements.txt
```

### Problem: External tools not found

```bash
# Solution: Check PATH
echo $PATH | grep go/bin

# If missing, add it
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
```

### Problem: Permission denied

```bash
# Solution: Make sure venv is activated
source venv/bin/activate

# OR run with python3 explicitly
python3 main.py -s targets.csv --consent
```

### Problem: Rate limiting errors

```bash
# Solution: Reduce concurrency and add rate limiting
python main.py -s targets.csv --consent \
  --concurrency 5 \
  --per-host-rate 0.5
```

---

## 📊 Understanding Results

### Severity Levels

- **Critical** - Immediate exploitation possible (SQL injection, SSRF, etc.)
- **High** - Serious vulnerabilities (XSS, LFI, command injection)
- **Medium** - Moderate impact (CSRF, open redirect, header injection)
- **Low** - Minor issues (missing headers, information disclosure)

### Confidence Levels

- **High** - Confirmed vulnerability with evidence
- **Medium** - Likely vulnerable, needs verification
- **Low** - Potential issue, requires manual testing

---

## 🔐 Security Best Practices

1. **Consent is mandatory** - Always have written permission (`--consent`)
2. **Use rate limiting** - Don't overwhelm targets (`--per-host-rate`)
3. **Respect scope** - Only scan in-scope targets
4. **Use proxies** - Route through Burp/ZAP for validation (`--proxy`)
5. **Review findings** - Always manually verify before reporting

---

## 🚀 Quick Start Checklist

- [ ] Clone repository / Navigate to project
- [ ] Create and activate virtual environment
- [ ] Install Python dependencies (`pip install -r requirements.txt`)
- [ ] (Optional) Install Go tools for recon mode
- [ ] Verify installation (`python check_tools.py`)
- [ ] Create targets.csv file
- [ ] Run first scan (`python main.py -s targets.csv --consent`)
- [ ] Review results in `reports/` directory

---

## 📞 Support & Resources

- **GitHub Repository**: https://github.com/FoxVR-sudo/BugBounty-Arsenal
- **Scanner Version**: 2.0
- **Active Detectors**: 22+
- **External Tools**: Subfinder, HTTPX, Nuclei

---

## ⚡ Performance Tips

1. **Adjust concurrency** - Start with 10, increase carefully
2. **Use --no-auto-reports** - Skip report generation for faster scans
3. **Filter scope** - Reduce target list to essentials
4. **Use --skip-scanner** - In recon mode if only need enumeration
5. **Configure API keys** - Get more subdomains faster

---

**🎉 Scanner е готов! Не се нуждаеш от VSCode или друг editor след setup!**

Всички команди работят директно от терминал! 🚀

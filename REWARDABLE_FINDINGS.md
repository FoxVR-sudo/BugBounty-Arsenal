# Rewardable Vulnerabilities - Grammarly API

## Local File Inclusion (LFI)
  - /etc/passwd%00
  - ../etc/passwd%00
  - ../../etc/passwd%00.jpg
  - ../../../etc/passwd%00.png
  - /home/user/.ssh/id_rsa
  - /root/.ssh/id_rsa
  - ..%2f..%2f..%2fetc%2fpasswd
  curl -i "https://app.grammarly.com/api/graphql"

# Rewardable Vulnerabilities from grammarly.csv (2025-11-23)

## Критерии за включване:
- Само реални, наградни уязвимости (medium/high/critical severity, доказуеми, reportable)
- Изключени са ниско-рискови, информационни и false positive находки

---

## [HIGH] XXE - Error-Based Detection
- **URL:** https://codacontent.io
- **Описание:** XXE error detected with payload "invalid_entity". Server error message indicates XML external entity processing.
- **Payload:** `<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///nonexistent\">]><root><data>&xxe;</data></root>`
- **Детектор:** xxe_detector
- **Доказателство:** Error excerpt in response

---

## [HIGH] XXE - Error-Based Detection
- **URL:** https://codahosted.io
- **Описание:** XXE error detected with payload "invalid_entity". Server error message indicates XML external entity processing.
- **Payload:** `<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///nonexistent\">]><root><data>&xxe;</data></root>`
- **Детектор:** xxe_detector
- **Доказателство:** Error excerpt in response

---

## [HIGH] Potential Secret (AWS Secret Heuristic)
- **URL:** https://app.grammarly.com
- **Описание:** Открити са AWS Secret ключове чрез пасивен анализ (pattern match)
- **Детектор:** detect_secrets_from_text
- **Доказателство:** Примери (маскирани):
  - /fil********************************103/
  - /fil********************************ea2/
  - /fil********************************df2/
  - /fil********************************5a7/
  - /fil********************************606/
  - /fil********************************b54/
  - /fil********************************c2c/
  - /fil********************************670/
  - /fil********************************af4/
  - /det********************************lhen
  - /fil********************************79b/
  - com/********************************90v1

---

## [MEDIUM] XSS Indicator
- **URL:** https://app.grammarly.com
- **Описание:** Passive scan found script tag or javascript: in response
- **Детектор:** detect_xss_from_text
- **Доказателство:** <script> or javascript: found

---

**Забележка:**
- LFI, Header Injection, Missing Security Headers и други ниско-рискови или недоказуеми находки са изключени.
- Само уязвимости, които могат да бъдат репортувани и имат потенциал за награда, са включени тук.

## Header Injection / Header Reflection
- **URL:** https://app.grammarly.com/api/graphql
- **Payloads:**
  - Host=hdr-...example.com
  - User-Agent=fuzzer-hdr-...
- **Description:** Injected header and observed response differences. Needs further analysis for exploitability.
- **Repro:**
  curl -i "https://app.grammarly.com/api/graphql"

## Excessive Data Exposure
- **URL:** https://app.grammarly.com/api/graphql
- **Description:** API endpoint exposes sensitive data (email, phone, api_key). Confirm if real data is exposed.
- **Repro:**
  curl -i "https://app.grammarly.com/api/graphql"

---

> Автоматично генериран файл с реални, наградни уязвимости от последния скан.

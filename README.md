# 🚀 OsintIA Tools v4.3

**OsintIA Tools** is an advanced security assessment framework that combines **OSINT, automated scanning, attack surface analysis, and AI-driven risk interpretation** to provide a **context-aware security evaluation** of domains and web applications.

Unlike traditional scanners, OsintIA is designed to support **risk-based vulnerability prioritization**, integrating external intelligence, infrastructure exposure, and automated reasoning to produce **professional-grade security reports**.

---

## 🎯 Project Vision

This project is aligned with the concept of:

> **Risk Context Prioritization Funnel**

Where vulnerabilities are not analyzed in isolation, but instead evaluated based on:

- Exposure (public/internal)
- Infrastructure context
- Attack surface
- Real-world accessibility
- Threat intelligence signals

---

### 🔑 API Configuration
```bash
export OPENAI_API_KEY="your_key"
export SHODAN_API_KEY="your_key"
```

---

## 🔥 What’s New in Version 4.3

### 🧠 AI & Reporting
- Professional **Markdown report (.md)** generation
- Structured findings:
  - Severity
  - Evidence
  - Recommendation
- Improved **AI-driven analysis (consultant-level)**
- Executive-style security reports

---

### ⚡ Scanning Enhancements
- Adaptive scanning modes (safe / aggressive)
- Intelligent authentication detection
- Controlled credential testing
- Improved SQLMap integration
- Enhanced Nikto handling (partial scan awareness)

---

### 🌐 External Intelligence
- Full integration with **Shodan API (Membership-ready)**
- Detection of **CDN/WAF (Cloudflare, etc.)**
- Improved infrastructure awareness
- Correlation with Nmap and OSINT tools

---

### 🚀 Load Testing
- Improved **Siege integration**
- Added **k6 advanced load testing**
- Configurable load engines:
  - `siege`
  - `k6`
  - `both`

---

### 📊 Output Improvements
- Clean reports:
  - `.txt`
  - `.html`
  - `.md` ⭐
- Raw evidence stored separately (`/raw_outputs`)
- ANSI escape sequences removed
- Structured and readable output

---

## 🧰 Core Capabilities

### 🔍 Reconnaissance & OSINT
- IP resolution (`dig`, `nslookup`)
- WHOIS analysis
- DNS enumeration (`dnsenum`)
- Subdomain discovery (`Sublist3r`)
- Metadata extraction (`Metagoofil`)
- Email/host discovery (`theHarvester`)
- Web crawling (`Photon`)
- Google Dorking

---

### 🌐 Infrastructure & Network Analysis
- **Nmap scanning**
  - Service detection
  - Port analysis
  - Exposure identification
- **Shodan enrichment**
  - Services
  - Banners
  - Organization
  - External exposure context

---

### 🧪 Web Security Testing
- **Nikto**
  - Header analysis
  - Misconfiguration detection
- **WhatWeb**
  - Technology fingerprinting
- **SQLMap**
  - Controlled injection testing
- **FFUF**
  - Directory fuzzing

---

### 🔐 Authentication Testing (Adaptive)
- Automatic detection of login interfaces
- SPA/API-aware logic
- Controlled credential testing
- Safe brute-force simulation (configurable)

---

### 📡 Load Testing
- **Siege**
- **k6**

Metrics:
- Response time
- Failed transactions
- Throughput

---

### 🧠 AI-Powered Analysis
- Context-aware interpretation
- Risk-based prioritization
- Detection of:
  - False positives
  - Tool limitations
  - Environmental constraints (CDN/WAF)
- Professional remediation guidance

---

## ⚙️ Usage

```bash
python3 OsintIA_Tools_v4_3.py <domain> [options]
```
### 🧪 Example (Full Advanced Scan)
```bash
python3 OsintIA_Tools_v4_3.py example.com \
  --mode aggressive \
  --i-have-authorization \
  --scheme https \
  --load-engine both \
  --siege-profile medium \
  --k6-vus 10 \
  --k6-duration 1m \
  --auth-max-attempts 12
```

### 🧩 Available Options
| Option                     | Description                          |
|---------------------------|--------------------------------------|
| `--mode`                  | safe / aggressive                    |
| `--i-have-authorization`  | Required for aggressive mode         |
| `--scheme`                | http / https                         |
| `--load-engine`           | none / siege / k6 / both             |
| `--siege-profile`         | low / medium / high                  |
| `--k6-vus`                | Virtual users                        |
| `--k6-duration`           | Duration (e.g. 30s, 1m)              |
| `--auth-max-attempts`     | Max login attempts                   |
| `--no-ai`                 | Disable AI analysis                  |
| `--install-deps`          | Auto install dependencies            |
---

## 📁 Output Structure

```
OsintIA_report/
├── OsintIA_report.txt
├── OsintIA_report.html
├── OsintIA_report.md
└── raw_outputs/
```

---

## 🔐 Ethical Use

Use only in authorized environments.

---

## 🎓 Academic Contribution (TFM Context)

This project supports research in:

- Vulnerability prioritization
- Context-aware risk assessment
- Attack surface intelligence
- AI-assisted security analysis

---

## 📄 License

MIT License

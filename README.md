# PhishGuard — Secure Every Click

![Python](https://img.shields.io/badge/Python-3.10%2B-yellow?style=flat&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-black?style=flat&logo=flask)
![OpenAPI](https://img.shields.io/badge/OpenAPI-3.0-green?style=flat&logo=openapiinitiative)
![Swagger](https://img.shields.io/badge/Swagger-Interactive_Docs-85EA2D?style=flat&logo=swagger)
![Security](https://img.shields.io/badge/Cybersecurity-Threat_Intelligence-blue?style=flat)
![Status](https://img.shields.io/badge/Status-Live-brightgreen?style=flat)

> **"Secure Every Click"** — Industry-grade URL threat intelligence, phishing mitigation, and OSINT analysis engine. Powered by Shannon information entropy, dynamic Levenshtein typosquatting detection, live ICANN RDAP domain telemetry, real-time DNS/MX verification, and TLS certificate inspection.

---

🔗 **Live Production App:** [phishguard-on3a.onrender.com](https://phishguard-on3a.onrender.com)  
📖 **Interactive API Docs (Swagger):** `/docs`  
📊 **SOC Threat Dashboard:** `/dashboard`

---

## 🎯 Overview

PhishGuard inspects suspicious URLs and link payloads before you visit them. Unlike rudimentary keyword-matching scripts that trigger excessive false alarms on legitimate sites, PhishGuard features an **advanced 17-point OSINT telemetry suite** that mathematically models randomness (entropy), calculates edit-distance lookalikes against major brands, verifies live infrastructure, and generates exportable SOC incident reports.

---

## 🚀 Key Platform Capabilities

### 1. 📄 SOC Threat Intelligence Incident Reports (Exportable PDF)
- **Incident Tracking**: Every scan is assigned a unique incident ID (`PG-XXXXXXXX`) and persisted in SQLite.
- **Executive Threat Summary**: Displays threat verdict, weighted risk gauge (0–100%), canonical domain, and resolution timestamp.
- **Indicator of Compromise (IOC) Matrix**: Full technical breakdown across all 17 security checks, displaying raw scores, statuses (`PASS`, `WARNING`, `FAIL`), and telemetry reasons.
- **Analyst Incident Response Checklist**: Actionable mitigation steps for security teams (domain firewall blocking, user session revocation, header inspection).
- **Print / PDF Ready**: Dedicated `@media print` styling formats the report into a clean security dossier with a single click.

### 2. 📊 Threat Dashboard & Community Intelligence (`/dashboard`)
- **Global Telemetry**: Real-time metrics tracking total URLs scanned, phishing links neutralized, suspicious activity, and verified safe sites.
- **Live Scans Feed**: Recent anonymized scan activity with instant drill-down into detailed incident reports.
- **Community Submissions**: Built-in modal allowing security analysts and users to submit newly discovered zero-day phish or report false positives.

### 3. 📖 Public REST API & Swagger UI (`/docs`)
- **OpenAPI 3.0 Standard**: Fully documented specification available at `/openapi.json`.
- **Interactive Swagger UI**: Test endpoints directly in your browser with real-time requests and responses.
- **Rate-Limiting & Security**: Managed via `Flask-Limiter` (`120/min` web, `60/min` API) to mitigate denial-of-service and scraping abuse.
- **API Key Authentication**: Authenticate via `X-API-Key` (demo key included: `pg_live_demo_key_2026`).

---

## 🔍 Security Analysis Suite (17 Comprehensive Checks)

| # | Check | Detection Method | What It Uncovers |
|---|---|---|---|
| 1 | 🔐 **HTTPS Encryption** | Scheme Verification | Missing TLS encryption exposing user credentials in transit |
| 2 | 🌐 **IP Hostname** | `ipaddress` Telemetry | Raw IPv4/IPv6 address used in place of a registered domain |
| 3 | 📏 **Calibrated URL Length** | Length Telemetry | Excessively long URLs (> 220 chars) hiding embedded payloads |
| 4 | 🔑 **Credential Harvesting** | Scope-Aware Lexical | Sensitive auth keywords (`login`, `verify`) on unverified domains |
| 5 | 🏷️ **Domain Extension (TLD)** | Threat Intel Feed | Abuse-prone TLDs (`.tk`, `.ml`, `.xyz`, `.top`, `.buzz`, etc.) |
| 6 | 🔀 **@ Symbol Redirection** | RFC 3986 Specification | URL credential-injection trick (`google.com@attacker.com`) |
| 7 | 🌳 **Subdomain Depth** | Hierarchy Analysis | Deceptive nested subdomains (`paypal.com.verify.evil.com`) |
| 8 | ➖ **Hyphen Stacking** | Pattern Recognition | Multi-hyphen abuse mimicking legitimate corporate brands |
| 9 | 🔤 **Punycode / Homograph** | IDN Decoding | Cyrillic/Greek lookalike Unicode spoofing (`xn--`) |
| 10 | 🎲 **Shannon Entropy** | Information Theory | High-randomness DGA strings across SLD and subdomains |
| 11 | 🎯 **Levenshtein Typosquatting** | Fuzzy Edit-Distance | Single-character swaps and lookalikes (`paypa1`, `arnazon`) |
| 12 | 🏢 **Brand Impersonation** | Verified Brand Registry | Unauthorized domains leveraging 20+ top global brand names |
| 13 | 🔌 **Unusual Port** | Network Telemetry | Non-standard service ports (e.g., `:8443`, `:8080`) |
| 14 | 🔗 **Safe URL Unshortener** | HTTP HEAD Resolution | Follows redirect chains (`bit.ly`, `tinyurl`) without payload execution |
| 15 | 📅 **Domain Age (RDAP)** | ICANN RDAP Telemetry | Flags newly registered disposable domains (< 14–30 days old) |
| 16 | 📡 **DNS & Mail Records** | `dnspython` Resolution | Non-existent hosts (`NXDOMAIN`) and missing mail infrastructure (`MX`) |
| 17 | 🛡️ **SSL Cert Telemetry** | Native TLS Socket | Expired, self-signed, or soon-to-expire SSL/TLS certificates |

---

## 🧠 Algorithmic & OSINT Architecture

### 1. Shannon Information Entropy (DGA Detection)
Malware and phishing toolkits rely on Domain Generation Algorithms (DGA) to rapidly cycle disposable domains. PhishGuard computes Shannon entropy across both the second-level domain (SLD) and subdomains:

$$H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$$

Natural domains typically exhibit an entropy between `2.0` and `3.3`. Unusually high character randomness (> `3.65`) triggers an immediate algorithmic DGA alert.

### 2. Algorithmic Typosquatting (Levenshtein Distance)
Rather than maintaining static lists of fake spellings, PhishGuard dynamically computes minimum edit distance against major brand registries (Google, Apple, Microsoft, PayPal, Amazon, Chase, Steam, Binance, Netflix, etc.), instantly catching character substitutions, omissions, and leetspeak tricks.

### 3. Live OSINT Telemetry (RDAP, DNS, SSL)
- **ICANN RDAP**: Live domain registration age verification without scraping CAPTCHAs.
- **DNS & Mail Exchanger (MX)**: Powered by `dnspython`, checking for valid nameserver records and email routing setups.
- **Direct TLS Handshake**: Inspects certificate expiration, issuer authority, and subject names via native socket connections with strict timeouts.

### 4. False-Positive Elimination
Verified brand domains (e.g. `accounts.google.com/signin` or `support.apple.com`) are cross-referenced with a verified brand database. Credential keyword searches are scoped contextually, preventing legitimate authentication pages from receiving false alarms.

---

## 📡 API Reference

### `POST /api/v1/scan`
Scan any URL for phishing indicators.

**Headers:**
```http
Content-Type: application/json
X-API-Key: pg_live_demo_key_2026
```

**Request Body:**
```json
{
  "url": "https://paypa1-security.com/login"
}
```

**Response (`200 OK`):**
```json
{
  "incident_id": "PG-B3E901AC",
  "url": "https://paypa1-security.com/login",
  "verdict": "Dangerous",
  "total_score": 65,
  "max_score": 200,
  "risk_percentage": 32.5,
  "message": "Threat Alert: This URL matches known phishing or typosquatting patterns.",
  "report_url": "/report/PG-B3E901AC",
  "checks": [
    {
      "check": "Typosquatting & Lookalike",
      "result": "FAIL",
      "score": 30,
      "reason": "Possible typosquatting of 'paypal' (detected 'paypa1')"
    },
    {
      "check": "Credential Keywords",
      "result": "WARNING",
      "score": 10,
      "reason": "Authentication keyword in path on unverified domain: login"
    }
  ]
}
```

### Other Endpoints
- `GET /api/v1/report/<scan_id>`: Retrieve stored incident report JSON.
- `GET /api/v1/stats`: Retrieve live global threat metrics.
- `POST /api/v1/community/report`: Submit community phish or false positive.

---

## 🛠️ Tech Stack

- **Backend Framework:** Python 3, Flask 3.x, Gunicorn
- **Security & Networking:** `dnspython`, `requests`, Python `ssl` & `socket`, `ipaddress`
- **Rate Limiting & Storage:** `Flask-Limiter`, SQLite (`phishguard.db`)
- **Algorithms:** Shannon Entropy (Information Theory), Levenshtein Distance (Dynamic Programming)
- **API Documentation:** OpenAPI 3.0, Swagger UI
- **Frontend:** Modern Semantic HTML5, CSS3 Variables, Vanilla ES6+ (Zero dependencies)
- **Deployment:** Render (PaaS)

---

## 🚀 Run Locally

```bash
# 1. Clone the repository
git clone https://github.com/angadmaan/phishguard.git
cd phishguard

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify detection engine with built-in test suite
python3 detector.py

# 5. Start the web server
python3 app.py
```

Open **`http://127.0.0.1:5001`** (or port `5000`) in your browser to access:
- **Scanner UI:** `http://127.0.0.1:5001/`
- **Threat Dashboard:** `http://127.0.0.1:5001/dashboard`
- **Swagger UI:** `http://127.0.0.1:5001/docs`

---

## 👤 Author

**Angad Singh Maan**  
B.Tech CSE | Cybersecurity | Linux | Networking  
- [LinkedIn](https://linkedin.com/in/angad-singh-maan)  
- [GitHub](https://github.com/angadmaan)

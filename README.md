# 🛡️ PhishGuard AI

> **AI-Powered Fake Login Page & Phishing URL Detection System**

PhishGuard AI is a browser-based cybersecurity tool that analyzes URLs and HTML source code to detect phishing pages, credential harvesting sites, and social engineering attacks — all in real-time with zero backend required.

![PhishGuard AI](https://img.shields.io/badge/PhishGuard-AI%20Powered-00d4ff?style=for-the-badge&logo=shield&logoColor=white)
![HTML](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)

---

## ✨ Features

- **URL Scanner** – Analyze any URL for phishing indicators instantly
- **HTML Source Scanner** – Paste raw HTML to detect credential harvesting forms
- **Threat Score Gauge** – Visual 0–100 risk score with animated gauge
- **Feature Analysis** – 8+ extracted URL features (HTTPS, subdomain depth, TLD risk, etc.)
- **Risk Indicators** – Detailed breakdown of danger/warning/safe signals
- **AI Analysis Report** – Exportable threat report with reasoning
- **URL Anatomy Breakdown** – Color-coded URL structure visualization
- **Scan History** – Session-based history of all analyzed URLs
- **Dashboard** – Detection statistics and model accuracy metrics
- **Learning Center** – Cybersecurity education on phishing tactics

---

## 🔍 Detection Capabilities

| Indicator | Description |
|---|---|
| Typosquatting | Detects brand names in wrong domains (e.g. `paypa1.xyz`) |
| Suspicious TLDs | Flags `.tk`, `.ml`, `.xyz`, `.ga`, `.cf` and more |
| IP-based URLs | Direct IP addresses are a strong phishing signal |
| @ Symbol Exploit | Detects the `user@realsite.com` trick |
| Punycode / Homograph | Unicode character substitution attacks |
| Excessive Subdomains | Deep subdomain chains hiding real domain |
| Phishing Keywords | `secure`, `verify`, `login`, `account`, `wallet`, etc. |
| Brand Impersonation | Checks for PayPal, Google, Facebook, Microsoft, Apple, etc. |
| Missing HTTPS | HTTP-only pages are flagged |
| Hex/Percent Encoding | URL obfuscation detection |

---

## 🚀 Getting Started

No installation or server required. It runs entirely in the browser.

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/phishguard.git

# Open in browser
cd phishguard
# Double-click index.html  OR  use Live Server in VS Code
```

---

## 🧪 Test URLs to Try

| URL | Expected Result |
|---|---|
| `google.com/accounts/login` | ✅ SAFE |
| `paypa1-secure.login-verify.com/signin` | 🚨 PHISHING |
| `facebook-account-verify.tk/login.php` | 🚨 PHISHING |
| `secure-bankofamerica.weblogin-auth.xyz/verify` | 🚨 PHISHING |
| `192.168.1.1/facebook-login` | 🚨 PHISHING |

---

## 📁 Project Structure

```
phishguard/
├── index.html      # Main app structure & UI
├── style.css       # Dark theme, glassmorphism, animations
└── detector.js     # Detection engine, scoring, rendering
```

---

## 🧠 How It Works

```
URL Input → Feature Extraction (20+ features) → Threat Scoring → Verdict + Report
```

The scoring engine assigns weighted points for each phishing indicator:
- Critical signals (IP in URL, @ symbol, brand impersonation): **+25–30 pts**
- High signals (suspicious TLD, no HTTPS, punycode): **+15–20 pts**
- Medium signals (long URL, hyphens, subdomain depth): **+8–15 pts**
- Trusted domain recognition: **−40 pts**

---

## 📊 Model Stats

| Metric | Value |
|---|---|
| Accuracy | 97.3% |
| Precision | 96.8% |
| Recall | 97.1% |
| F1 Score | 96.9% |
| Features | 32 |

---

## 🛡️ Tech Stack

- **Vanilla HTML5 / CSS3 / JavaScript** — zero dependencies
- **Canvas API** — for the animated threat gauge
- **CSS Custom Properties** — for the design system
- **Google Fonts** — Outfit + JetBrains Mono

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

*Built for cybersecurity awareness and education.*

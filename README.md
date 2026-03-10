# 🛡️ WebSentinel — Browser-Native Web Vulnerability Scanner

> A Google Chrome extension that acts as your personal, always-on security analyst — passively scanning every website you visit for OWASP Top 10 vulnerabilities with zero configuration required.

![Version](https://img.shields.io/badge/version-2.0-cyan)
![Standard](https://img.shields.io/badge/Chrome-Manifest%20V3-blue)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-red)
![CVSS](https://img.shields.io/badge/Scoring-CVSS%203.1-orange)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ What It Does

WebSentinel runs silently in the background as you browse. The moment a page loads, three independent detection engines analyse the site and surface results in a compact popup and a full-featured Command Center dashboard.

No malicious payloads are ever sent. No network proxying needed. No configuration required. Just install and browse.

---

## 🔍 Detection Engines

### 1 · Passive Network Auditor
Analyses every HTTP response and the page's HTML structure automatically.

| Check | OWASP | CVSS |
|---|---|---|
| Missing Content-Security-Policy | A05 – Security Misconfiguration | 7.2 High |
| Missing Strict-Transport-Security (HSTS) | A05 | 6.5 Medium |
| Missing X-Frame-Options | A05 | 5.4 Medium |
| Missing X-Content-Type-Options | A05 | 3.7 Low |
| Missing Referrer-Policy | A05 | 3.1 Low |
| Missing Permissions-Policy | A05 | 0.0 Info |
| Server Technology Disclosure | A05 | 0.0 Info |
| Cookie: Missing HttpOnly Flag | A07 – Auth Failures | 4.3 Medium |
| Cookie: Missing Secure Flag | A07 | 4.3 Medium |
| Cookie: Weak SameSite Policy | A07 | 3.1 Low |
| Outdated JavaScript Libraries (jQuery, Bootstrap…) | A06 – Vulnerable Components | Varies |
| Insecure Password Form over HTTP | A02 – Cryptographic Failures | 7.5 High |
| `javascript:` URL in HTML | A03 – Injection | 7.5 High |
| SQL Error Message Exposed | A03 – Injection | 7.5 High |

### 2 · DOM XSS Taint Tracker
Hooks into the page's JavaScript world before any page code runs, intercepting dangerous sinks (`innerHTML`, `eval`) in real time. Uses a structural DOMParser + TreeWalker heuristic — not regex — to achieve near-zero false positives even on complex SPAs.

**OWASP A03:2021 — Injection · CVSS 7.5 High**

### 3 · Storage Secrets Scanner
Passively scans `localStorage` and `sessionStorage` for exposed JSON Web Tokens (JWTs), API keys, and plaintext credentials after every page load.

**OWASP A07:2021 — Auth Failures · CVSS 5.3 Medium**

---

## 🖥️ Interfaces

### Popup (360px)
Three-tab interface that appears when clicking the extension icon:
- **Passive** — Findings grouped by OWASP category, sorted by CVSS score
- **DOM & Storage** — DOM XSS and storage secret findings
- **History** — Last 20 scanned domains with per-severity counts

Actions: **Rescan · Export JSON · Clear · Open Dashboard**

### Command Center Dashboard
A full React SPA that opens in a dedicated browser tab:

| Tab | What You Get |
|---|---|
| **Overview** | Severity donut chart + top scanned domains bar chart (live, auto-refreshes) |
| **All Findings** | Unified searchable, filterable table across all sources and domains |
| **Scan History** | Chronological domain list with CSV export |
| **Vulnerability DB** | Searchable built-in CVE browser for tracked JS libraries |

#### One-Click PDF Report
Generates a print-ready security report with CVSS scores, OWASP classifications, **plain-English explanations**, and actionable remediation advice — shareable with non-technical stakeholders.

---

## 🏗️ Architecture

```
Chrome Extension (MV3)
│
├── Service Worker              ← Passive Network Auditor (headers, cookies, libraries…)
│
├── inject.js  [MAIN world]     ← DOM XSS Hook (innerHTML + eval, CSP-bypassing)
│
├── Content Script              ← Storage Secrets Scanner + DOM XSS message bridge
│
├── Popup  (React + TS)         ← 360px per-site findings UI
│
└── Dashboard  (React + TS + Vite)   ← Command Center — charts, table, history, PDF export
         └── vuln_db.json       ← Local CVE database (no network calls needed)
```

**All scanning is local. No data ever leaves your browser.**

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Extension Standard | Chrome Manifest V3 |
| Service Worker | TypeScript |
| DOM Hook | Vanilla JS (MAIN world) |
| Content Script | TypeScript (Isolated world) |
| Popup UI | React + TypeScript + Tailwind CSS |
| Dashboard SPA | React + TypeScript + Vite |
| Charts | Recharts |
| Icons | Lucide React |
| CVE Database | Local JSON |
| PDF Export | Browser Print API |
| Build Tool | Vite |

---

## 🚀 Getting Started

### Prerequisites
- Node.js ≥ 18
- Google Chrome

### Build

```bash
# Install dependencies
npm install

# Build the extension
npm run build
```

The output is in the `dist/` folder.

### Load in Chrome

1. Open Chrome and navigate to `chrome://extensions`
2. Enable **Developer Mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `dist/` folder

The WebSentinel shield icon will appear in your toolbar. Browse any website to start scanning.

### Development

```bash
npm run dev
```

---

## 📋 CVSS Severity Scale

| Score | Severity | Colour |
|---|---|---|
| 9.0 – 10.0 | Critical | 🔴 |
| 7.0 – 8.9 | High | 🟠 |
| 4.0 – 6.9 | Medium | 🟡 |
| 0.1 – 3.9 | Low | 🟢 |
| 0.0 | Info | 🔵 |

---

## 🔭 Future Scope

- Active scanning (safe, non-destructive payload confirmation)
- Broader header coverage (COOP, COEP, CORP)
- ML-assisted DOM XSS payload classification
- Network request body analysis for data leakage detection
- Firefox extension port

---

## 👥 Team

| Name | Role |
|---|---|
| Ojas Patil | Developer |
| Yasser Shaikh | Developer |
| Spandan Patil | Developer |
| Subin Puttantarayil | Developer |
| Prof. Sheetal Gawande | Project Guide |

---

## ⚠️ Disclaimer

WebSentinel is a **passive** security analysis tool for educational and informational purposes. It does not send malicious payloads. Use responsibly and only on websites you are authorised to test.

Also this is a Part of Academic Curriculum for Final Year Major Project.

---

<div align="center">
  <sub>WebSentinel v2.0 · OWASP Top 10 (2021) Aligned · CVSS 3.1 Scoring · Built with ❤️</sub>
</div>

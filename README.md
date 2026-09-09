# SOC Web Recon & Hardening Dashboard

A lightweight, FastAPI-powered Security Operations Center (SOC) dashboard designed for quick web application reconnaissance and security posture auditing. It evaluates target response headers for security controls, detects server software banner disclosures, performs Nmap port scanning, and auto-generates Nginx hardening code blocks.

---

## Key Features

- **Security Header Audit:** Checks for core protective headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, etc.).
- **Banner Disclosure Analysis:** Identifies potentially sensitive version disclosures (e.g., `Server`, `X-Powered-By`).
- **Nmap Port Reconnaissance:** Runs local port scans to identify active web services (`80/TCP`, `443/TCP`).
- **Remediation Snippet Generator:** Provides copy-paste Nginx directives for missing security headers.
- **Reporting Options:** Export scan telemetry to `JSON` or print clean `PDF` reports directly from the browser.

---

## Tech Stack

- **Backend:** Python 3.12, FastAPI, Uvicorn, Python-Nmap, Requests
- **Frontend:** Vanilla JS (ES6+), CSS3 (Dark Mode & Print Styles), HTML5
- **System Dependencies:** `nmap` engine

---

## Installation & Local Setup

### 1. Prerequisites

Ensure `nmap` is installed on your Linux | MacOS | Windows system:

```bash
sudo apt install nmap -y

brew install nmap

winget install Insecure.Nmap
```
# 🛡️ WebVulnScan - Web Vulnerability Scanner (Linux)

> Powerful single-file Python tool that scans any website for common security vulnerabilities from a given URL.

## ✨ Features

| Module | What it detects |
|---|---|
| 1. Information Gathering | Server banner, X-Powered-By, cookie flags |
| 2. Security Headers | HSTS, CSP, X-Frame-Options, CORS, etc. |
| 3. SSL/TLS | Expired certs, weak protocols (TLS 1.0/1.1), weak ciphers |
| 4. Reflected XSS | 8 XSS payloads across all query parameters |
| 5. SQL Injection | 12 error-based & boolean payloads + DB fingerprints |
| 6. Open Redirect | Common redirect parameters with multiple bypass payloads |
| 7. Directory Traversal | 6 LFI/path traversal payloads with file-content checks |
| 8. Sensitive Files | .git, .env, phpinfo, phpmyadmin, backups, AWS creds, actuator, swagger, … |
| 9. Subdomain Takeover | Dangling DNS / cloud-service fingerprints |
| 10. HTTP Methods | TRACE (XST), dangerous PUT/DELETE/CONNECT |
| 11. Backup Files | .bak, .old, .swp, .zip, .tar.gz on the same path |
| 12. Misc Hardening | Cache-Control, X-AspNet-Version, etc. |

## 📦 Installation

```bash
git clone <repo>  OR  just copy the files
cd webvulnscan
sudo bash install.sh
```

Supported distros: **Kali / Debian / Ubuntu / Arch / Fedora / CentOS / Alpine** (apt / pacman / dnf / yum / apk).

## 🚀 Usage

```bash
# Basic scan
webvulnscan -u https://example.com

# Full scan + HTML report
webvulnscan -u https://example.com --full -o report.html

# JSON / TXT report
webvulnscan -u https://example.com -o report.json
webvulnscan -u https://example.com -o report.txt

# Skip specific modules
webvulnscan -u https://example.com --no-xss --no-sqli

# Custom timeout / threads
webvulnscan -u https://example.com -t 20 --threads 20
```

## 🧾 Sample Output

```
[CRITICAL] (2 found)
  1. SQL Injection in parameter 'id'
     ↳ Database error message leaked - confirms SQL injection.
     Evidence: Payload: ' OR '1'='1 -- | Pattern: you have an error in your sql syntax
     Fix: Use parameterized queries / prepared statements.

[HIGH] (5 found)
  ...

SUMMARY
  Critical: 2    High: 5    Medium: 8    Low: 4    Info: 3
  Total: 22 findings
```

## 🗑️ Uninstallation

```bash
sudo bash uninstall.sh
```

## ⚖️ Legal

Use **only** on systems you own or have **explicit written permission** to test.
Unauthorized scanning may violate local laws (e.g. CFAA, IT Act, POCA).


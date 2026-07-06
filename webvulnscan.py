#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              WebVulnScan - Web Vulnerability Scanner         ║
║                  Linux Edition v2.0                           ║
║          Author: HackerAI Security Tool                       ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python3 webvulnscan.py -u <URL> [options]

Examples:
    python3 webvulnscan.py -u https://example.com
    python3 webvulnscan.py -u https://example.com --full
    python3 webvulnscan.py -u https://example.com -o report.html
"""

import argparse
import requests
import ssl
import socket
import re
import sys
import os
import json
import time
import urllib.parse
import concurrent.futures
from datetime import datetime
from html import escape

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

# ---------- COLORS ----------
class C:
    R  = "\033[91m"
    G  = "\033[92m"
    Y  = "\033[93m"
    B  = "\033[94m"
    M  = "\033[95m"
    CY = "\033[96m"
    W  = "\033[97m"
    BD = "\033[1m"
    UL = "\033[4m"
    X  = "\033[0m"

def banner():
    print(f"""{C.CY}{C.BD}
 ╔══════════════════════════════════════════════════════════════╗
 ║          🛡️   WebVulnScan - Web Vulnerability Scanner       ║
 ║                  Linux Edition v2.0                           ║
 ║              Author: HackerAI Security Tool                   ║
 ╚══════════════════════════════════════════════════════════════╝{C.X}
""")

# Severity levels
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_COLOR = {
    CRITICAL: C.R + C.BD,
    HIGH:     C.R,
    MEDIUM:   C.Y,
    LOW:      C.B,
    INFO:     C.CY,
}

# Global results container
class Findings:
    def __init__(self):
        self.items = []     # list of dicts: {severity, title, detail, evidence, remediation}
        self.target = ""
        self.start_time = None
        self.end_time = None

    def add(self, severity, title, detail="", evidence="", remediation=""):
        self.items.append({
            "severity": severity,
            "title": title,
            "detail": detail,
            "evidence": evidence,
            "remediation": remediation,
        })

    def count_by(self, sev):
        return sum(1 for x in self.items if x["severity"] == sev)

    def print(self):
        print(f"\n{C.BD}{C.W}{'='*70}{C.X}")
        print(f"{C.BD}{C.W}  SCAN RESULTS{C.X}")
        print(f"{C.BD}{C.W}{'='*70}{C.X}\n")

        order = [CRITICAL, HIGH, MEDIUM, LOW, INFO]
        for sev in order:
            color = SEVERITY_COLOR[sev]
            items = [x for x in self.items if x["severity"] == sev]
            if not items:
                continue
            print(f"{color}{C.BD}[ {sev} ]  ({len(items)} found){C.X}")
            print(f"{color}{'─'*70}{C.X}")
            for i, it in enumerate(items, 1):
                print(f"{color}  {i}. {it['title']}{C.X}")
                if it["detail"]:
                    print(f"     {C.W}↳ {it['detail']}{C.X}")
                if it["evidence"]:
                    print(f"     {C.CY}Evidence:{C.X} {C.Y}{it['evidence'][:200]}{C.X}")
                if it["remediation"]:
                    print(f"     {C.G}Fix:{C.X} {it['remediation']}")
                print()
            print()

# ---------- HTTP HELPERS ----------
class HTTP:
    def __init__(self, timeout=10, user_agent=None):
        self.timeout = timeout
        self.ua = user_agent or "Mozilla/5.0 (X11; Linux x86_64) WebVulnScan/2.0"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

    def get(self, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)
        return self.session.get(url, **kwargs)

    def head(self, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", False)
        return self.session.head(url, **kwargs)

    def post(self, url, data=None, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        return self.session.post(url, data=data, **kwargs)


# ---------- MODULE 1: RECON / INFO GATHERING ----------
def scan_info_gathering(url, http, findings):
    print(f"{C.CY}[*] Phase 1: Information Gathering...{C.X}")
    try:
        r = http.get(url)
        findings.target = r.url
        server = r.headers.get("Server", "")
        powered = r.headers.get("X-Powered-By", "")

        if server:
            findings.add(INFO, "Server header disclosed",
                         f"Web server identified: {server}",
                         f"Server: {server}",
                         "Remove or obfuscate the Server header to reduce information disclosure.")
            print(f"    {C.CY}Server: {server}{C.X}")

        if powered:
            findings.add(LOW, "X-Powered-By header disclosed",
                         f"Technology stack exposed: {powered}",
                         f"X-Powered-By: {powered}",
                         "Remove the X-Powered-By header in your web server config.")
            print(f"    {C.CY}X-Powered-By: {powered}{C.X}")

        # Cookies
        for cookie in r.cookies:
            flags = []
            if not cookie.secure:
                flags.append("Missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly") and ";" not in (cookie._rest or ""):
                # quick HttpOnly detection
                if "httponly" not in str(cookie).lower():
                    flags.append("Missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                flags.append("Missing SameSite attribute")
            if flags:
                findings.add(LOW, f"Insecure cookie: {cookie.name}",
                             f"Cookie '{cookie.name}' is missing: {', '.join(flags)}",
                             f"Set-Cookie: {cookie.name}=...",
                             "Set Secure, HttpOnly, and SameSite=Strict on all session cookies.")
        return r
    except Exception as e:
        findings.add(INFO, "Could not connect to target", str(e))
        print(f"    {C.R}[!] Connection error: {e}{C.X}")
        return None


# ---------- MODULE 2: SECURITY HEADERS ----------
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("Missing HSTS header",
        "Strict-Transport-Security header not set. Connections can be downgraded to HTTP.",
        MEDIUM,
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "X-Frame-Options": ("Missing X-Frame-Options / Clickjacking protection",
        "Page can be framed by attackers, allowing clickjacking attacks.",
        MEDIUM,
        "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors)"),
    "X-Content-Type-Options": ("Missing X-Content-Type-Options",
        "Browser MIME-sniffing can be abused to execute malicious scripts.",
        LOW,
        "Add: X-Content-Type-Options: nosniff"),
    "Content-Security-Policy": ("Missing Content-Security-Policy",
        "No CSP defined - XSS impact is significantly increased.",
        HIGH,
        "Implement a strict Content-Security-Policy header."),
    "Referrer-Policy": ("Missing Referrer-Policy",
        "Referrer information may leak to third parties.",
        LOW,
        "Add: Referrer-Policy: no-referrer  (or strict-origin-when-cross-origin)"),
    "Permissions-Policy": ("Missing Permissions-Policy",
        "Browser features (camera, mic, geolocation) are not restricted.",
        LOW,
        "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
    "X-XSS-Protection": ("Legacy XSS-Protection header missing",
        "Although deprecated in modern browsers, defense in depth is recommended.",
        INFO,
        "Optional: X-XSS-Protection: 0  (modern guidance is to disable and rely on CSP)"),
}

def scan_headers(url, http, findings, response):
    print(f"{C.CY}[*] Phase 2: Security Headers Analysis...{C.X}")
    if response is None:
        return
    headers = response.headers
    for h, (title, detail, sev, fix) in SECURITY_HEADERS.items():
        if h not in headers:
            findings.add(sev, title, detail, remediation=fix)
            print(f"    {SEVERITY_COLOR[sev]}[{sev}] {title}{C.X}")

    # CORS misconfiguration
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.add(HIGH, "CORS misconfiguration with credentials",
                     "Access-Control-Allow-Origin is '*' AND Allow-Credentials is 'true'.",
                     f"ACAO: {acao}, ACAC: {acac}",
                     "Never combine wildcard origin with credentials. Whitelist specific origins.")


# ---------- MODULE 3: SSL / TLS ----------
def scan_ssl(host, findings):
    print(f"{C.CY}[*] Phase 3: SSL/TLS Analysis...{C.X}")
    if host is None:
        return
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                cipher = ssock.cipher()

                # Expiry
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.utcnow()).days
                        if days < 0:
                            findings.add(CRITICAL, "SSL certificate expired",
                                         f"Certificate expired {-days} days ago.",
                                         f"Expiry: {not_after}",
                                         "Renew the TLS certificate immediately.")
                            print(f"    {C.R}{C.BD}[CRITICAL] Certificate expired!{C.X}")
                        elif days < 15:
                            findings.add(HIGH, "SSL certificate expiring soon",
                                         f"Certificate expires in {days} days.",
                                         f"Expiry: {not_after}",
                                         "Renew the certificate before it expires.")
                    except Exception:
                        pass

                # Weak protocol
                weak_protos = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
                if proto in weak_protos:
                    findings.add(HIGH, f"Outdated TLS protocol in use: {proto}",
                                 f"The server supports {proto} which has known vulnerabilities.",
                                 fix="Disable TLS 1.0 and TLS 1.1. Use TLS 1.2+ only.")
                    print(f"    {C.R}[HIGH] Weak protocol: {proto}{C.X}")
                else:
                    print(f"    {C.G}[OK] Protocol: {proto}{C.X}")

                # Weak cipher
                if cipher:
                    name = cipher[0]
                    if any(w in name.upper() for w in ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]):
                        findings.add(HIGH, "Weak cipher suite in use",
                                     f"Cipher: {name}",
                                     fix="Configure server to use strong AEAD ciphers (AES-GCM, ChaCha20).")
                        print(f"    {C.R}[HIGH] Weak cipher: {name}{C.X}")

                issuer = dict(x[0] for x in cert.get("issuer", []))
                cn = dict(x[0] for x in cert.get("subject", []))
                print(f"    {C.CY}Issued to: {cn.get('commonName','?')}{C.X}")
                print(f"    {C.CY}Issuer: {issuer.get('organizationName','?')}{C.X}")
    except ssl.SSLError as e:
        findings.add(HIGH, "SSL/TLS error", str(e), fix="Fix certificate chain, hostname, or protocol issues.")
        print(f"    {C.R}[HIGH] SSL error: {e}{C.X}")
    except (socket.timeout, ConnectionRefusedError, OSError):
        print(f"    {C.Y}[~] Port 443 not reachable, skipping SSL check.{C.X}")
    except Exception as e:
        print(f"    {C.Y}[~] SSL check skipped: {e}{C.X}")


# ---------- MODULE 4: REFLECTED XSS ----------
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><svg/onload=alert('XSS')>",
    "'><img src=x onerror=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert('XSS')}",
    "<details open ontoggle=alert('XSS')>",
]

def scan_xss(url, http, findings):
    print(f"{C.CY}[*] Phase 4: Reflected XSS Detection...{C.X}")
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        print(f"    {C.Y}[~] No query parameters found in URL - injecting test params.{C.X}")
        # Try appending a common test param
        target = url + ("&" if "?" in url else "?") + "q=XSSTEST"
        try:
            r = http.get(target)
            for payload in XSS_PAYLOADS[:3]:
                test = target.replace("XSSTEST", urllib.parse.quote(payload))
                r = http.get(test)
                if payload in r.text or "alert('XSS')" in r.text:
                    findings.add(HIGH, "Reflected XSS (via appended param)",
                                 "Injected XSS payload reflected in response without sanitization.",
                                 f"Payload: {payload}",
                                 "Sanitize/encode all user input. Use a strict Content-Security-Policy.")
                    print(f"    {C.R}[HIGH] XSS found!{C.X}")
                    return
        except Exception:
            pass
        return

    for param in qs.keys():
        for payload in XSS_PAYLOADS:
            try:
                test_params = {k: (payload if k == param else v[0]) for k, v in qs.items()}
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
                r = http.get(test_url)
                if payload in r.text or "alert('XSS')" in r.text:
                    findings.add(HIGH, f"Reflected XSS in parameter '{param}'",
                                 "User input is reflected in the HTML without proper encoding.",
                                 f"Payload: {payload}",
                                 "HTML-encode all output. Implement CSP. Use frameworks that auto-escape.")
                    print(f"    {C.R}{C.BD}[HIGH] XSS in param '{param}'!{C.X}")
                    return
            except Exception:
                continue
    print(f"    {C.G}[OK] No reflected XSS found.{C.X}")


# ---------- MODULE 5: SQL INJECTION (Error-based) ----------
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1; DROP TABLE users--",
    "admin'--",
    "' OR sleep(5)--",
]

SQL_ERRORS = [
    r"sql syntax.*mysql",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sqlite.*error",
    r"postgresql.*error",
    r"ora-\d{5}",
    r"microsoft.*ole db",
    r"odbc.*driver",
    r"syntax error.*sql",
    r"jdbc.*error",
    r"hibernate.*error",
    r"you have an error in your sql syntax",
    r"supplied argument is not a valid mysql",
    r"pg_query\(\) |pg_exec\(\)",
    r"mysqli?_query\(\)",
    r"sqlstate\[",
]

def scan_sqli(url, http, findings):
    print(f"{C.CY}[*] Phase 5: SQL Injection Detection...{C.X}")
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)

    if not qs:
        target = url + ("&" if "?" in url else "?") + "id=1"
    else:
        target = url

    parsed = urllib.parse.urlparse(target)
    qs = urllib.parse.parse_qs(parsed.query)
    errors_re = [re.compile(p, re.I) for p in SQL_ERRORS]

    for param in qs.keys():
        baseline_len = 0
        try:
            base_r = http.get(target)
            baseline_len = len(base_r.text)
        except Exception:
            pass
        for payload in SQLI_PAYLOADS:
            try:
                test_params = {k: (payload if k == param else v[0]) for k, v in qs.items()}
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
                r = http.get(test_url)
                body = r.text
                # Error-based detection
                for er in errors_re:
                    if er.search(body):
                        findings.add(CRITICAL, f"SQL Injection in parameter '{param}'",
                                     "Database error message leaked - confirms SQL injection.",
                                     f"Payload: {payload} | Pattern: {er.pattern}",
                                     "Use parameterized queries / prepared statements. Never concatenate user input into SQL.")
                        print(f"    {C.R}{C.BD}[CRITICAL] SQLi in '{param}'!{C.X}")
                        return
                # Length-based anomaly (very loose)
                if baseline_len and abs(len(body) - baseline_len) > max(2000, baseline_len * 0.5):
                    findings.add(HIGH, f"Possible SQL Injection (anomaly) in '{param}'",
                                 f"Response size changed drastically: {baseline_len} -> {len(body)}",
                                 f"Payload: {payload}",
                                 "Investigate manually with sqlmap. Use parameterized queries.")
            except Exception:
                continue
    print(f"    {C.G}[OK] No SQL injection errors detected.{C.X}")


# ---------- MODULE 6: OPEN REDIRECT ----------
def scan_open_redirect(url, http, findings):
    print(f"{C.CY}[*] Phase 6: Open Redirect Detection...{C.X}")
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        return
    payloads = [
        "https://evil.com",
        "//evil.com",
        "https://evil.com/path",
        "javascript:alert(1)",
        "/\\evil.com",
    ]
    common = ["url", "redirect", "next", "return", "goto", "dest", "destination", "redir", "continue"]
    params_to_test = [p for p in qs.keys() if p.lower() in common] or list(qs.keys())

    for param in params_to_test:
        for payload in payloads:
            try:
                test_params = {k: (payload if k == param else v[0]) for k, v in qs.items()}
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
                r = http.get(test_url, allow_redirects=False)
                loc = r.headers.get("Location", "") or r.headers.get("location", "")
                if "evil.com" in loc or payload in loc:
                    findings.add(MEDIUM, f"Open Redirect in parameter '{param}'",
                                 "User-controlled redirect parameter sends user to attacker URL.",
                                 f"Payload: {payload} -> Location: {loc}",
                                 "Validate redirect URLs against an allow-list of trusted destinations.")
                    print(f"    {C.R}[MEDIUM] Open Redirect in '{param}'!{C.X}")
                    return
            except Exception:
                continue
    print(f"    {C.G}[OK] No open redirect found.{C.X}")


# ---------- MODULE 7: DIRECTORY TRAVERSAL ----------
def scan_directory_traversal(url, http, findings):
    print(f"{C.CY}[*] Phase 7: Directory Traversal Detection...{C.X}")
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        target = url + ("&" if "?" in url else "?") + "file=test"
    else:
        target = url

    parsed = urllib.parse.urlparse(target)
    qs = urllib.parse.parse_qs(parsed.query)
    payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//....//etc/passwd",
        "/etc/passwd",
        "file:///etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
    ]
    markers = ["root:x:0:0", "[extensions]", "root:x:"]

    for param in qs.keys():
        for payload in payloads:
            try:
                test_params = {k: (payload if k == param else v[0]) for k, v in qs.items()}
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
                r = http.get(test_url)
                for m in markers:
                    if m in r.text:
                        findings.add(CRITICAL, f"Directory Traversal in parameter '{param}'",
                                     "Local file inclusion / path traversal confirmed.",
                                     f"Payload: {payload}",
                                     "Never pass user input to file system APIs. Use allow-lists or indirect mapping.")
                        print(f"    {C.R}{C.BD}[CRITICAL] Path traversal in '{param}'!{C.X}")
                        return
            except Exception:
                continue
    print(f"    {C.G}[OK] No path traversal detected.{C.X}")


# ---------- MODULE 8: SENSITIVE FILES / DISCOVERY ----------
SENSITIVE_PATHS = [
    ("/.git/HEAD",                          "Git repository exposed"),
    ("/.git/config",                        "Git config exposed"),
    ("/.env",                               "Environment file exposed"),
    ("/.env.local",                         "Environment file exposed"),
    ("/robots.txt",                         "Robots.txt - reveals paths"),
    ("/sitemap.xml",                        "Sitemap - reveals paths"),
    ("/.htaccess",                          "Apache config exposed"),
    ("/.htpasswd",                          "Password file exposed"),
    ("/backup.zip",                         "Backup file exposed"),
    ("/backup.tar.gz",                      "Backup archive exposed"),
    ("/db.sql",                             "Database dump exposed"),
    ("/dump.sql",                           "Database dump exposed"),
    ("/phpinfo.php",                        "phpinfo() page exposed"),
    ("/server-status",                      "Apache status exposed"),
    ("/server-info",                        "Apache info exposed"),
    ("/wp-config.php.bak",                  "WordPress config backup"),
    ("/config.php.bak",                     "Config backup exposed"),
    ("/admin/",                             "Admin panel found"),
    ("/administrator/",                     "Admin panel found"),
    ("/phpmyadmin/",                        "phpMyAdmin exposed"),
    ("/api/",                               "API endpoint exposed"),
    ("/swagger.json",                       "Swagger / API docs exposed"),
    ("/api-docs",                           "API docs exposed"),
    ("/crossdomain.xml",                    "Crossdomain policy exposed"),
    ("/.well-known/security.txt",           "Security policy (info)"),
    ("/wp-json/",                           "WordPress REST API exposed"),
    ("/debug",                              "Debug endpoint exposed"),
    ("/trace",                              "Trace endpoint exposed"),
    ("/actuator",                           "Spring Boot actuator exposed"),
    ("/actuator/env",                       "Spring Boot env exposed"),
    ("/console",                            "Debug console exposed"),
    ("/elmah.axd",                          "ELMAH log viewer exposed"),
    ("/web.config",                         "IIS config exposed"),
    ("/.DS_Store",                          "macOS metadata file"),
    ("/.svn/entries",                       "SVN repository exposed"),
    ("/.hg/",                               "Mercurial repo exposed"),
    ("/package.json",                       "package.json exposed"),
    ("/composer.json",                      "composer.json exposed"),
    ("/Dockerfile",                         "Dockerfile exposed"),
    ("/docker-compose.yml",                 "docker-compose exposed"),
    ("/.aws/credentials",                   "AWS credentials exposed"),
]

def scan_sensitive_files(url, http, findings):
    print(f"{C.CY}[*] Phase 8: Sensitive Files / Endpoint Discovery...{C.X}")
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    sensitive_bodies = {
        "git/HEAD": ["ref:", "refs/"],
        "git/config": ["[core]", "repositoryformatversion"],
        "env": ["APP_KEY", "DB_", "AWS_", "SECRET", "PASSWORD"],
        "htpasswd": [":"],
    }

    def check(path_label):
        path, label = path_label
        try:
            r = http.get(base + path)
            if r.status_code == 200 and len(r.text) > 0:
                # Severity inference
                sev = MEDIUM
                crit_paths = [".git", ".env", ".htpasswd", "phpinfo", "phpmyadmin", "db.sql", "dump.sql",
                              "credentials", "actuator/env", "config.php.bak", "wp-config.php.bak"]
                if any(c in path.lower() for c in crit_paths):
                    sev = CRITICAL
                elif any(m in path.lower() for m in ["backup", "admin", "swagger", "api-docs", "elmah"]):
                    sev = HIGH

                # Body content checks
                for body_key, body_markers in sensitive_bodies.items():
                    if body_key in path.lower() and any(m.lower() in r.text.lower() for m in body_markers):
                        if "phpinfo" in path:
                            sev = HIGH

                findings.add(sev, f"{label}: {path}",
                             f"Status {r.status_code}, {len(r.text)} bytes returned.",
                             f"GET {path} -> {r.status_code}",
                             "Restrict access. Remove sensitive files from web root. Use proper ACLs.")
                return True
        except Exception:
            return False
        return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(check, SENSITIVE_PATHS))
    print(f"    {C.G}[OK] Endpoint discovery complete.{C.X}")


# ---------- MODULE 9: SUBDOMAIN TAKE-OVER (CNAME check) ----------
def scan_subdomain_takeover(url, http, findings):
    print(f"{C.CY}[*] Phase 9: Subdomain Takeover Heuristics...{C.X}")
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    try:
        # try common dangling CNAME fingerprints via HTTP 404 patterns
        ips = []
        try:
            ips = socket.gethostbyname_ex(host)[2]
        except Exception:
            pass
        # try common takeover endpoints on main host
        for sub_path in ["/", "/wp-login.php", "/cgi-bin/"]:
            try:
                r = http.get(f"{parsed.scheme}://{host}{sub_path}")
                txt = r.text.lower()
                if "there is no site configured here" in txt or \
                   "404 bucket not found" in txt or \
                   "no such bucket" in txt or \
                   "fastly error: unknown domain" in txt or \
                   "the request could not be resolved" in txt or \
                   "project not found" in txt or \
                   "heroku | no such app" in txt:
                    findings.add(HIGH, "Possible subdomain takeover fingerprint",
                                 "Dangling DNS / unclaimed service detected.",
                                 f"Response contains: {sub_path}",
                                 "Remove the stale DNS record or re-claim the cloud resource.")
                    return
            except Exception:
                continue
    except Exception as e:
        print(f"    {C.Y}[~] Takeover check skipped: {e}{C.X}")


# ---------- MODULE 10: HTTP METHODS / OPTIONS ----------
def scan_http_methods(url, http, findings):
    print(f"{C.CY}[*] Phase 10: HTTP Methods Discovery...{C.X}")
    try:
        r = http.request("OPTIONS", url) if hasattr(http, "request") else http.session.options(url, timeout=http.timeout, verify=False)
        allow = r.headers.get("Allow", "") or r.headers.get("allow", "")
        if allow:
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"] if m in allow.upper()]
            if dangerous:
                findings.add(HIGH, "Dangerous HTTP methods enabled",
                             f"Server allows: {allow}",
                             f"Allow: {allow}",
                             "Disable PUT, DELETE, TRACE, CONNECT. Only allow GET, POST, HEAD, OPTIONS.")
            else:
                print(f"    {C.G}[OK] Allowed methods: {allow}{C.X}")
    except Exception:
        pass

    # TRACE
    try:
        r = http.session.request("TRACE", url, timeout=http.timeout, verify=False)
        if r.status_code == 200 and "TRACE" in r.text.upper():
            findings.add(LOW, "HTTP TRACE method enabled (XST)",
                         "TRACE echoes request headers - can be used for Cross-Site Tracing.",
                         fix="Disable the TRACE method in your web server.")
    except Exception:
        pass


# ---------- MODULE 11: BACKUP / SOURCE FILES ----------
BACKUP_SUFFIXES = [".bak", ".old", ".orig", ".swp", ".save", "~", ".copy", ".1", ".tmp"]

def scan_backup_files(url, http, findings):
    print(f"{C.CY}[*] Phase 11: Backup File Discovery...{C.X}")
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    base = f"{parsed.scheme}://{parsed.netloc}"
    base_name = os.path.basename(path.rstrip("/")) or "index"
    candidates = [path + s for s in BACKUP_SUFFIXES]
    candidates += [path + ".php.bak", path + ".html.bak", path + ".zip", path + ".tar.gz"]

    for c in candidates:
        try:
            r = http.get(base + c)
            if r.status_code == 200 and len(r.text) > 20 and r.text != "<!DOCTYPE":
                findings.add(HIGH, f"Backup file exposed: {c}",
                             f"File {c} is publicly accessible ({len(r.text)} bytes).",
                             f"GET {c} -> 200",
                             "Remove backup files from the web root. Disable directory listing.")
        except Exception:
            continue
    print(f"    {C.G}[OK] Backup file scan complete.{C.X}")


# ---------- MODULE 12: COMPRESSION / HSTS / CACHE ----------
def scan_misc(url, http, findings, response):
    print(f"{C.CY}[*] Phase 12: Misc Hardening Checks...{C.X}")
    if response is None:
        return
    h = response.headers
    # Cache-Control
    cc = h.get("Cache-Control", "")
    if not cc and "Set-Cookie" in str(h):
        findings.add(LOW, "Cache-Control missing on authenticated page",
                     "Sensitive responses may be cached by browsers or proxies.",
                     remediation="Set Cache-Control: no-store, no-cache, must-revalidate for sensitive pages.")
    # X-AspNet-Version etc
    for leak in ["X-AspNet-Version", "X-AspNetMvc-Version"]:
        if leak in h:
            findings.add(LOW, f"{leak} header disclosed", h[leak],
                         remediation=f"Remove the {leak} header.")


# ---------- REPORT GENERATION ----------
def save_report_txt(findings, path):
    with open(path, "w") as f:
        f.write(f"WebVulnScan Report\n")
        f.write(f"Target: {findings.target}\n")
        f.write(f"Scanned: {findings.start_time} -> {findings.end_time}\n")
        f.write("="*70 + "\n\n")
        for it in findings.items:
            f.write(f"[{it['severity']}] {it['title']}\n")
            if it["detail"]:    f.write(f"  Detail: {it['detail']}\n")
            if it["evidence"]:  f.write(f"  Evidence: {it['evidence']}\n")
            if it["remediation"]: f.write(f"  Fix: {it['remediation']}\n")
            f.write("\n")
    print(f"{C.G}[+] Text report saved: {path}{C.X}")

def save_report_html(findings, path):
    rows = ""
    for it in findings.items:
        color = {"CRITICAL":"#d63031","HIGH":"#e17055","MEDIUM":"#fdcb6e","LOW":"#74b9ff","INFO":"#00cec9"}[it["severity"]]
        rows += f"""
        <tr>
          <td><span style="background:{color};color:#fff;padding:4px 8px;border-radius:4px;font-weight:bold;">{escape(it['severity'])}</span></td>
          <td><b>{escape(it['title'])}</b><br><small>{escape(it['detail'])}</small></td>
          <td><code>{escape(it['evidence'][:200])}</code></td>
          <td>{escape(it['remediation'])}</td>
        </tr>"""
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>WebVulnScan Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#0f0f17;color:#eee;padding:20px;}}
h1{{color:#00cec9}}
table{{width:100%;border-collapse:collapse;background:#1a1a26;}}
th,td{{padding:10px;border-bottom:1px solid #333;text-align:left;vertical-align:top;}}
th{{background:#222233;}}
code{{background:#000;padding:2px 6px;border-radius:3px;color:#fdcb6e;font-size:12px;}}
</style></head><body>
<h1>🛡️ WebVulnScan Report</h1>
<p><b>Target:</b> {escape(findings.target)}<br>
<b>Scanned:</b> {findings.start_time} → {findings.end_time}<br>
<b>Findings:</b> {len(findings.items)}
  (Critical: {findings.count_by(CRITICAL)} |
   High: {findings.count_by(HIGH)} |
   Medium: {findings.count_by(MEDIUM)} |
   Low: {findings.count_by(LOW)} |
   Info: {findings.count_by(INFO)})</p>
<table><tr><th>Severity</th><th>Issue</th><th>Evidence</th><th>Remediation</th></tr>{rows}</table>
</body></html>"""
    with open(path, "w") as f:
        f.write(html)
    print(f"{C.G}[+] HTML report saved: {path}{C.X}")

def save_report_json(findings, path):
    out = {
        "target": findings.target,
        "start_time": str(findings.start_time),
        "end_time": str(findings.end_time),
        "summary": {
            "total": len(findings.items),
            "critical": findings.count_by(CRITICAL),
            "high": findings.count_by(HIGH),
            "medium": findings.count_by(MEDIUM),
            "low": findings.count_by(LOW),
            "info": findings.count_by(INFO),
        },
        "findings": findings.items,
    }
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"{C.G}[+] JSON report saved: {path}{C.X}")


# ---------- MAIN ----------
def main():
    parser = argparse.ArgumentParser(
        description="WebVulnScan - Web Vulnerability Scanner (Linux)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 webvulnscan.py -u https://target.com --full")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="HTTP timeout (default 10s)")
    parser.add_argument("--threads", type=int, default=10, help="Thread count (default 10)")
    parser.add_argument("--full", action="store_true", help="Run all modules (default)")
    parser.add_argument("--no-xss", action="store_true", help="Skip XSS scan")
    parser.add_argument("--no-sqli", action="store_true", help="Skip SQL injection scan")
    parser.add_argument("--no-ssl", action="store_true", help="Skip SSL/TLS scan")
    parser.add_argument("--no-files", action="store_true", help="Skip sensitive file discovery")
    parser.add_argument("-o", "--output", help="Save report to file (txt/json/html by extension)")
    args = parser.parse_args()

    banner()

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    print(f"{C.BD}Target:{C.X} {url}")
    print(f"{C.BD}Timeout:{C.X} {args.timeout}s   {C.BD}Threads:{C.X} {args.threads}\n")

    findings = Findings()
    findings.start_time = datetime.now()
    http = HTTP(timeout=args.timeout)

    response = scan_info_gathering(url, http, findings)
    scan_headers(url, http, findings, response)

    host = urllib.parse.urlparse(url).hostname
    if not args.no_ssl:
        scan_ssl(host, findings)
    else:
        print(f"{C.Y}[~] SSL scan skipped.{C.X}")

    if not args.no_xss:
        scan_xss(url, http, findings)
    if not args.no_sqli:
        scan_sqli(url, http, findings)

    scan_open_redirect(url, http, findings)
    scan_directory_traversal(url, http, findings)
    scan_subdomain_takeover(url, http, findings)
    scan_http_methods(url, http, findings)
    scan_misc(url, http, findings, response)

    if not args.no_files:
        scan_sensitive_files(url, http, findings)
        scan_backup_files(url, http, findings)

    findings.end_time = datetime.now()
    findings.print()

    # Summary footer
    print(f"{C.BD}{C.W}{'='*70}{C.X}")
    print(f"{C.BD}  SUMMARY{C.X}")
    print(f"{C.BD}{'='*70}{C.X}")
    print(f"  {C.R}{C.BD}Critical:{C.X} {findings.count_by(CRITICAL)}    "
          f"{C.R}High:{C.X} {findings.count_by(HIGH)}    "
          f"{C.Y}Medium:{C.X} {findings.count_by(MEDIUM)}    "
          f"{C.B}Low:{C.X} {findings.count_by(LOW)}    "
          f"{C.CY}Info:{C.X} {findings.count_by(INFO)}")
    print(f"  Total: {C.BD}{len(findings.items)} findings{C.X}")
    print(f"  Duration: {findings.end_time - findings.start_time}\n")

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".json":
            save_report_json(findings, args.output)
        elif ext in [".html", ".htm"]:
            save_report_html(findings, args.output)
        else:
            save_report_txt(findings, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Scan interrupted by user.{C.X}")
        sys.exit(0)




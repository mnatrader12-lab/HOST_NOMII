#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         HeaderScanner Pro - HTTP Headers Audit Tool         ║
║                   Linux Edition v1.0                         ║
╚══════════════════════════════════════════════════════════════╝

Deep analysis of HTTP security headers with grading, CSP parsing,
cookie security, CORS, redirect chains, and reverse-proxy detection.

Usage:
    python3 headerscanner.py -u https://target.com
    python3 headerscanner.py -u https://target.com --json report.json
"""

import argparse
import json
import re
import socket
import ssl
import sys
import urllib.parse
from datetime import datetime
from html import escape
from collections import OrderedDict

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Need: pip install requests urllib3")
    sys.exit(1)

# ───────────── Colors ─────────────
class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
    M="\033[95m"; CY="\033[96m"; W="\033[97m"; BD="\033[1m"; X="\033[0m"

def banner():
    print(f"""{C.CY}{C.BD}
 ╔══════════════════════════════════════════════════════════════╗
 ║        🛡  HeaderScanner Pro - HTTP Headers Audit            ║
 ║                  Linux Edition v1.0                           ║
 ╚══════════════════════════════════════════════════════════════╝{C.X}
""")

# ───────────── Header rules ─────────────
# (key, weight 0-10, severity, description, fix)
HEADER_RULES = OrderedDict([
    ("Strict-Transport-Security", {
        "weight": 10, "sev": "HIGH",
        "desc": "Forces HTTPS, prevents SSL-stripping attacks.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    }),
    ("Content-Security-Policy", {
        "weight": 15, "sev": "HIGH",
        "desc": "Mitigates XSS and data-injection attacks.",
        "fix": "Implement a strict CSP starting with: default-src 'self'"
    }),
    ("X-Frame-Options", {
        "weight": 8, "sev": "MEDIUM",
        "desc": "Prevents clickjacking via iframes.",
        "fix": "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors 'none')"
    }),
    ("X-Content-Type-Options", {
        "weight": 5, "sev": "LOW",
        "desc": "Stops MIME-sniffing-based attacks.",
        "fix": "Add: X-Content-Type-Options: nosniff"
    }),
    ("Referrer-Policy", {
        "weight": 4, "sev": "LOW",
        "desc": "Controls referrer information leakage.",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    }),
    ("Permissions-Policy", {
        "weight": 4, "sev": "LOW",
        "desc": "Restricts powerful browser features (camera, mic…).",
        "fix": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    }),
    ("Cross-Origin-Opener-Policy",   {"weight":3,"sev":"INFO","desc":"Isolates browsing context (Spectre).","fix":"Add: Cross-Origin-Opener-Policy: same-origin"}),
    ("Cross-Origin-Embedder-Policy", {"weight":3,"sev":"INFO","desc":"Requires explicit CORS for resources.","fix":"Add: Cross-Origin-Embedder-Policy: require-corp"}),
    ("Cross-Origin-Resource-Policy",{"weight":3,"sev":"INFO","desc":"Prevents cross-origin reads.","fix":"Add: Cross-Origin-Resource-Policy: same-origin"}),
    ("X-XSS-Protection",            {"weight":1,"sev":"INFO","desc":"Legacy XSS filter (deprecated).","fix":"Optional: 0 (rely on CSP)"}),
    ("X-Permitted-Cross-Domain-Policies",{"weight":2,"sev":"INFO","desc":"Restricts Flash/PDF cross-domain.","fix":"Add: X-Permitted-Cross-Domain-Policies: none"}),
    ("X-DNS-Prefetch-Control",      {"weight":1,"sev":"INFO","desc":"Controls DNS prefetching.","fix":"Add: X-DNS-Prefetch-Control: off"}),
    ("Clear-Site-Data",             {"weight":2,"sev":"INFO","desc":"Clears browser data on logout.","fix":"Add on logout endpoint: Clear-Site-Data: \"cache\", \"cookies\", \"storage\""}),
    ("Cache-Control",               {"weight":3,"sev":"LOW","desc":"Prevents caching of sensitive responses.","fix":"Cache-Control: no-store, no-cache, must-revalidate, private"}),
    ("Server",                      {"weight":1,"sev":"LOW","desc":"Discloses web server software/version.","fix":"Remove or obfuscate the Server header."}),
    ("X-Powered-By",                {"weight":1,"sev":"LOW","desc":"Discloses framework/version.","fix":"Remove the X-Powered-By header."}),
    ("X-AspNet-Version",            {"weight":1,"sev":"LOW","desc":"Discloses ASP.NET version.","fix":"Remove the X-AspNet-Version header."}),
    ("X-AspNetMvc-Version",         {"weight":1,"sev":"LOW","desc":"Discloses ASP.NET MVC version.","fix":"Remove the X-AspNetMvc-Version header."}),
])

# ───────────── CSP analyzer ─────────────
def parse_csp(csp):
    """Returns dict of directive -> list of sources."""
    parsed = {}
    for d in csp.split(";"):
        d = d.strip()
        if not d: continue
        parts = d.split()
        parsed[parts[0].lower()] = [p.lower() for p in parts[1:]]
    return parsed

def csp_warnings(csp):
    warns = []
    p = parse_csp(csp)
    has_script_src = "script-src" in p
    has_default    = "default-src" in p
    if not has_script_src and not has_default:
        warns.append("Neither script-src nor default-src defined — scripts unrestricted.")
    if "'unsafe-inline'" in p.get("script-src", []):
        warns.append("'unsafe-inline' in script-src defeats XSS protection.")
    if "'unsafe-eval'" in p.get("script-src", []):
        warns.append("'unsafe-eval' allows eval() — RCE risk via XSS.")
    if "*" in p.get("script-src", []) and not has_default:
        warns.append("Wildcard script-src with no default-src fallback.")
    if "data:" in p.get("script-src", []):
        warns.append("data: in script-src allows arbitrary inline scripts.")
    if "https:" in p.get("frame-ancestors", []) or "*" in p.get("frame-ancestors", []):
        warns.append("frame-ancestors allows framing — clickjacking possible.")
    if "object-src" not in p and "default-src" not in p:
        warns.append("object-src unrestricted — Flash/Plugin abuse possible.")
    if "base-uri" not in p:
        warns.append("base-uri not set — base-tag injection can hijack relative URLs.")
    if "form-action" not in p:
        warns.append("form-action not set — forms can POST to attacker URLs.")
    if "upgrade-insecure-requests" not in csp.lower():
        warns.append("upgrade-insecure-requests missing — HTTP subresources allowed.")
    if "report-uri" not in p and "report-to" not in p:
        warns.append("No CSP reporting endpoint — violations won't be tracked.")
    return warns

# ───────────── HSTS analyzer ─────────────
def hsts_warnings(hsts):
    w = []
    m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
    if not m:
        w.append("max-age missing.")
        return w
    age = int(m.group(1))
    if age < 15552000:                # 180 days
        w.append(f"max-age too low ({age}s). Use ≥ 31536000 (1 year).")
    if "includesubdomains" not in hsts.lower():
        w.append("includeSubDomains missing — subdomains not protected.")
    if "preload" not in hsts.lower():
        w.append("Not in HSTS preload list (consider adding).")
    return w

# ───────────── Cookie analyzer ─────────────
def cookie_warnings(cookies):
    out = []
    for c in cookies:
        raw = f"Set-Cookie: {c.name}={c.value}"
        issues = []
        raw_attrs = str(c).lower()
        if not c.secure: issues.append("Missing Secure")
        if "httponly" not in raw_attrs: issues.append("Missing HttpOnly")
        if "samesite" not in raw_attrs: issues.append("Missing SameSite")
        if c.expires is None and c.max_age is None:
            issues.append("Session cookie (no Expires/Max-Age)")
        if issues:
            out.append(f"{c.name} → " + ", ".join(issues))
    return out

# ───────────── CORS analyzer ─────────────
def cors_warnings(headers):
    w = []
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*" and acac.lower() == "true":
        w.append("CRITICAL: ACAO='*' combined with credentials=true is invalid + dangerous.")
    elif acao == "*" and acac.lower() == "true":
        w.append("Wildcard origin with credentials.")
    if "null" in acao.lower() and acac.lower() == "true":
        w.append("Origin 'null' is exploitable with credentials.")
    if "Access-Control-Allow-Origin" in headers and "Vary" not in headers and "*" not in acao:
        # Any specific origin requires Vary: Origin
        w.append("Specific ACAO without 'Vary: Origin' header → cache poisoning risk.")
    return w

# ───────────── Main scan ─────────────
def scan(url):
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urllib.parse.urlparse(url)

    sess = requests.Session()
    sess.headers["User-Agent"] = "HeaderScannerPro/1.0 (Linux)"
    try:
        r = sess.get(url, timeout=12, verify=False, allow_redirects=True)
    except Exception as e:
        print(f"{C.R}[ERROR] {e}{C.X}")
        return None

    h = r.headers
    url_final = r.url
    print(f"{C.BD}Target:{C.X}     {url_final}")
    print(f"{C.BD}Status:{C.X}    {r.status_code}")
    print(f"{C.BD}Server:{C.X}    {h.get('Server','-')}")
    print(f"{C.BD}Powered:{C.X}   {h.get('X-Powered-By','-')}")
    print(f"{C.BD}Final URL:{C.X} {url_final}")
    print(f"{C.BD}Redirects:{C.X} {len(r.history)}")
    for i, hop in enumerate(r.history, 1):
        print(f"           {C.CY}{i}. {hop.status_code} → {hop.headers.get('Location','?')}{C.X}")

    return r

def grade(present, missing_warn):
    """Compute security grade A-F."""
    score = 0
    max_score = 0
    for k, rule in HEADER_RULES.items():
        max_score += rule["weight"]
        if k in present:
            score += rule["weight"]
    pct = (score / max_score) * 100
    if pct >= 90: g = "A"
    elif pct >= 80: g = "B"
    elif pct >= 65: g = "C"
    elif pct >= 50: g = "D"
    else: g = "F"
    return g, pct

def main():
    ap = argparse.ArgumentParser(description="HeaderScanner Pro - HTTP headers audit")
    ap.add_argument("-u","--url", required=True)
    ap.add_argument("--json", help="Save JSON report")
    ap.add_argument("--html", help="Save HTML report")
    args = ap.parse_args()

    banner()
    r = scan(args.url)
    if r is None: sys.exit(1)
    h = r.headers

    print(f"\n{C.BD}{C.W}{'='*70}{C.X}")
    print(f"{C.BD}{C.W}  HEADER ANALYSIS{C.X}")
    print(f"{C.BD}{C.W}{'='*70}{C.X}\n")

    present, missing = [], []
    for k, rule in HEADER_RULES.items():
        v = h.get(k, h.get(k.lower(), None))
        sev_c = {"HIGH":C.R, "MEDIUM":C.Y, "LOW":C.B, "INFO":C.CY}[rule["sev"]]
        if v is not None:
            present.append(k)
            print(f"{C.G}✓{C.X} {k}: {C.W}{v}{C.X}")
        else:
            missing.append((k, rule))
            print(f"{sev_c}✗{C.X} {C.BD}{k}{C.X}  {C.CY}[{rule['sev']}]{C.X}  {rule['desc']}")
            print(f"  {C.G}→ Fix:{C.X} {rule['fix']}")

    # CSP deep
    csp = h.get("Content-Security-Policy") or h.get("Content-Security-Policy-Report-Only")
    if csp:
        print(f"\n{C.BD}CSP deep analysis:{C.X} {csp[:200]}{'...' if len(csp)>200 else ''}")
        for w in csp_warnings(csp):
            print(f"  {C.Y}!{C.X} {w}")

    # HSTS deep
    hsts = h.get("Strict-Transport-Security")
    if hsts:
        for w in hsts_warnings(hsts):
            print(f"  {C.Y}! HSTS:{C.X} {w}")

    # CORS
    cors = cors_warnings(h)
    if cors:
        print(f"\n{C.BD}CORS analysis:{C.X}")
        for w in cors:
            print(f"  {C.R}!{C.X} {w}")

    # Cookies
    cookie_warns = cookie_warnings(r.cookies)
    if cookie_warns:
        print(f"\n{C.BD}Cookie security:{C.X}")
        for w in cookie_warns:
            print(f"  {C.Y}!{C.X} {w}")

    # Server-info leakage
    leaks = []
    for leak in ["X-AspNet-Version", "X-AspNetMvc-Version", "X-Powered-By", "Server"]:
        if leak in h:
            leaks.append(f"{leak}: {h[leak]}")
    if leaks:
        print(f"\n{C.BD}Information disclosure:{C.X}")
        for l in leaks:
            print(f"  {C.Y}!{C.X} {l}")

    # Grade
    g, pct = grade(present, missing)
    color = {"A":C.G, "B":C.G, "C":C.Y, "D":C.Y, "F":C.R}[g]
    print(f"\n{C.BD}Security grade:{C.X} {color}{C.BD} {g} {C.X}({pct:.0f}%)")

    # Save
    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "url": r.url, "status": r.status_code,
                "headers": dict(h),
                "present": present,
                "missing": [{"header":k, **rule} for k, rule in missing],
                "grade": g, "score_pct": round(pct,1),
                "csp_warnings": csp_warnings(csp) if csp else [],
                "cors_warnings": cors,
                "cookie_warnings": cookie_warns,
                "leaks": leaks,
                "redirects": [{"status": x.status_code, "location": x.headers.get("Location")} for x in r.history],
            }, f, indent=2)
        print(f"{C.G}[+] JSON saved: {args.json}{C.X}")

    if args.html:
        rows = "".join(
            f"<tr><td>{escape(k)}</td><td><b style='color:red'>MISSING</b></td><td>{escape(rule['desc'])}</td><td>{escape(rule['fix'])}</td></tr>"
            for k, rule in missing
        ) + "".join(
            f"<tr><td>{escape(k)}</td><td><b style='color:lime'>OK</b></td><td colspan=2>{escape(h.get(k,''))[:200]}</td></tr>"
            for k in present
        )
        html = f"""<!doctype html><html><head><meta charset='utf-8'><title>Header Report</title>
<style>body{{font-family:Arial;background:#0f0f17;color:#eee;padding:20px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:8px;border:1px solid #333}}th{{background:#222}}</style></head>
<body><h1>HeaderScanner Pro</h1><p>URL: {escape(r.url)} | Grade: <b>{g}</b> ({pct:.0f}%)</p>
<table><tr><th>Header</th><th>Status</th><th>Description</th><th>Fix/Value</th></tr>{rows}</table></body></html>"""
        with open(args.html,"w") as f: f.write(html)
        print(f"{C.G}[+] HTML saved: {args.html}{C.X}")

if __name__ == "__main__":
    main()


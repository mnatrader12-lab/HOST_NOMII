#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          TechDetector - Technology Fingerprinting            ║
║                   Linux Edition v1.0                         ║
╚══════════════════════════════════════════════════════════════╝

Detects web technologies: CMS, frameworks, JS libraries,
servers, WAF, analytics, programming language.

Usage:
    python3 techdetector.py -u https://target.com
    python3 techdetector.py -u https://target.com -o report.json
"""

import argparse
import json
import re
import sys
import urllib.parse
from collections import OrderedDict

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Need: pip install requests"); sys.exit(1)

class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
    M="\033[95m"; CY="\033[96m"; W="\033[97m"; BD="\033[1m"; X="\033[0m"

def banner():
    print(f"""{C.CY}{C.BD}
 ╔══════════════════════════════════════════════════════════════╗
 ║        🔍  TechDetector - Technology Fingerprinting          ║
 ║                  Linux Edition v1.0                           ║
 ╚══════════════════════════════════════════════════════════════╝{C.X}
""")

# Signatures: (category, name, regex/list of patterns, weight)
SIGNATURES = [
    # ---- CMS ----
    ("CMS", "WordPress",      [r'wp-content/', r'wp-includes/', r'wp-json/', r'<meta name="generator" content="WordPress', r'/wp-login\.php'], 5),
    ("CMS", "Drupal",         [r'drupal\.js', r'sites/default/files', r'/drupal/', r'<meta name="generator" content="Drupal'], 5),
    ("CMS", "Joomla",         [r'/components/com_', r'<meta name="generator" content="Joomla', r'/administrator/index\.php'], 5),
    ("CMS", "Magento",        [r'/skin/frontend/', r'Mage\.Cookies', r'var/connect/', r'<meta name="generator" content="Magento'], 5),
    ("CMS", "Shopify",        [r'cdn\.shopify\.com', r'shopify-features', r'Shopify\.theme'], 5),
    ("CMS", "Squarespace",    [r'squarespace\.com', r'sqsp\.com', r'squarespace-cdn'], 5),
    ("CMS", "Wix",            [r'wix\.com', r'wixstatic\.com', r'_wixCIDX'], 5),
    ("CMS", "Blogger",        [r'blogspot\.com', r'blogger\.com'], 4),
    ("CMS", "Ghost",          [r'ghost\.org', r'/\.ghost/', r'content="Ghost'], 4),
    ("CMS", "TYPO3",          [r'typo3/', r'typo3conf/', r'<meta name="generator" content="TYPO3'], 4),
    ("CMS", "PrestaShop",     [r'prestashop', r'/themes/.+?/assets/', r'<meta name="generator" content="PrestaShop'], 4),
    ("CMS", "OpenCart",       [r'index\.php\?route=', r'<meta name="generator" content="OpenCart'], 4),
    ("CMS", "Bitrix",         [r'bitrix/', r'BX\.'], 4),
    ("CMS", "Django CMS",     [r'csrfmiddlewaretoken', r'/static/admin/'], 3),

    # ---- Web Servers ----
    ("Web Server", "nginx",         [r'Server: nginx', r'nginx/'], 5),
    ("Web Server", "Apache",        [r'Server: Apache', r'Apache/'], 5),
    ("Web Server", "IIS",           [r'Server: Microsoft-IIS', r'X-Powered-By: ASP\.NET', r'\.aspx'], 5),
    ("Web Server", "LiteSpeed",     [r'Server: LiteSpeed', r'litespeed'], 4),
    ("Web Server", "Caddy",         [r'Server: Caddy'], 4),
    ("Web Server", "Tomcat",        [r'Server: Apache-Coyote', r'<title>Apache Tomcat'], 4),
    ("Web Server", "OpenResty",     [r'Server: openresty'], 4),
    ("Web Server", "Gunicorn",      [r'Server: gunicorn'], 4),
    ("Web Server", "Cloudflare",    [r'Server: cloudflare', r'__cfduid', r'cf-ray', r'cloudflareinsights'], 4),
    ("Web Server", "Akamai",        [r'akamai', r'x-akamai'], 3),
    ("Web Server", "Fastly",        [r'fastly', r'x-served-by', r'x-cache:.*HIT.*fastly'], 3),

    # ---- Language / Framework ----
    ("Language", "PHP",          [r'\.php\?|, \$\w+ =|<\?php'], 4),
    ("Language", "ASP.NET",      [r'__VIEWSTATE', r'X-AspNet-Version', r'\.aspx', r'aspnetForm'], 5),
    ("Language", "Java",         [r'jsessionid', r'\.jsp', r'JSESSIONID', r'<%@', r'org\.apache\.'], 4),
    ("Language", "Python",       [r'csrfmiddlewaretoken', r'Server: gunicorn', r'Server: waitress', r'Werkzeug', r'\.pyc'], 4),
    ("Language", "Ruby",         [r'_rails_session', r'X-Runtime', r'X-Request-Id', r'\.rhtml', r'phusion'], 4),
    ("Language", "Node.js",      [r'X-Powered-By: Express', r'connect\.sid', r'\.bundle\.js'], 4),
    ("Language", "Go",           [r'Server: Caddy', r'X-Powered-By: Go', r'\.go-'], 3),

    # ---- Frameworks ----
    ("Framework", "React",         [r'react\.production\.min\.js', r'__REACT', r'ReactDOM', r'data-react'], 5),
    ("Framework", "Vue.js",        [r'vue\.runtime', r'Vue\.js', r'v-cloak', r'__VUE__'], 5),
    ("Framework", "Angular",       [r'angular\.js', r'ng-version', r'angular\.min\.js', r'<app-root>'], 5),
    ("Framework", "jQuery",        [r'jquery', r'jQuery'], 4),
    ("Framework", "Next.js",       [r'_next/static', r'__NEXT_DATA__', r'next/dist'], 5),
    ("Framework", "Nuxt.js",       [r'_nuxt/', r'__NUXT__', r'nuxt-build'], 5),
    ("Framework", "Express",       [r'X-Powered-By: Express'], 5),
    ("Framework", "Django",        [r'csrfmiddlewaretoken', r'django'], 5),
    ("Framework", "Laravel",       [r'laravel_session', r'X-Powered-By: Laravel', r'laravel'], 5),
    ("Framework", "Symfony",       [r'symfony'], 4),
    ("Framework", "CodeIgniter",   [r'codeigniter', r'ci_session'], 4),
    ("Framework", "Yii",           [r'YII_CSRF_TOKEN', r'yii\.'], 4),
    ("Framework", "CakePHP",       [r'cakephp', r'CakeSession'], 4),
    ("Framework", "Spring",        [r'org\.springframework', r'X-Application-Context'], 5),
    ("Framework", "Flask",         [r'Server: Werkzeug', r'flask'], 4),
    ("Framework", "FastAPI",       [r'fastapi'], 4),
    ("Framework", "Rails",         [r'X-Runtime', r'csrf-param', r'turbolinks', r'_rails_session'], 4),
    ("Framework", "Sinatra",       [r'sinatra'], 3),
    ("Framework", "Bootstrap",     [r'bootstrap\.min\.css', r'class="container"', r'bootstrapcdn'], 3),
    ("Framework", "Tailwind",      [r'tailwindcss', r'class="(?:flex|grid|w-full)'], 3),
    ("Framework", "Foundation",    [r'foundation\.min\.css'], 3),
    ("Framework", "Material-UI",   [r'mui-', r'MuiButton'], 3),
    ("Framework", "Bulma",         [r'bulma\.css', r'class="hero "'], 2),
    ("Framework", "Ember.js",      [r'ember-', r'ember\.min\.js'], 4),
    ("Framework", "Backbone.js",   [r'backbone\.js', r'Backbone\.'], 3),
    ("Framework", "Svelte",        [r'svelte-', r'__svelte'], 4),
    ("Framework", "Gatsby",        [r'gatsby-', r'___gatsby'], 4),

    # ---- JS Libraries / Analytics ----
    ("JS Library", "Google Analytics",  [r'google-analytics\.com', r'ga\(', r'gtag\('], 4),
    ("JS Library", "Google Tag Manager",[r'googletagmanager\.com', r'GTM-'], 4),
    ("JS Library", "Facebook Pixel",   [r'connect\.facebook\.net', r'fbq\('], 4),
    ("JS Library", "Hotjar",           [r'static\.hotjar\.com', r'hjid='], 4),
    ("JS Library", "Mixpanel",         [r'mixpanel\.com', r'mixpanel\.'], 4),
    ("JS Library", "Segment",          [r'segment\.com', r'analytics\.js'], 3),
    ("JS Library", "Intercom",         [r'intercom\.io', r'intercomSettings'], 3),
    ("JS Library", "Sentry",           [r'sentry\.io', r'@sentry/'], 3),
    ("JS Library", "Stripe.js",        [r'js\.stripe\.com', r'Stripe\('], 4),
    ("JS Library", "PayPal",           [r'paypal\.com/sdk', r'paypalobjects'], 4),
    ("JS Library", "Cloudflare Turnstile",[r'challenges\.cloudflare\.com/turnstile'], 3),
    ("JS Library", "reCAPTCHA",        [r'google\.com/recaptcha', r'grecaptcha'], 3),
    ("JS Library", "hCaptcha",         [r'hcaptcha\.com'], 3),
    ("JS Library", "MathJax",          [r'mathjax'], 3),
    ("JS Library", "Three.js",         [r'three\.js', r'THREE\.'], 3),
    ("JS Library", "D3.js",            [r'd3\.js', r'd3\.min\.js'], 3),
    ("JS Library", "Chart.js",         [r'chart\.js', r'Chart\.js'], 3),
    ("JS Library", "Moment.js",        [r'moment\.js', r'moment\.min\.js'], 3),
    ("JS Library", "Lodash",           [r'lodash', r'_\.VERSION'], 3),

    # ---- WAF / CDN ----
    ("Security", "Cloudflare WAF",   [r'__cfduid', r'cf-ray', r'cloudflare'], 4),
    ("Security", "Akamai WAF",       [r'akamai', r'x-akamai'], 3),
    ("Security", "AWS WAF",          [r'X-Amzn-', r'awselb'], 3),
    ("Security", "Imperva/Incapsula",[r'incapsula', r'visid_incap', r'imperva'], 4),
    ("Security", "Sucuri",           [r'sucuri', r'x-sucuri'], 4),
    ("Security", "F5 BIG-IP ASM",    [r'BigIP', r'X-Cnection'], 3),
    ("Security", "Barracuda WAF",    [r'barracuda'], 3),
    ("Security", "ModSecurity",      [r'mod_security', r'Mod_Security'], 3),
    ("Security", "DDoS-Guard",       [r'ddos-guard'], 3),
    ("Security", "Varnish",          [r'X-Varnish', r'Via: .*varnish'], 3),

    # ---- Misc / Tools ----
    ("Tool", "phpMyAdmin",    [r'/phpmyadmin/', r'pma_'], 5),
    ("Tool", "cPanel",        [r'cPanel', r':2083', r':2082'], 4),
    ("Tool", "Plesk",         [r'Plesk', r':8443'], 4),
    ("Tool", "Wordfence",     [r'wordfence'], 3),
    ("Tool", "Yoast SEO",     [r'yoast'], 2),
    ("Tool", "All In One SEO",[r'aioseop', r'all_in_one_seo'], 2),
    ("Tool", "W3 Total Cache",[r'w3-total-cache', r'W3TC_'], 2),
    ("Tool", "WP Fastest Cache",[r'wp-fastest-cache'], 2),
    ("Tool", "Elementor",     [r'elementor'], 2),
]

def detect(url, response):
    body = response.text
    headers_str = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    haystack = body + "\n" + headers_str

    found = OrderedDict()
    for cat, name, patterns, weight in SIGNATURES:
        for pat in patterns:
            if re.search(pat, haystack, re.I):
                if cat not in found: found[cat] = []
                if name not in [x["name"] for x in found[cat]]:
                    found[cat].append({"name": name, "weight": weight, "matched": pat})
                break

    return found

def main():
    ap = argparse.ArgumentParser(description="TechDetector - fingerprint web technologies")
    ap.add_argument("-u","--url", required=True)
    ap.add_argument("-t","--timeout", type=int, default=12)
    ap.add_argument("-o","--output", help="Output JSON file")
    args = ap.parse_args()

    banner()

    url = args.url.strip()
    if not url.startswith(("http://","https://")):
        url = "https://" + url

    print(f"{C.BD}Target:{C.X} {url}\n")

    sess = requests.Session()
    sess.headers["User-Agent"] = "TechDetector/1.0 (Linux)"

    try:
        r = sess.get(url, timeout=args.timeout, verify=False, allow_redirects=True)
    except Exception as e:
        print(f"{C.R}[ERROR] {e}{C.X}"); sys.exit(1)

    print(f"{C.BD}Status:{C.X}  {r.status_code}")
    print(f"{C.BD}Server:{C.X}  {r.headers.get('Server','-')}")
    print(f"{C.BD}Length:{C.X}  {len(r.text)} bytes\n")

    found = detect(url, r)

    print(f"{C.BD}{C.W}{'='*70}{C.X}")
    print(f"{C.BD}  DETECTED TECHNOLOGIES{C.X}")
    print(f"{C.BD}{C.W}{'='*70}{C.X}\n")

    if not found:
        print(f"{C.Y}No technologies detected.{C.X}")

    for cat, items in found.items():
        print(f"{C.CY}{C.BD}[{cat}]{C.X}")
        for it in items:
            w_color = C.G if it["weight"] >= 5 else (C.Y if it["weight"] >= 3 else C.B)
            print(f"  {C.G}●{C.X} {C.W}{it['name']:<28}{C.X} {w_color}confidence: {'█'*it['weight']}{C.X}")
            print(f"      {C.CY}matched: {it['matched']}{C.X}")
        print()

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"url": r.url, "headers": dict(r.headers), "detected": found}, f, indent=2)
        print(f"{C.G}[+] Saved: {args.output}{C.X}")

if __name__ == "__main__":
    main()


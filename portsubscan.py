#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       PortSubScan - Port + Subdomain Scanner                 ║
║                   Linux Edition v1.0                         ║
╚══════════════════════════════════════════════════════════════╝

- Concurrent TCP port scan (top 100 + custom list)
- Service banner grabbing
- Subdomain enumeration via wordlist
- DNS record lookup (A, AAAA, MX, NS, TXT, CNAME)
- HTTP probes on discovered subdomains

Usage:
    python3 portsubscan.py -t example.com
    python3 portsubscan.py -t example.com --ports top1000 --sub wordlist.txt
    python3 portsubscan.py -t example.com --full -o report.json
"""

import argparse
import json
import socket
import ssl
import sys
import os
import concurrent.futures
from datetime import datetime
from collections import OrderedDict

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    pass

class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
    M="\033[95m"; CY="\033[96m"; W="\033[97m"; BD="\033[1m"; X="\033[0m"

def banner():
    print(f"""{C.CY}{C.BD}
 ╔══════════════════════════════════════════════════════════════╗
 ║     🔌  PortSubScan - Ports & Subdomain Discovery           ║
 ║                  Linux Edition v1.0                           ║
 ╚══════════════════════════════════════════════════════════════╝{C.X}
""")

# Top 100 + extra common
TOP_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",26:"SMTP-alt",37:"Time",43:"WHOIS",
    53:"DNS",67:"DHCP",68:"DHCP",69:"TFTP",80:"HTTP",81:"HTTP-alt",110:"POP3",
    111:"RPCBind",113:"Ident",119:"NNTP",123:"NTP",135:"MSRPC",137:"NetBIOS-NS",
    138:"NetBIOS-DGM",139:"NetBIOS-SSN",143:"IMAP",161:"SNMP",162:"SNMP-trap",
    179:"BGP",389:"LDAP",443:"HTTPS",445:"SMB",465:"SMTPS",500:"IKE",514:"Syslog",
    515:"LPD",520:"RIP",587:"SMTP-sub",631:"IPP",636:"LDAPS",873:"rsync",902:"VNC",
    989:"FTPS",990:"FTPS",993:"IMAPS",995:"POP3S",1080:"SOCKS",1194:"OpenVPN",
    1433:"MSSQL",1434:"MSSQL-UDP",1521:"Oracle",1701:"L2TP",1723:"PPTP",
    1883:"MQTT",2049:"NFS",2082:"cPanel",2083:"cPanel-SSL",2086:"WHM",2087:"WHM-SSL",
    2095:"Webmail",2096:"Webmail-SSL",2181:"ZooKeeper",2375:"Docker",2376:"Docker-SSL",
    3306:"MySQL",3389:"RDP",3690:"SVN",4000:"ICQ/Node-Alt",4369:"Erlang",
    5000:"UPNP/Flask",5001:"Flask-SSL",5432:"PostgreSQL",5601:"Kibana",5984:"CouchDB",
    6379:"Redis",7001:"WebLogic",8000:"HTTP-alt",8008:"HTTP-alt",8080:"HTTP-Proxy",
    8081:"HTTP-Alt",8083:"Vestacp",8443:"HTTPS-Alt",8500:"Consul",8888:"Alt-HTTP",
    9000:"PHP-FPM",9001:"Supervisor",9042:"Cassandra",9090:"Prometheus/Cockpit",
    9092:"Kafka",9100:"JetDirect",9200:"Elasticsearch",9418:"Git",11211:"Memcached",
    15672:"RabbitMQ",27017:"MongoDB",50000:"SAP",50070:"Hadoop"
}

DEFAULT_SUBS = [
    "www","mail","smtp","pop","pop3","imap","webmail","email","mx","mx1",
    "blog","forum","shop","store","api","api2","v1","v2","rest","graphql",
    "dev","development","stage","staging","test","testing","qa","sandbox",
    "beta","alpha","demo","trial","pre","preview","sandbox","lab",
    "admin","administrator","panel","cpanel","whm","webadmin","sysadmin",
    "portal","intranet","extranet","internal","private","corp","corporate",
    "secure","login","auth","sso","oauth","vpn","remote","gateway",
    "m","mobile","mobi","m2","m3","wap","ios","android","app","apps",
    "static","assets","cdn","media","images","img","photos","video","videos",
    "files","filemanager","upload","uploads","download","downloads",
    "git","gitlab","github","bitbucket","svn","hg","jira","confluence","wiki",
    "jenkins","travis","drone","bamboo","circle","ci","cd","build","deploy",
    "monitor","monitoring","status","health","nagios","zabbix","grafana",
    "prometheus","kibana","elastic","elasticsearch","logstash","splunk",
    "k8s","kubernet","kubernetes","rancher","helm","argo",
    "db","database","mysql","postgres","postgresql","mongo","mongodb",
    "redis","cache","memcached","rabbitmq","kafka","activemq","mq","queue",
    "backup","backups","bak","old","new","temp","tmp","archive","archives",
    "docs","doc","documentation","help","faq","support","ticket","tickets",
    "chat","irc","xmpp","slack","mattermost","rocket","teams",
    "stats","analytics","tracking","pixel","track","telemetry",
    "search","solr","opensearch","sphinx",
    "cloud","aws","azure","gcp","digitalocean","heroku","vercel","netlify",
    "ftp","sftp","ftps","ssh","telnet","snmp","ldap",
    "ns1","ns2","ns3","ns4","ns01","ns02","dns1","dns2","dns","nameserver",
    "mx01","mx02","mx2","smtp1","smtp2",
    "office","o365","exchange","owa","autodiscover","lync","skype","teams",
    "sharepoint","onedrive","intranet","portal","erp","crm","sap","oracle",
    "hr","it","finance","sales","marketing","legal","ops",
    "us","eu","uk","de","fr","asia","jp","cn","in","br","au","ca","sa",
    "1","2","3","01","02","1a","1b","2a","v1","v2","old","new","backup"
]

# ----- DNS helpers -----
def dns_lookup(host, rtype="A"):
    try:
        import dns.resolver
        answers = dns.resolver.resolve(host, rtype)
        return [str(a) for a in answers]
    except Exception:
        return []
    except ModuleNotFoundError:
        return []

def fallback_dns(host):
    """Use socket if dnspython not installed."""
    out = {"A": [], "AAAA": []}
    try:
        out["A"] = socket.gethostbyname_ex(host)[2]
    except Exception:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET6)
        out["AAAA"] = list({i[4][0] for i in infos})
    except Exception:
        pass
    return out

# ----- Port scan -----
def grab_banner(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.settimeout(1.5)
        try:
            s.send(b"HEAD / HTTP/1.0\r\nHost: %b\r\nUser-Agent: PortSubScan/1.0\r\n\r\n" % host.encode())
        except Exception:
            pass
        data = b""
        try:
            data = s.recv(512)
        except Exception:
            pass
        s.close()
        return data.decode(errors="ignore").strip().splitlines()[0] if data else ""
    except Exception:
        return ""

def scan_port(host, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            banner = grab_banner(host, port)
            return (port, TOP_PORTS.get(port, "unknown"), banner)
    except Exception:
        pass
    return None

def port_scan(host, ports, workers=80, timeout=1.5):
    results = []
    print(f"{C.CY}[*] Port scan: {host} ({len(ports)} ports, {workers} workers){C.X}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(lambda p: scan_port(host, p, timeout), ports):
            if r:
                results.append(r)
                port, svc, bn = r
                bn_short = bn[:70] + "…" if len(bn) > 70 else bn
                print(f"    {C.G}●{C.X} {C.BD}{port:>5}{C.X}/{C.CY}{svc:<14}{C.X}  {C.W}{bn_short}{C.X}")
    return results

# ----- Subdomain enum -----
def check_sub(domain, sub, workers=50, timeout=2.0):
    host = f"{sub}.{domain}"
    try:
        socket.gethostbyname(host)
        return host
    except Exception:
        return None

def subdomain_enum(domain, wordlist=None, workers=80):
    words = wordlist or DEFAULT_SUBS
    print(f"{C.CY}[*] Subdomain enum: {domain} ({len(words)} words){C.X}")
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for h in ex.map(lambda w: check_sub(domain, w, workers, 1.0), words):
            if h:
                found.append(h)
                print(f"    {C.G}●{C.X} {C.BD}{h}{C.X}")
    return sorted(found)

# ----- HTTP probe -----
def http_probe(host, timeout=4):
    info = {"host": host, "http": None, "https": None}
    for proto in ("https", "http"):
        url = f"{proto}://{host}/"
        try:
            r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            info[proto] = {
                "status": r.status_code,
                "server": r.headers.get("Server",""),
                "title": re_title(r.text),
                "redirect_to": r.url if r.url != url else None,
            }
        except Exception as e:
            info[proto] = {"error": str(e)[:80]}
    return info

def re_title(html):
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I|re.S)
    return m.group(1).strip()[:80] if m else ""

# ----- Main -----
def main():
    ap = argparse.ArgumentParser(description="PortSubScan - ports + subdomain discovery")
    ap.add_argument("-t","--target", required=True, help="Domain or host (e.g. example.com)")
    ap.add_argument("--ports", default="top100", help="top100, top1000, or comma list like 80,443,8080")
    ap.add_argument("--sub", help="Subdomain wordlist file")
    ap.add_argument("--threads", type=int, default=80)
    ap.add_argument("--timeout", type=int, default=1500, help="Port timeout in ms")
    ap.add_argument("--full", action="store_true", help="Run ports + subdomains + http probe")
    ap.add_argument("-o","--output", help="Save JSON")
    args = ap.parse_args()

    banner()
    target = args.target.strip().replace("https://","").replace("http://","").rstrip("/")
    host   = target.split("/")[0].split(":")[0]

    print(f"{C.BD}Target:{C.X} {host}\n")

    # Resolve
    print(f"{C.CY}[*] DNS resolution...{C.X}")
    ips = []
    try:
        ips = socket.gethostbyname_ex(host)[2]
        print(f"    {C.G}A records:{C.X} {', '.join(ips)}")
    except Exception as e:
        print(f"    {C.R}{e}{C.X}")

    # Ports
    if args.ports == "top1000":
        port_list = list(range(1, 1001))
    elif args.ports == "top100":
        port_list = list(TOP_PORTS.keys())
    elif args.ports == "all":
        port_list = list(range(1, 65536))
    else:
        port_list = [int(x) for x in args.ports.split(",") if x.isdigit()]

    port_results = port_scan(host, port_list, workers=args.threads, timeout=args.timeout/1000)

    # Subdomains
    sub_list = None
    if args.sub and os.path.exists(args.sub):
        with open(args.sub) as f:
            sub_list = [l.strip() for l in f if l.strip()]
    subs = subdomain_enum(host, sub_list, workers=args.threads)

    # HTTP probe on subs
    if args.full and subs:
        print(f"\n{C.CY}[*] HTTP probe on {len(subs)} subdomains...{C.X}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            for info in ex.map(http_probe, subs):
                for proto in ("https","http"):
                    p = info[proto]
                    if p and "error" not in p and p.get("status"):
                        s_color = C.G if p["status"] < 400 else C.Y
                        print(f"    {s_color}{proto}://{info['host']:<40}{C.X} {C.BD}{p['status']}{C.X}  {C.CY}{p.get('title','')}{C.X}  {C.W}{p.get('server','')}{C.X}")

    # Summary
    print(f"\n{C.BD}{C.W}{'='*70}{C.X}")
    print(f"{C.BD}  SUMMARY{C.X}")
    print(f"{C.BD}{C.W}{'='*70}{C.X}")
    print(f"  Open ports:       {C.G}{len(port_results)}{C.X}")
    print(f"  Subdomains found: {C.G}{len(subs)}{C.X}")
    print(f"  IPs resolved:     {C.G}{len(ips)}{C.X}\n")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "target": host, "ips": ips,
                "ports": [{"port":p,"service":s,"banner":b} for p,s,b in port_results],
                "subdomains": subs,
                "scanned_at": str(datetime.now()),
            }, f, indent=2)
        print(f"{C.G}[+] Saved: {args.output}{C.X}")

if __name__ == "__main__":
    main()


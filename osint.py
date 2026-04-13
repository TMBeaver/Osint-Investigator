#!/usr/bin/env python3
"""
============================================================
  OSINT Investigator — Domain & Username Intelligence Tool
  For authorized security research and ethical use only.
============================================================
"""

import sys
import json
import socket
import time
import argparse
import re
import urllib.request
import urllib.error
from datetime import datetime

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    C = True
except ImportError:
    C = False

# ── Color helpers ──────────────────────────────────────────
def green(s):  return (Fore.GREEN + str(s) + Style.RESET_ALL) if C else str(s)
def red(s):    return (Fore.RED + str(s) + Style.RESET_ALL) if C else str(s)
def cyan(s):   return (Fore.CYAN + str(s) + Style.RESET_ALL) if C else str(s)
def yellow(s): return (Fore.YELLOW + str(s) + Style.RESET_ALL) if C else str(s)
def bold(s):   return (Style.BRIGHT + str(s) + Style.RESET_ALL) if C else str(s)
def dim(s):    return (Style.DIM + str(s) + Style.RESET_ALL) if C else str(s)

BANNER = r"""
  ___  ____  ___ _   _ _____   _____ ___   ___  _     
 / _ \/ ___|_ _| \ | |_   _| |_   _/ _ \ / _ \| |    
| | | \___ \| ||  \| | | |     | || | | | | | | |    
| |_| |___) | || |\  | | |     | || |_| | |_| | |___ 
 \___/|____/___|_| \_| |_|     |_| \___/ \___/|_____|
                                                       
  Domain & Username Intelligence Investigator v1.0
  [ For authorized security research only ]
"""

SECTION = "─" * 55

results_store = {}

# ── Utilities ──────────────────────────────────────────────
def section(title):
    print(f"\n{cyan(SECTION)}")
    print(f"  {bold(title)}")
    print(cyan(SECTION))

def hit(label, value):
    print(f"  {green('✔')}  {bold(label):<22} {value}")

def miss(label):
    print(f"  {dim('✘')}  {label}")

def info(msg):
    print(f"  {yellow('ℹ')}  {msg}")

def fetch(url, timeout=8, headers=None):
    """Safe HTTP GET, returns (status_code, text) or (None, None)."""
    if not REQUESTS_OK:
        return None, None
    try:
        h = {"User-Agent": "Mozilla/5.0 (OSINT-Investigator/1.0)"}
        if headers:
            h.update(headers)
        r = requests.get(url, timeout=timeout, headers=h, allow_redirects=True)
        return r.status_code, r.text
    except Exception:
        return None, None

def head_request(url, timeout=6):
    """HEAD request, returns status code or None."""
    if not REQUESTS_OK:
        return None
    try:
        h = {"User-Agent": "Mozilla/5.0 (OSINT-Investigator/1.0)"}
        r = requests.head(url, timeout=timeout, headers=h, allow_redirects=True)
        return r.status_code
    except Exception:
        return None

# ══════════════════════════════════════════════════════════
#   DOMAIN INVESTIGATION
# ══════════════════════════════════════════════════════════

def investigate_domain(domain):
    print(f"\n{bold(cyan(BANNER))}")
    print(f"\n  Target domain : {green(domain)}")
    print(f"  Scan started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    results_store['target'] = domain
    results_store['type'] = 'domain'
    results_store['findings'] = {}

    dns_lookup(domain)
    whois_lookup(domain)
    http_probe(domain)
    subdomain_enum(domain)
    check_security_headers(domain)
    check_robots_sitemap(domain)
    breach_check_domain(domain)
    google_dorks(domain)
    print_summary()


def dns_lookup(domain):
    section("DNS Records")
    findings = {}

    # A record (IP)
    try:
        ip = socket.gethostbyname(domain)
        hit("A (IP Address)", ip)
        findings['A'] = ip
        # Reverse DNS
        try:
            rev = socket.gethostbyaddr(ip)[0]
            hit("Reverse DNS", rev)
            findings['PTR'] = rev
        except Exception:
            pass
    except Exception:
        miss("A record — could not resolve")

    if DNS_OK:
        record_types = ['MX', 'NS', 'TXT', 'CNAME', 'AAAA']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                vals = [str(r) for r in answers]
                for v in vals:
                    hit(rtype, v[:70])
                findings[rtype] = vals
            except Exception:
                pass
    else:
        info("Install dnspython for full DNS enumeration: pip install dnspython")

    results_store['findings']['dns'] = findings


def whois_lookup(domain):
    section("WHOIS / Registration Info")
    findings = {}
    # Try WHOIS via RDAP (HTTP-based, no socket needed)
    rdap_url = f"https://rdap.org/domain/{domain}"
    status, body = fetch(rdap_url)
    if status == 200 and body:
        try:
            data = json.loads(body)
            # Registrar
            entities = data.get('entities', [])
            for e in entities:
                roles = e.get('roles', [])
                vcard = e.get('vcardArray', [])
                name = None
                if vcard and len(vcard) > 1:
                    for v in vcard[1]:
                        if v[0] == 'fn':
                            name = v[3]
                if 'registrar' in roles and name:
                    hit("Registrar", name)
                    findings['Registrar'] = name
            # Dates
            events = data.get('events', [])
            for ev in events:
                action = ev.get('eventAction', '')
                date = ev.get('eventDate', '')[:10]
                if action == 'registration':
                    hit("Created", date); findings['Created'] = date
                elif action == 'expiration':
                    hit("Expires", date); findings['Expires'] = date
                elif action == 'last changed':
                    hit("Updated", date); findings['Updated'] = date
            # Name servers
            ns_list = [ns.get('ldhName','') for ns in data.get('nameservers', [])]
            if ns_list:
                hit("Name Servers", ', '.join(ns_list[:4]))
                findings['Name Servers'] = ns_list
            # Status
            status_list = data.get('status', [])
            if status_list:
                hit("Domain Status", ', '.join(status_list[:3]))
        except Exception as e:
            info(f"RDAP parse error: {e}")
    else:
        info("WHOIS/RDAP unavailable in this environment.")
        info("Run locally: pip install python-whois && python3 osint.py -d " + domain)
    results_store['findings']['whois'] = findings


def http_probe(domain):
    section("HTTP / HTTPS Probe")
    findings = {}
    for scheme in ['https', 'http']:
        url = f"{scheme}://{domain}"
        status, body = fetch(url)
        if status:
            hit(f"{scheme.upper()} Status", status)
            findings[scheme] = status
            # Try to grab title
            if body:
                m = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
                if m:
                    title = m.group(1).strip()[:80]
                    hit("Page Title", title)
                    findings['title'] = title
                # Tech fingerprinting from body
                techs = []
                patterns = {
                    'WordPress': 'wp-content',
                    'Joomla': 'joomla',
                    'Drupal': 'drupal',
                    'Laravel': 'laravel',
                    'React': 'react',
                    'Angular': 'ng-version',
                    'Vue.js': 'vue',
                    'jQuery': 'jquery',
                    'Bootstrap': 'bootstrap',
                    'Shopify': 'shopify',
                    'Cloudflare': '__cfduid',
                }
                body_lower = body.lower()
                for tech, sig in patterns.items():
                    if sig in body_lower:
                        techs.append(tech)
                if techs:
                    hit("Technologies", ', '.join(techs))
                    findings['technologies'] = techs
            break
        else:
            miss(f"{scheme.upper()} — no response")
    results_store['findings']['http'] = findings


def check_security_headers(domain):
    section("Security Headers Audit")
    findings = {}
    if not REQUESTS_OK:
        info("requests not available")
        return
    try:
        url = f"https://{domain}"
        h = {"User-Agent": "Mozilla/5.0 (OSINT-Investigator/1.0)"}
        r = requests.get(url, timeout=8, headers=h, allow_redirects=True)
        headers = r.headers

        checks = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy':   'CSP',
            'X-Frame-Options':           'Clickjacking Protection',
            'X-Content-Type-Options':    'MIME Sniffing Protection',
            'Referrer-Policy':           'Referrer Policy',
            'Permissions-Policy':        'Permissions Policy',
            'X-XSS-Protection':          'XSS Protection (legacy)',
        }
        for header, label in checks.items():
            val = headers.get(header)
            if val:
                hit(label, green("PRESENT"))
                findings[header] = val
            else:
                print(f"  {red('✘')}  {bold(label):<22} {red('MISSING')}")
                findings[header] = None

        # Server header — info leakage
        server = headers.get('Server', '')
        if server:
            hit("Server Header", yellow(server) + " ← possible info leak")
            findings['Server'] = server

        x_powered = headers.get('X-Powered-By', '')
        if x_powered:
            hit("X-Powered-By", yellow(x_powered) + " ← info leak")
            findings['X-Powered-By'] = x_powered

    except Exception as e:
        info(f"Could not fetch headers: {e}")
    results_store['findings']['headers'] = findings


def subdomain_enum(domain):
    section("Subdomain Enumeration (passive)")
    findings = []
    # Common subdomains wordlist
    common = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
        'admin', 'portal', 'api', 'dev', 'staging', 'test', 'beta',
        'vpn', 'remote', 'ssh', 'git', 'gitlab', 'github', 'jira',
        'confluence', 'wiki', 'docs', 'blog', 'shop', 'store', 'cdn',
        'static', 'assets', 'img', 'images', 'media', 'upload',
        'cpanel', 'webdisk', 'ns1', 'ns2', 'mx', 'relay',
        'app', 'mobile', 'm', 'new', 'old', 'legacy', 'backup',
        'db', 'database', 'mysql', 'redis', 'monitor', 'status',
        'help', 'support', 'kb', 'crm', 'erp', 'login', 'auth',
    ]
    found = []
    total = len(common)
    print(f"  Probing {total} common subdomains...\n")
    for sub in common:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            print(f"  {green('✔')}  {bold(fqdn):<40} {ip}")
            found.append({'subdomain': fqdn, 'ip': ip})
            findings.append(fqdn)
        except socket.gaierror:
            pass

    if not found:
        info("No common subdomains resolved.")
    else:
        print(f"\n  {green(f'Found {len(found)} subdomains.')}")
    results_store['findings']['subdomains'] = findings


def check_robots_sitemap(domain):
    section("Robots.txt & Sitemap")
    for path in ['/robots.txt', '/sitemap.xml', '/sitemap_index.xml']:
        url = f"https://{domain}{path}"
        status, body = fetch(url)
        if status == 200 and body:
            lines = [l.strip() for l in body.splitlines() if l.strip()][:10]
            hit(path, f"Found ({len(body)} bytes)")
            for line in lines[:6]:
                print(f"       {dim(line[:70])}")
        else:
            miss(path)


def breach_check_domain(domain):
    section("Public Breach & Exposure Check")
    # Check crt.sh for certificate transparency (leaks subdomains/emails)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    status, body = fetch(url)
    if status == 200 and body:
        try:
            certs = json.loads(body)
            unique = set()
            for c in certs:
                name = c.get('name_value', '')
                for n in name.split('\n'):
                    n = n.strip().lstrip('*.')
                    if domain in n:
                        unique.add(n)
            if unique:
                hit("crt.sh certificates", f"{len(unique)} unique entries found")
                for entry in sorted(unique)[:8]:
                    print(f"       {dim(entry)}")
                if len(unique) > 8:
                    print(f"       {dim(f'... and {len(unique)-8} more')}")
                results_store['findings']['crtsh'] = list(unique)
            else:
                miss("crt.sh — no entries")
        except Exception:
            miss("crt.sh — parse error")
    else:
        miss("crt.sh — unavailable")

    # HaveIBeenPwned domain search (public endpoint, no key needed)
    info("Tip: Check https://haveibeenpwned.com/DomainSearch for email breaches")


def google_dorks(domain):
    section("Google Dork Suggestions")
    info("Run these searches manually in Google for deeper recon:\n")
    dorks = [
        f'site:{domain} filetype:pdf',
        f'site:{domain} filetype:xls OR filetype:xlsx',
        f'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard',
        f'site:{domain} intitle:"index of"',
        f'site:{domain} "password" OR "credentials" filetype:txt',
        f'"{domain}" email contact',
        f'site:github.com "{domain}"',
        f'site:pastebin.com "{domain}"',
    ]
    for d in dorks:
        print(f"  {yellow('❯')}  {d}")


# ══════════════════════════════════════════════════════════
#   USERNAME INVESTIGATION
# ══════════════════════════════════════════════════════════

def investigate_username(username):
    print(f"\n{bold(cyan(BANNER))}")
    print(f"\n  Target username : {green(username)}")
    print(f"  Scan started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    results_store['target'] = username
    results_store['type'] = 'username'
    results_store['findings'] = {}

    username_platforms(username)
    username_github(username)
    username_email_guess(username)
    print_summary()


def username_platforms(username):
    section("Platform Presence Check")
    platforms = {
        'GitHub':       f"https://github.com/{username}",
        'GitLab':       f"https://gitlab.com/{username}",
        'Twitter/X':    f"https://twitter.com/{username}",
        'Instagram':    f"https://www.instagram.com/{username}/",
        'Reddit':       f"https://www.reddit.com/user/{username}",
        'LinkedIn':     f"https://www.linkedin.com/in/{username}",
        'TryHackMe':    f"https://tryhackme.com/p/{username}",
        'HackTheBox':   f"https://app.hackthebox.com/users/search?term={username}",
        'Medium':       f"https://medium.com/@{username}",
        'Dev.to':       f"https://dev.to/{username}",
        'Keybase':      f"https://keybase.io/{username}",
        'Pinterest':    f"https://www.pinterest.com/{username}/",
        'YouTube':      f"https://www.youtube.com/@{username}",
        'Twitch':       f"https://www.twitch.tv/{username}",
        'Steam':        f"https://steamcommunity.com/id/{username}",
        'HackerNews':   f"https://news.ycombinator.com/user?id={username}",
        'Pastebin':     f"https://pastebin.com/u/{username}",
        'DockerHub':    f"https://hub.docker.com/u/{username}",
        'NPM':          f"https://www.npmjs.com/~{username}",
        'PyPI':         f"https://pypi.org/user/{username}/",
    }

    found = []
    not_found = []

    print(f"  Checking {len(platforms)} platforms...\n")
    for name, url in platforms.items():
        status = head_request(url, timeout=7)
        if status and status == 200:
            print(f"  {green('✔')}  {bold(name):<18} {green('FOUND')}  →  {dim(url)}")
            found.append({'platform': name, 'url': url})
        elif status and status in [301, 302]:
            print(f"  {yellow('~')}  {bold(name):<18} {yellow('REDIRECT')}  →  {dim(url)}")
        else:
            print(f"  {dim('✘')}  {name}")
            not_found.append(name)
        time.sleep(0.3)  # polite rate limiting

    print(f"\n  {green(f'Found on {len(found)} platforms.')}")
    results_store['findings']['platforms'] = found


def username_github(username):
    section("GitHub Deep Dive")
    url = f"https://api.github.com/users/{username}"
    status, body = fetch(url, headers={"Accept": "application/vnd.github.v3+json"})

    if status == 200 and body:
        try:
            data = json.loads(body)
            fields = {
                'Name':        data.get('name'),
                'Bio':         data.get('bio'),
                'Company':     data.get('company'),
                'Location':    data.get('location'),
                'Blog/Site':   data.get('blog'),
                'Email':       data.get('email'),
                'Twitter':     data.get('twitter_username'),
                'Public Repos':data.get('public_repos'),
                'Followers':   data.get('followers'),
                'Following':   data.get('following'),
                'Created':     data.get('created_at'),
                'Last Active': data.get('updated_at'),
            }
            for label, val in fields.items():
                if val:
                    hit(label, str(val))

            # Fetch repos
            repos_url = f"https://api.github.com/users/{username}/repos?sort=updated&per_page=5"
            rs, rb = fetch(repos_url)
            if rs == 200 and rb:
                repos = json.loads(rb)
                if repos:
                    print(f"\n  {bold('Recent Repositories:')}")
                    for repo in repos[:5]:
                        lang = repo.get('language') or 'unknown'
                        stars = repo.get('stargazers_count', 0)
                        print(f"    {yellow('❯')}  {repo['name']:<30} ⭐{stars}  [{lang}]")

            results_store['findings']['github'] = data
        except Exception as e:
            info(f"GitHub parse error: {e}")
    elif status == 404:
        miss("GitHub — username not found")
    else:
        miss("GitHub API — unavailable or rate limited")


def username_email_guess(username):
    section("Email Pattern Intelligence")
    info("Common email patterns for this username:\n")
    patterns = [
        f"{username}@gmail.com",
        f"{username}@yahoo.com",
        f"{username}@hotmail.com",
        f"{username}@outlook.com",
        f"{username}@protonmail.com",
        f"{username}@icloud.com",
    ]
    for p in patterns:
        print(f"  {yellow('❯')}  {p}")
    info("\nVerify these at: https://haveibeenpwned.com or hunter.io")
    results_store['findings']['email_patterns'] = patterns


# ══════════════════════════════════════════════════════════
#   SUMMARY & REPORT
# ══════════════════════════════════════════════════════════

def print_summary():
    section("Scan Complete — Summary")
    target = results_store.get('target', 'unknown')
    scan_type = results_store.get('type', 'unknown')
    findings = results_store.get('findings', {})

    print(f"  Target   : {green(target)}")
    print(f"  Type     : {scan_type}")
    print(f"  Sections : {len(findings)} modules completed")

    if scan_type == 'domain':
        dns = findings.get('dns', {})
        subs = findings.get('subdomains', [])
        headers = findings.get('headers', {})
        missing_headers = [k for k, v in headers.items() if v is None]

        if dns.get('A'):
            hit("Resolved IP", dns['A'])
        if subs:
            hit("Subdomains found", len(subs))
        if missing_headers:
            print(f"  {red('⚠')}  {bold('Missing security headers:')} {', '.join(missing_headers[:4])}")

    elif scan_type == 'username':
        platforms = findings.get('platforms', [])
        if platforms:
            hit("Platforms found", len(platforms))
            for p in platforms[:5]:
                print(f"       {dim(p['url'])}")

    # Save JSON report
    report_file = f"osint_report_{target.replace('.','_')}_{int(time.time())}.json"
    try:
        with open(report_file, 'w') as f:
            json.dump({
                'target': target,
                'type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'findings': findings
            }, f, indent=2, default=str)
        print(f"\n  {green('✔')}  Report saved → {bold(report_file)}")
    except Exception as e:
        info(f"Could not save report: {e}")

    print(f"\n{cyan(SECTION)}\n")


# ══════════════════════════════════════════════════════════
#   ENTRY POINT
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="OSINT Investigator — Domain & Username Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 osint.py -d example.com
  python3 osint.py -u johndoe
  python3 osint.py -d github.com
        """
    )
    parser.add_argument('-d', '--domain',   help='Target domain  (e.g. example.com)')
    parser.add_argument('-u', '--username', help='Target username (e.g. johndoe)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    print(f"\n  {red('⚠  LEGAL NOTICE:')} This tool is for authorized security research only.")
    print(f"     Only investigate targets you have permission to research.\n")

    if args.domain:
        investigate_domain(args.domain.strip().lower().replace('https://','').replace('http://','').split('/')[0])
    elif args.username:
        investigate_username(args.username.strip())
    else:
        parser.print_help()


if __name__ == '__main__':
    main()

# 🔍 OSINT Investigator

> A Python CLI tool for **domain and username intelligence gathering** — built for ethical security researchers, bug bounty hunters, and cybersecurity students.

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat-square)
![Use](https://img.shields.io/badge/use-authorized%20research%20only-red?style=flat-square)

```
  ___  ____  ___ _   _ _____   _____ ___   ___  _     
 / _ \/ ___|_ _| \ | |_   _| |_   _/ _ \ / _ \| |    
| | | \___ \| ||  \| | | |     | || | | | | | | |    
| |_| |___) | || |\  | | |     | || |_| | |_| | |___ 
 \___/|____/___|_| \_| |_|     |_| \___/ \___/|_____|
  Domain & Username Intelligence Investigator v1.0
```

---

## 📌 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Example Output](#-example-output)
- [Safe Practice Targets](#-safe-practice-targets)
- [Real-World Use Cases](#-real-world-use-cases)
- [Roadmap](#-roadmap)
- [Legal Notice](#-legal-notice)
- [Contributing](#-contributing)
- [License](#-license)

---

##  Features

### 🌐 Domain Mode (`-d`)
| Module | What it finds |
|---|---|
| **DNS Records** | A, MX, NS, TXT, CNAME, AAAA, Reverse DNS |
| **WHOIS / RDAP** | Registrar, creation date, expiry, name servers |
| **HTTP Probe** | Status code, page title, technology fingerprinting |
| **Security Headers** | HSTS, CSP, X-Frame-Options, MIME, Referrer Policy |
| **Subdomain Enum** | 60+ common subdomains probed via DNS resolution |
| **Robots & Sitemap** | Exposed paths and disallowed routes |
| **Breach Check** | Certificate transparency logs via crt.sh |
| **Google Dorks** | Ready-to-run search queries for deeper recon |

###  Username Mode (`-u`)
| Module | What it finds |
|---|---|
| **Platform Check** | 20 platforms: GitHub, Reddit, Twitter/X, TryHackMe, HackTheBox, PyPI, NPM... |
| **GitHub Deep Dive** | Name, bio, location, email, repos, followers via GitHub API |
| **Email Patterns** | Common email combos to verify on HIBP or hunter.io |

### 📄 Auto Report
Every scan automatically saves a full **JSON report** with all findings.

---

## 🚀 Installation

### Requirements
- Python 3.8+
- pip

### Quick Start
```bash
# 1. Clone the repo
git clone https://github.com/YOURUSERNAME/osint-investigator.git
cd osint-investigator

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run it
python3 osint.py -d example.com
```

### Windows
```powershell
git clone https://github.com/YOURUSERNAME/osint-investigator.git
cd osint-investigator
pip install -r requirements.txt
python osint.py -d example.com
```

---

##  Usage

```bash
# Domain investigation
python3 osint.py -d example.com

# Username investigation  
python3 osint.py -u johndoe

# Help
python3 osint.py --help
```

---

##  Example Output

### Domain Scan
```
───────────────────────────────────────────────────────
  Security Headers Audit
───────────────────────────────────────────────────────
  ✔  HSTS                    PRESENT
  ✔  CSP                     PRESENT
  ✔  Clickjacking Protection  PRESENT
  ✘  Permissions Policy       MISSING  ← potential finding
  ✔  Server Header            nginx    ← info leak

───────────────────────────────────────────────────────
  Subdomain Enumeration (passive)
───────────────────────────────────────────────────────
  ✔  dev.example.com          93.184.216.10   ← exposed dev environment!
  ✔  mail.example.com         93.184.216.11
  ✔  api.example.com          93.184.216.12

───────────────────────────────────────────────────────
  Scan Complete — Summary
───────────────────────────────────────────────────────
  ✔  Report saved → osint_report_example_com_1712345678.json
```

### Username Scan
```
───────────────────────────────────────────────────────
  Platform Presence Check
───────────────────────────────────────────────────────
  ✔  GitHub       FOUND  →  https://github.com/johndoe
  ✔  TryHackMe    FOUND  →  https://tryhackme.com/p/johndoe
  ✔  Reddit       FOUND  →  https://reddit.com/user/johndoe
  ✘  Instagram
  ✘  LinkedIn
```

---

## 🎯 Safe Practice Targets

Only scan targets you are **authorized** to test. These are safe for practice:

| Target | Command | Notes |
|---|---|---|
| `scanme.nmap.org` | `-d scanme.nmap.org` | Made by Nmap **specifically** for practice |
| `testphp.vulnweb.com` | `-d testphp.vulnweb.com` | Made by Acunetix for practice |
| `github.com` | `-d github.com` | Public info only |
| Your own domain | `-d yourdomain.com` | You own it |
| Your own username | `-u yourusername` | It's you |

---

##  Real-World Use Cases

### Bug Bounty Hunting
Run a domain scan on an in-scope target. Missing security headers, exposed subdomains, and sensitive paths in robots.txt are all reportable findings on platforms like HackerOne and Bugcrowd.

### Penetration Testing (Reconnaissance Phase)
The first phase of any pentest is passive reconnaissance. This tool automates what would take hours of manual work into minutes, with a JSON report you can reference throughout the engagement.

### CTF Challenges
Many CTF challenges hide flags in DNS records, robots.txt, certificate transparency logs, or GitHub profiles. This tool checks all of them automatically.

### Security Awareness
Run it on your own domain or company domain to see what an attacker would find before they do.

---

##  Roadmap

- [ ] Shodan API integration (exposed ports & services)
- [ ] VirusTotal domain reputation check
- [ ] Email breach check via HaveIBeenPwned API
- [ ] 100+ platform username search
- [ ] HTML report export
- [ ] Async scanning (faster results)
- [ ] Tor/proxy support for anonymity
- [ ] Wayback Machine historical data

---

## ⚠️ Legal Notice

This tool is for **authorized security research only**.

- ✅ Your own domains and usernames
- ✅ Domains in active bug bounty scope
- ✅ CTF challenges and practice environments
- ✅ Authorized penetration tests
- ❌ Domains you do not have permission to test
- ❌ Any form of unauthorized access

The author assumes no liability for misuse. Always get written authorization before testing.

---

##  Contributing

Contributions are welcome! Here's how:

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/shodan-integration`
3. Commit your changes: `git commit -m "Add Shodan integration"`
4. Push and open a Pull Request

Check the [Roadmap](#-roadmap) for ideas.

---

##  License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE).

---

*Built by a cybersecurity graduate, for the security community. If this helped you find a bug, drop a ⭐ on the repo!*

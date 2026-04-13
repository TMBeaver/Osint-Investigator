# Contributing to OSINT Investigator

Thanks for your interest in contributing! Here's how to get started.

## 🛠️ Development Setup

```bash
git clone https://github.com/YOURUSERNAME/osint-investigator.git
cd osint-investigator
pip install -r requirements.txt
```

## 💡 Ideas for Contributions

Check the roadmap in README.md. Here are some good first issues:

- **Add more platforms** to the username checker (just add to the `platforms` dict in `username_platforms()`)
- **Add Shodan integration** — query `https://api.shodan.io/shodan/host/{ip}` for open ports
- **Add VirusTotal** — domain reputation via `https://www.virustotal.com/api/v3/domains/{domain}`
- **HTML report export** — convert the JSON output into a nice HTML report
- **Async scanning** — use `asyncio` + `aiohttp` to make username checks faster

## 📐 Code Style

- Keep it simple and readable — comments are encouraged
- Every new module should follow the `section()` / `hit()` / `miss()` pattern
- Store findings in `results_store['findings']['your_module']`
- Handle all exceptions gracefully — never crash on a failed lookup

## 🔀 Pull Request Process

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Test it: `python3 osint.py -d scanme.nmap.org`
5. Open a Pull Request with a clear description

## ⚠️ Rules

- No offensive/attack tools — this is a reconnaissance tool only
- All new modules must use public APIs or passive methods only
- Never store or log sensitive data

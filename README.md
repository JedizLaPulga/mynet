# MyNet - High Performance Network Scanner

<p align="center">
  <strong>Modern, async-first network reconnaissance toolkit built with Python</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/tests-246%20passed-brightgreen.svg" alt="Tests">
  <img src="https://img.shields.io/badge/modules-28-blueviolet.svg" alt="Modules">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
</p>

---

MyNet is a comprehensive network scanner designed for security professionals and penetration testers. It combines 27+ scanning modules into a single, fast, async-powered tool with beautiful terminal output.

## ✨ Features

- **⚡ Async Scanning** - High concurrency powered by `asyncio` and `aiohttp`
- **🧩 Modular Architecture** - 27+ plug-and-play scanning modules
- **🎯 Multi-Input Support** - URLs, IPs, Domains, and CIDR ranges
- **🎨 Rich Terminal UI** - Beautiful output with `rich` library
- **📊 Multiple Export Formats** - JSON, Markdown, HTML, and CSV
- **🔒 Security Focused** - WAF detection, vulnerability scanning, secret discovery
- **📸 Visual Recon** - Automated webpage screenshots with Playwright

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/mynet.git
cd mynet

# Install dependencies
pip install -r requirements.txt

# Install browser for screenshots (optional)
playwright install chromium
```

## 🚀 Usage

```bash
# Basic scan
python main.py example.com

# Scan specific ports
python main.py 192.168.1.1 --ports 22,80,443,8080

# Scan CIDR range
python main.py 10.0.0.0/24

# Save results to file
python main.py example.com --file results.json
python main.py example.com --file report.html
python main.py example.com --file report.md

# JSON output to console
python main.py example.com --output json

# Custom concurrency and timeout
python main.py example.com --concurrency 100 --timeout 10

# Save baseline for future comparisons
python main.py example.com --save-baseline baseline.json

# Compare against previous scan (Diff Mode)
python main.py example.com --diff baseline.json
```

### Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ports` | Comma-separated ports to scan | Common ports |
| `--concurrency` | Number of concurrent connections | 50 |
| `--timeout` | Request timeout in seconds | 5 |
| `--output` | Output format: `table` or `json` | table |
| `--file`, `-f` | Save results to file (.json, .html, .md, .csv, .pdf) | None |
| `--diff`, `-d` | Compare against baseline JSON file | None |
| `--save-baseline`, `-b` | Save results as baseline for future diffs | None |

## 🔧 Modules

MyNet includes **31 scanning modules** organized by category:


### 🌐 Network & DNS
| Module | Description |
|--------|-------------|
| **DNS Scanner** | Resolves A, AAAA, MX, NS, CNAME, TXT, PTR records |
| **Port Scanner** | TCP port scanning with banner grabbing |
| **Traceroute Scanner** | Network path analysis |
| **Zone Transfer Scanner** | AXFR vulnerability detection |
| **Whois Scanner** | WHOIS and ASN information |

### 🔐 Security Analysis
| Module | Description |
|--------|-------------|
| **WAF Detection** | Detects 40+ WAFs (Cloudflare, AWS, Akamai, etc.) with bypass hints |
| **Security Headers** | Analyzes security headers with scoring |
| **Vuln Scanner** | CVE lookup for detected software versions |
| **CORS Scanner** | Cross-Origin Resource Sharing misconfiguration detection |
| **Subdomain Takeover** | Detects vulnerable dangling CNAMEs |
| **Open Redirect Scanner** | Detects open redirect vulnerabilities with bypass payloads |
| **HTTP Method Scanner** | Tests for dangerous methods (PUT, DELETE, TRACE, WebDAV) |
| **Host Header Injection** | Tests for cache poisoning, password reset poisoning |

### 🕵️ Reconnaissance
| Module | Description |
|--------|-------------|
| **Subdomain Scanner** | Discovers subdomains via multiple sources |
| **CRT.sh Scanner** | Certificate transparency log enumeration |
| **Tech Fingerprinter** | Identifies technologies (frameworks, CMS, servers) |
| **Wayback Scanner** | Historical URL discovery via Archive.org |
| **Email Harvester** | Extracts email addresses from pages |
| **Cloud Enumerator** | Discovers cloud assets (S3 buckets, etc.) |

### 🌍 Web Analysis
| Module | Description |
|--------|-------------|
| **HTTP Scanner** | Status codes, titles, redirects, server info |
| **SSL Scanner** | Certificate analysis, expiry, SANs |
| **Web Crawler** | Discovers internal links and site structure |
| **Dir Enumerator** | Common directory/path discovery |
| **Robots & Sitemap** | Parses robots.txt and sitemap.xml |
| **API Scanner** | REST/GraphQL endpoint discovery with auth detection |

### 🔍 Secret Discovery
| Module | Description |
|--------|-------------|
| **JS Secret Scanner** | Finds API keys, tokens, secrets in JavaScript files |
| **Sensitive File Fuzzer** | Discovers exposed config files (.git, .env, backups) |

### 📸 Visual Recon
| Module | Description |
|--------|-------------|
| **Screenshot Capture** | Automated webpage screenshots (desktop & mobile) |

## 📁 Project Structure

```
mynet/
├── main.py                 # Entry point
├── requirements.txt        # Dependencies
├── mynet/
│   ├── core/
│   │   ├── config.py       # Configuration
│   │   ├── input_parser.py # Target parsing (URL, IP, CIDR)
│   │   └── runner.py       # Async scan orchestration
│   ├── modules/            # 27 scanning modules
│   │   ├── base.py         # BaseModule abstract class
│   │   ├── dns_scanner.py
│   │   ├── waf_scanner.py
│   │   ├── screenshot_scanner.py
│   │   └── ...
│   ├── output/
│   │   └── handler.py      # Output rendering (console, files)
│   └── ui/
│       └── cli.py          # Typer CLI interface
└── tests/                  # 115+ unit tests
```

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_waf_scanner.py -v

# Run with coverage
python -m pytest tests/ --cov=mynet
```

## 🛠️ Development

### Adding a New Module

1. Create a new file in `mynet/modules/`:

```python
from .base import BaseModule
from ..core.input_parser import Target

class MyNewScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "My New Scanner"
        self.description = "Does something cool"

    async def run(self, target: Target) -> dict:
        # Your scanning logic here
        return {"result": "data"}
```

2. The module is automatically discovered and loaded by the `Runner`.

3. Add a renderer in `mynet/output/handler.py` for custom console output.

4. Write tests in `tests/test_my_new_scanner.py`.

## 📋 Requirements

- Python 3.10+
- aiohttp
- dnspython
- rich
- typer
- ipwhois
- tldextract
- beautifulsoup4
- cryptography
- playwright (optional, for screenshots)

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

Built with:
- [aiohttp](https://github.com/aio-libs/aiohttp) - Async HTTP
- [rich](https://github.com/Textualize/rich) - Beautiful terminal output
- [typer](https://github.com/tiangolo/typer) - CLI framework
- [playwright](https://playwright.dev/) - Browser automation

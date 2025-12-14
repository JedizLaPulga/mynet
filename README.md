# MyNet - High Performance Network Scanner

MyNet is a modern, async-first network scanner built with Python. It allows for fast, modular scanning of targets (IPs, Domains, CIDRs).

## Features
- **Async Scanning**: High concurrency for fast results.
- **Modular**: Easily extensible plugin system.
- **Multi-Input**: Supports URL, IP, Domain, and CIDR ranges.
- **Rich UI**: Beautiful terminal output.
- **Export**: JSON, Markdown, and CSV support.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic Scan
python main.py example.com

# Scan specific ports
python main.py 192.168.1.1 --ports 22,80,443

# Save to Markdown
python main.py google.com --file results.md

# Scan CIDR
python main.py 10.0.0.0/24
```

## Modules
- **DNS Scanner**: Resolves A, AAAA, MX, NS, CNAME, TXT, PTR.
- **Port Scanner**: Checks common ports (customizable).
- **HTTP Scanner**: Checks Headers, Status, Title, Server.

## Development
To add a new module, create a class incurring `BaseModule` in `mynet/modules/`.

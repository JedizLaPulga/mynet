# MyNet Changelog

Track all changes made to the project here.

---

## [Session: 2026-01-18]

### 📋 Project Audit Complete
- Studied entire codebase (29 scanner modules)
- Ran full test suite: **215 tests passing** ✅
- Documented architecture and design patterns

---

### 🚀 Feature: Module Selection via CLI

**What:** Users can now choose which scanner modules to run instead of running all 29.

**New Options:**
- `--modules, -m` — Run only specific modules (comma-separated)
- `--exclude-modules, -x` — Skip certain modules
- `mynet modules` — New command to list all available scanners

**Usage Examples:**
```bash
# List all available modules
python -m mynet.ui.cli modules

# Run only WAF and Port scanners
mynet scan example.com --modules "WAF Detection,Port Scanner"

# Run everything except slow modules
mynet scan example.com --exclude-modules "Screenshot Capture,Web Crawler"
```

**Files Modified:**
- `mynet/core/runner.py` — Added module filtering logic
- `mynet/ui/cli.py` — Added CLI options and `modules` command
- `tests/test_module_filtering.py` — New test file with 8 tests

**Tests:** 8 new tests, all passing ✅

---

### 🛡️ Feature: Severity Scoring & Risk Dashboard

**What:** All scan findings are now classified by severity (Critical/High/Medium/Low/Info) with a visual risk dashboard displayed at the top of scan output.

**Key Features:**
- **Risk Summary Panel** — Shows overall risk level and score (0-100%)
- **Severity Breakdown** — Color-coded counts for each severity level
- **Priority Findings Table** — Highlights top Critical/High findings for immediate attention
- **Smart Severity Mapping** — Each scanner module's findings are automatically classified based on impact

**Severity Levels:**
| Level | Score | Color | Example Findings |
|-------|-------|-------|------------------|
| 🔴 Critical | 10 | Red | Subdomain takeover, CORS with credentials, RCE CVEs |
| 🟠 High | 8 | Orange | Zone transfer, API keys exposed, redirect poisoning |
| 🟡 Medium | 5 | Yellow | Missing security headers, GraphQL introspection |
| 🔵 Low | 3 | Cyan | Informational file exposure |
| ⚪ Info | 1 | Dim | WAF detected, open ports |

**Files Created:**
- `mynet/core/severity.py` — Severity scoring engine with module-specific rules
- `tests/test_severity.py` — 23 comprehensive tests

**Files Modified:**
- `mynet/output/handler.py` — Added risk summary panel and priority findings table

**Tests:** 23 new tests, all passing ✅

---



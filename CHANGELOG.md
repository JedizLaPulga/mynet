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



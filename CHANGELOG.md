# MyNet Changelog

Track all changes made to the project here.

---

## [v1.0.0] - 2026-01-20

### 🎉 Production Release

MyNet is now production-ready with proper packaging, CI/CD, and comprehensive testing.

---

### �️ Code Quality Improvements

**runner.py refactored:**
- Extracted `_discover_module_classes()` generator to eliminate duplicate code
- Replaced `print()` statements with proper `logging` module
- Fixed internal import placement
- Added comprehensive type hints

**screenshot_scanner.py cleaned:**
- Moved magic viewport numbers to class constants (`DESKTOP_VIEWPORT`, `MOBILE_VIEWPORT`)
- Added `logging.debug()` to silent exception handlers
- Switched from `md5` to `sha256` for URL hashing

---

### � Packaging & Distribution

**Added `pyproject.toml`:**
- Version: `1.0.0`
- Build system: Hatchling
- Pinned dependencies with version ranges
- Optional extras: `[screenshots]`, `[dev]`, `[all]`
- CLI entrypoint: `mynet` command
- Ruff linting configuration
- Pytest async mode configuration

**Added `mynet/__init__.py`:**
- `__version__ = "1.0.0"` for runtime version access

---

### � CI/CD Pipeline

**Added `.github/workflows/ci.yml`:**
- Matrix testing: Python 3.10, 3.11, 3.12, 3.13
- Multi-OS: Ubuntu, Windows, macOS
- Ruff linting and formatting checks
- Triggers on push/PR to main/master

---

### 📝 Documentation

**Updated `README.md`:**
- Fixed test badge: 115 → 246 tests
- Fixed module badge: 27 → 28 modules

---

### 📊 Test Summary

- **Total tests:** 246
- **All passing:** ✅
- **Test files:** 21

---

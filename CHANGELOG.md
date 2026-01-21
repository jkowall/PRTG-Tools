# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-01-21
### Added
- **Versioning**: Added `__version__` to all python scripts.
- **Tools**: Created `CHANGELOG.md` to track project history.

## [1.1.0] - 2026-01-21
### Added
- **Hybrid Audit**: Added `prtg_hybrid_audit.py` tool.
- **Discovery**: Implemented MAC Address scanning and Vendor Lookup.
- **WSL Support**: Implemented ARP-based discovery (`arp.exe` fallback) for Windows Subsystem for Linux users.
- **Reporting**: Generates CSV report with "Unmonitored" asset recommendations.
- **Documentation**: Added dedicated `README.md` for `hybrid_audit` and `netsnmp_scanner`.

## [1.0.0] - 2025-12-01
### Added
- **Scanner**: Initial release of `scan_netsnmp.py` for CVE-2025-68615.

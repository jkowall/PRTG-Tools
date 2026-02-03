# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.1] - 2026-02-03

### Fixed

- **Hybrid Audit**: Fixed sensor count always showing empty for managed devices. Updated PRTG API request to include `totalsens_raw` column and improved sensor count retrieval to check multiple possible response fields (`sensor`, `totalsens`, `totalsens_raw`).

## [1.3.0] - 2026-02-03

### Added

- **Hybrid Audit**: Expanded vendor detection from ~30 to ~80 vendors, covering:
  - Enterprise network equipment (Extreme, Alcatel-Lucent/Nokia, Brocade, Meraki)
  - Consumer/SMB networking (TP-Link, D-Link, NETGEAR, Zyxel, Linksys)
  - VoIP/Telecom systems (Avaya, Mitel, Polycom, Yealink, Grandstream, AudioCodes)
  - Additional camera vendors (Vivotek, Mobotix, Pelco, Uniview, Reolink, Amcrest)
  - More storage systems (HPE Nimble, 3PAR, Hitachi, Buffalo, Drobo, TerraMaster)
  - Environmental/Power equipment (Geist, Server Technology, CyberPower, Tripp Lite)
  - Industrial sensors (ABB, Omron, Emerson, Honeywell, Keyence, IFM, Turck)
  - Virtualization platforms (Proxmox, Nutanix, Hyper-V, XenServer, KVM)
- **Hybrid Audit**: Added DNS logging with detailed debug output for reverse DNS lookups
- **Hybrid Audit**: Added timeout handling for reverse DNS lookups to prevent hangs

### Changed

- **Hybrid Audit**: Refactored vendor detection into data-driven `_identify_vendor_from_snmp()` method to reduce code complexity (fix C901 linting error)
- **Hybrid Audit**: Improved pattern matching with support for context-aware vendor detection (e.g., distinguishing Bosch cameras from other Bosch products)

## [1.2.0] - 2026-02-02

### Added

- **Development**: Added `flake8` linting with `.flake8` configuration
- **Development**: Added `black` code formatting support
- **Development**: Added `pytest` unit testing framework with test suite in `tests/`
- **Development**: Added `Makefile` with `lint`, `format`, `test`, and `verify` targets
- **CI/CD**: Added GitHub Actions workflow (`.github/workflows/ci.yml`) for automated linting and testing on pull requests
- **Hybrid Audit**: Added reverse DNS lookup for discovered devices
- **Hybrid Audit**: Added parallel DNS resolution for PRTG hostnames

### Changed

- **Documentation**: Updated root `README.md` with development setup instructions
- **Documentation**: Updated `hybrid_audit/README.md` with testing and linting info

## [1.1.2] - 2026-02-02

### Fixed

- **Hybrid Audit**: Fixed FQDN/hostname matching - devices registered by hostname in PRTG are now resolved to IPs for proper comparison with scan results.
- **Hybrid Audit**: Renamed `api_hash`/`passhash` to `apitoken` throughout the codebase and config files to match PRTG API terminology.
- **Hybrid Audit**: Removed duplicate dictionary keys and duplicate import statements.
- **Documentation**: Updated installation instructions to recommend using Python virtual environments (venv) to avoid permission issues.
- **Documentation**: Listed all required dependencies including `getmac` and `mac-vendor-lookup` in the README.

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

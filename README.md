# PRTG-Tools

A collection of utilities and tools for PRTG Network Monitor users to enhance network monitoring, security scanning, and device management capabilities.

## About

This repository provides practical tools designed to help PRTG administrators and network security professionals extend their monitoring capabilities, identify security vulnerabilities, and maintain their network infrastructure.

## Tools

### 1. [Net-SNMP Vulnerability Scanner](netsnmp_scanner/README.md)

*Located in `netsnmp_scanner/`*

A Python-based security scanner that identifies devices running vulnerable versions of Net-SNMP affected by CVE-2025-68615 (CVSS 9.8).

**Use Case:**
Security teams need to quickly identify all devices in their network that are vulnerable to the critical Net-SNMP remote code execution vulnerability (CVE-2025-68615) to prioritize patching and mitigation.

**Why a PRTG User Would Care:**
PRTG relies heavily on SNMP to monitor network infrastructure. If your monitored devices are running vulnerable versions of Net-SNMP, your monitoring infrastructure itself could become an entry point for attackers. This tool helps you secure the very devices you are monitoring.

### 2. [PRTG Hybrid Audit Tool](hybrid_audit/README.md)

*Located in `hybrid_audit/`*

A "Hybrid Audit Tool" that combines data from an existing PRTG installation with a fresh network scan to identify unmanaged assets and upsell opportunities.

**Use Case:**
PRTG Administrators and MSPs need to reconcile what is currently in PRTG against what is actually live on the network to find gaps in monitoring coverage.

**Why a PRTG User Would Care:**

* **For Admins:** Ensure you aren't missing critical infrastructure in your monitoring. "You can't manage what you don't monitor."
* **For MSPs:** Identify unmanaged devices at client sites to demonstrate value and justify additional text/sensor licensing or service contract expansions.

## Development

This repository uses automated linting and testing to ensure code quality.

* **Requirements**: Install development dependencies with `pip install -r requirements.txt`.
* **Tasks**: Use the provided `Makefile` for local development:
  * `make test`: Run unit tests with `pytest`.
  * `make lint`: Check for PEP 8 compliance with `flake8`.
  * `make format`: Auto-format code with `black`.
* **CI**: GitHub Actions runs these checks on every pull request to the `main` branch.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! If you have additional tools or improvements that would benefit PRTG users, please feel free to submit a pull request.

## Support

For issues, questions, or feature requests, please open an issue on the GitHub repository.

## Disclaimer

These tools are provided "as is" for network administrators and security professionals to assess and maintain their own networks. Always ensure you have proper authorization before scanning any network infrastructure.

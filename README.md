# PRTG-Tools

A collection of utilities and tools for PRTG Network Monitor users to enhance network monitoring, security scanning, and device management capabilities.

## About

This repository provides practical tools designed to help PRTG administrators and network security professionals extend their monitoring capabilities, identify security vulnerabilities, and maintain their network infrastructure.

## Tools

### 1. [Net-SNMP Vulnerability Scanner](netsnmp_scanner/README.md)

*Located in `netsnmp_scanner/`*

A Python-based security scanner that identifies devices running vulnerable versions of Net-SNMP affected by CVE-2025-68615 (CVSS 9.8).

### 2. [PRTG Hybrid Audit Tool](hybrid_audit/README.md)

*Located in `hybrid_audit/`*

A "Hybrid Audit Tool" that combines data from an existing PRTG installation with a fresh network scan to identify unmanaged assets and upsell opportunities.

## Development

This repository uses automated linting and testing to ensure code quality.

- **Requirements**: Install development dependencies with `pip install -r requirements.txt`.
- **Tasks**: Use the provided `Makefile` for local development:
  - `make test`: Run unit tests with `pytest`.
  - `make lint`: Check for PEP 8 compliance with `flake8`.
  - `make format`: Auto-format code with `black`.
- **CI**: GitHub Actions runs these checks on every pull request to the `main` branch.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! If you have additional tools or improvements that would benefit PRTG users, please feel free to submit a pull request.

## Support

For issues, questions, or feature requests, please open an issue on the GitHub repository.

## Disclaimer

These tools are provided "as is" for network administrators and security professionals to assess and maintain their own networks. Always ensure you have proper authorization before scanning any network infrastructure.

# PRTG-Tools

A collection of utilities and tools for PRTG Network Monitor users to enhance network monitoring, security scanning, and device management capabilities.

## About

This repository provides practical tools designed to help PRTG administrators and network security professionals extend their monitoring capabilities, identify security vulnerabilities, and maintain their network infrastructure.

## Tools

### 1. Net-SNMP Vulnerability Scanner (`scan_netsnmp.py`)

A Python-based security scanner that identifies devices running vulnerable versions of Net-SNMP affected by CVE-2025-68615 (CVSS 9.8). This critical vulnerability affects the snmptrapd daemon in Net-SNMP versions prior to 5.9.5.

#### Features

- **Fast Parallel Scanning**: Scan entire subnets efficiently with configurable worker threads
- **CVE-2025-68615 Detection**: Identifies devices vulnerable to the snmptrapd remote code execution vulnerability
- **Flexible Configuration**: Customize SNMP community strings, timeouts, and retry settings
- **Comprehensive Reporting**: Color-coded output showing vulnerable, safe, and non-Net-SNMP devices
- **Multiple Subnet Support**: Scan multiple network ranges in a single execution

#### Installation

1. **Ensure Python 3.7 or later is installed:**
   ```bash
   python --version
   ```

2. **Install required dependencies:**
   ```bash
   pip install pysnmp
   ```

3. **(Optional) Use a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # or
   venv\Scripts\activate     # Windows
   pip install pysnmp
   ```

#### Usage

**Basic subnet scan:**
```bash
python scan_netsnmp.py 192.168.1.0/24
```

**Scan multiple subnets with custom community string:**
```bash
python scan_netsnmp.py 192.168.1.0/24 10.0.0.0/24 --community mySecretString
```

**Advanced scan with custom parameters:**
```bash
python scan_netsnmp.py 192.168.1.0/24 --timeout 2 --workers 100 --verbose
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --community` | SNMP community string | `public` |
| `-t, --timeout` | Timeout in seconds per device | `1.0` |
| `-r, --retries` | Number of retries per device | `1` |
| `-w, --workers` | Number of parallel workers | `50` |
| `-v, --verbose` | Show all responding devices, not just vulnerable ones | `false` |
| `--no-color` | Disable colored output | `false` |

#### How It Works

The scanner queries SNMP-enabled devices using OID `1.3.6.1.2.1.1.1.0` (sysDescr) to extract the Net-SNMP version information. Any device running Net-SNMP version earlier than 5.9.5 is flagged as vulnerable to CVE-2025-68615.

#### Security Advisory

**CVE-2025-68615** is a critical remote code execution vulnerability in the Net-SNMP snmptrapd daemon with a CVSS score of 9.8. Affected devices should be:

1. Patched to Net-SNMP version 5.9.5 or later
2. Have snmptrapd service disabled if patching is not possible
3. Have UDP port 162 blocked from untrusted networks
4. Monitored for suspicious activity

**Reference:** [NVD - CVE-2025-68615](https://nvd.nist.gov/vuln/detail/CVE-2025-68615)

#### Integration with PRTG

This tool complements PRTG Network Monitor by:
- Identifying security vulnerabilities in SNMP-enabled devices already monitored by PRTG
- Providing security assessment capabilities beyond standard PRTG monitoring
- Helping prioritize device patching and maintenance activities
- Enabling proactive security posture management

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! If you have additional tools or improvements that would benefit PRTG users, please feel free to submit a pull request.

## Support

For issues, questions, or feature requests, please open an issue on the GitHub repository.

## Disclaimer

These tools are provided "as is" for network administrators and security professionals to assess and maintain their own networks. Always ensure you have proper authorization before scanning any network infrastructure.

# PRTG Hybrid Audit Tool (`hybrid_audit/prtg_hybrid_audit.py`)

A "Hybrid Audit Tool" that combines data from an existing PRTG installation with a fresh network scan to identify unmanaged assets and upsell opportunities.

## Features

- **PRTG Integration**: Imports current device list from PRTG Core API.
- **Active Discovery**: Scans CIDR ranges for live hosts using threaded socket checks.
- **Deep Identification**: Fingerprints devices via SNMP, SSH, and WMI to identify Vendor, Model, and OS.
- **Parallel DNS Resolution**: Resolves PRTG hostnames in batches using a thread pool for high performance.
- **Gap Analysis**: Reconciles PRTG data with scan results to find "Unmonitored" devices.
- **Reporting**: Generates a CSV report with sales recommendations.
- **Unit Tested**: Includes a comprehensive test suite for API and reconciliation logic.

## Installation

1. **Create a virtual environment (recommended):**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install required dependencies:**

   ```bash
   python3 -m pip install -r ../requirements.txt
   ```

   *Dependencies include: `requests`, `paramiko`, `impacket`, `pysnmp`, `pyyaml`, `getmac`, `mac-vendor-lookup`*

## Usage

1. **Configure**: Copy `config_example.yaml` to `config.yaml` and edit with your PRTG details and scan settings.

   Example `config.yaml`:

   ```yaml
   prtg:
     url: "https://your-prtg-server.com"
     apitoken: "YOUR_API_TOKEN"  # PRTG API token (Setup > Account Settings > My Account)
   scan:
     cidr_ranges: ["192.168.1.0/24"]
   credentials:
     # ... see config_example.yaml
   ```

2. **Run** (make sure your venv is activated):

   ```bash
   python prtg_hybrid_audit.py
   ```

3. **Report**: Check `Hybrid_Assessment_Report.csv` for results.

## Troubleshooting

- **Missing MAC Addresses**: MAC address detection requires **Layer 2 connectivity**. The script must be run on the same physical subnet as the target devices. If you run this from WSL, Docker, or across a router, MAC addresses (and Vendor lookups) will effectively be empty.

## Development

A `Makefile` is provided in the root directory for common development tasks.

- **Run Tests**: `make test`
- **Lint Code**: `make lint`
- **Format Code**: `make format`

Continuous Integration is set up via GitHub Actions to run these checks on every pull request.
